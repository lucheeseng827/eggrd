//! Client certificates on the TLS listener: mutual TLS (`[tls.client_auth]`).
//!
//! Three parts:
//!
//! * [`ClientAuth`] is the listener's client-certificate verifier: rustls's own WebPKI verifier
//!   over the CAs in `ca_path` and the CRLs in `crl_paths`, held behind an [`ArcSwap`] so a
//!   changed CA bundle or CRL is picked up by new handshakes with no restart ([`watch`]).
//! * [`ClientCert`] is what a verified certificate says about the client — its names and its
//!   fingerprint — read once per connection and attached to every request on it.
//! * [`ForwardPolicy`] decides what reaches the app: the client's own `X-Forwarded-Client-Cert` is
//!   always dropped while client authentication is on, and with `forward_client_cert = "xfcc"`
//!   EdgeGuard writes one describing the certificate it verified.
//!
//! The listener that uses a [`ClientAuth`] turns TLS session resumption off (see
//! [`crate::tls::server_config_with_client_auth`]): a resumed session is not verified again, so a
//! certificate revoked by a CRL update would otherwise keep connecting.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use tokio::sync::watch as tokio_watch;
use tracing::{info, warn};

use crate::certstore::CertNames;
use crate::config::{ClientAuthCfg, TlsCfg};

/// The request header the app reads a verified client certificate from.
pub const XFCC_HEADER: &str = "x-forwarded-client-cert";

/// `[tls.client_auth] mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    /// A certificate is verified if the client presents one; a client without one still connects.
    Optional,
    /// No certificate, no connection.
    Required,
}

impl Mode {
    pub fn parse(value: &str) -> Result<Mode> {
        match value {
            "off" => Ok(Mode::Off),
            "optional" => Ok(Mode::Optional),
            "required" => Ok(Mode::Required),
            other => anyhow::bail!(
                "unknown tls.client_auth.mode {other:?} (expected off|optional|required)"
            ),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Optional => "optional",
            Mode::Required => "required",
        }
    }
}

/// What the CA bundle and CRLs the verifier was built from say about themselves: for the
/// certificate series, `doctor` and `GET /__edgeguard/tls`.
#[derive(Debug, Clone, Default)]
pub struct TrustInfo {
    pub cas: Vec<TrustedCa>,
    pub crls: Vec<LoadedCrl>,
}

/// One CA in `tls.client_auth.ca_path`.
#[derive(Debug, Clone)]
pub struct TrustedCa {
    /// Its subject common name, or its serial when it has none: the `client-ca:<name>` label.
    pub name: String,
    pub info: crate::certstore::CertInfo,
}

/// One CRL from `tls.client_auth.crl_paths`.
#[derive(Debug, Clone)]
pub struct LoadedCrl {
    /// Its file, with `#<n>` from the second CRL on when a file holds several: the `crl` label.
    pub name: String,
    pub info: crate::certstore::CrlInfo,
}

/// The listener's client-certificate verifier, reloadable.
pub struct ClientAuth {
    mode: Mode,
    ca_path: String,
    crl_paths: Vec<String>,
    current: ArcSwap<Arc<dyn ClientCertVerifier>>,
    /// The bytes the current verifier was built from, to tell a real change from a touch.
    loaded: Mutex<Vec<u8>>,
    trust: ArcSwap<TrustInfo>,
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuth")
            .field("mode", &self.mode)
            .field("ca_path", &self.ca_path)
            .field("crl_paths", &self.crl_paths)
            .finish()
    }
}

impl ClientAuth {
    /// The verifier `[tls.client_auth]` describes, or `None` when it is off. Fails on anything the
    /// listener could not start with: client authentication without `[tls] enabled`, no
    /// `ca_path`, a CA bundle or CRL that does not load.
    pub fn from_cfg(tls: &TlsCfg) -> Result<Option<Arc<ClientAuth>>> {
        let cfg = &tls.client_auth;
        let mode = Mode::parse(&cfg.mode)?;
        if mode == Mode::Off {
            return Ok(None);
        }
        anyhow::ensure!(
            tls.enabled,
            "tls.client_auth.mode = {:?} needs [tls] enabled = true: a client certificate only \
             reaches the process that terminates TLS",
            cfg.mode
        );
        anyhow::ensure!(
            !cfg.ca_path.is_empty(),
            "tls.client_auth.ca_path is required when client authentication is on"
        );
        let (verifier, loaded, trust) = build(mode, &cfg.ca_path, &cfg.crl_paths)?;
        Ok(Some(Arc::new(ClientAuth {
            mode,
            ca_path: cfg.ca_path.clone(),
            crl_paths: cfg.crl_paths.clone(),
            current: ArcSwap::from_pointee(verifier),
            loaded: Mutex::new(loaded),
            trust: ArcSwap::from_pointee(trust),
        })))
    }

    /// A verifier for certificates that did not arrive in a handshake: those a load balancer
    /// forwards in `[trusted_client_cert_header]`, when `ca_path` asks for them to be checked
    /// again. Reloadable and watchable like the listener's.
    pub fn for_header(ca_path: &str, crl_paths: &[String]) -> Result<Arc<ClientAuth>> {
        let (verifier, loaded, trust) = build(Mode::Required, ca_path, crl_paths)?;
        Ok(Arc::new(ClientAuth {
            mode: Mode::Required,
            ca_path: ca_path.to_string(),
            crl_paths: crl_paths.to_vec(),
            current: ArcSwap::from_pointee(verifier),
            loaded: Mutex::new(loaded),
            trust: ArcSwap::from_pointee(trust),
        }))
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn ca_path(&self) -> &str {
        &self.ca_path
    }

    /// The CAs and CRLs the current verifier was built from.
    pub fn trust(&self) -> Arc<TrustInfo> {
        self.trust.load_full()
    }

    /// Every file the verifier is built from.
    pub fn paths(&self) -> Vec<String> {
        std::iter::once(self.ca_path.clone())
            .chain(self.crl_paths.iter().cloned())
            .collect()
    }

    /// Re-read the CA bundle and CRLs. `Ok(true)` when they changed and new handshakes now use
    /// them; `Ok(false)` when nothing changed. On error the current verifier stays in place.
    pub fn reload(&self) -> Result<bool> {
        let (verifier, loaded, trust) = build(self.mode, &self.ca_path, &self.crl_paths)?;
        let mut current = self.loaded.lock().expect("client auth mutex poisoned");
        if *current == loaded {
            return Ok(false);
        }
        self.current.store(Arc::new(verifier));
        self.trust.store(Arc::new(trust));
        *current = loaded;
        Ok(true)
    }
}

/// Build a WebPKI verifier from the files, and return the bytes it was built from and what they
/// say about themselves.
fn build(
    mode: Mode,
    ca_path: &str,
    crl_paths: &[String],
) -> Result<(Arc<dyn ClientCertVerifier>, Vec<u8>, TrustInfo)> {
    // Each file is read once and parsed from those bytes, so what a reload compares is exactly what
    // the verifier was built from. Read twice, a file replaced in between would be remembered as
    // loaded while the verifier kept the old one, and the change would never be applied.
    let mut loaded = std::fs::read(ca_path)
        .with_context(|| format!("reading tls.client_auth.ca_path {ca_path}"))?;
    let cas = rustls_pemfile::certs(&mut loaded.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("tls.client_auth.ca_path: parsing certificates from {ca_path}"))?;
    anyhow::ensure!(
        !cas.is_empty(),
        "tls.client_auth.ca_path: no certificates found in {ca_path}"
    );
    let mut roots = RootCertStore::empty();
    let mut trust = TrustInfo::default();
    for cert in cas {
        // Best effort, like the served certificate's: a CA this reader cannot parse still verifies.
        if let Ok(info) = crate::certstore::CertInfo::from_der(&cert) {
            let name = crate::certstore::CertNames::from_der(&cert)
                .ok()
                .and_then(|n| n.common_name)
                .unwrap_or_else(|| info.serial.clone());
            trust.cas.push(TrustedCa { name, info });
        }
        roots
            .add(cert)
            .with_context(|| format!("tls.client_auth.ca_path {ca_path}: not a usable CA"))?;
    }

    let mut crls: Vec<CertificateRevocationListDer<'static>> = Vec::new();
    for path in crl_paths {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading tls.client_auth.crl_paths entry {path}"))?;
        let parsed = rustls_pemfile::crls(&mut bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("parsing CRLs from {path}"))?;
        anyhow::ensure!(!parsed.is_empty(), "no CRL found in {path}");
        for (i, crl) in parsed.iter().enumerate() {
            if let Ok(info) = crate::certstore::CrlInfo::from_der(crl) {
                let name = if i == 0 {
                    path.clone()
                } else {
                    format!("{path}#{}", i + 1)
                };
                trust.crls.push(LoadedCrl { name, info });
            }
        }
        crls.extend(parsed);
        loaded.extend(bytes);
    }

    let mut builder = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    );
    if !crls.is_empty() {
        // The client's own certificate is what a CRL here is for. Checking the whole chain would
        // refuse every client whose intermediate CA publishes no CRL in `crl_paths`.
        builder = builder.with_crls(crls).only_check_end_entity_revocation();
    }
    if mode == Mode::Optional {
        builder = builder.allow_unauthenticated();
    }
    let verifier = builder
        .build()
        .context("building the client certificate verifier")?;
    Ok((verifier, loaded, trust))
}

impl ClientCertVerifier for ClientAuth {
    fn offer_client_auth(&self) -> bool {
        self.current.load().offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.current.load().client_auth_mandatory()
    }

    /// No CA names are sent with the certificate request. The list would have to outlive a reload
    /// of the CA bundle, and it is only a hint: clients present the certificate they are
    /// configured with whether or not it names their CA.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.current
            .load()
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.current
            .load()
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.current
            .load()
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.current.load().supported_verify_schemes()
    }
}

/// Reload `auth` when its files change, and hourly regardless, until `shutdown` flips. The hourly
/// read is the backstop for filesystems that deliver no change events, as for certificates.
pub async fn watch(auth: Arc<ClientAuth>, shutdown: tokio_watch::Receiver<bool>) {
    let reload = {
        let auth = Arc::clone(&auth);
        move || {
            match auth.reload() {
            Ok(true) => {
                info!(ca = %auth.ca_path, "client CA bundle or CRLs reloaded; new handshakes use them")
            }
            Ok(false) => {}
            Err(e) => warn!(
                error = format!("{e:#}"),
                "client CA bundle or CRLs changed but do not load; still verifying against the previous ones"
            ),
        }
        }
    };
    let backstop = {
        let reload = reload.clone();
        let mut shutdown = shutdown.clone();
        async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(3600)) => reload(),
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() { return; }
                    }
                }
            }
        }
    };
    info!(ca = %auth.ca_path, crls = auth.crl_paths.len(), "client CA and CRL reload on change enabled");
    let on_change = crate::certstore::watch_paths(auth.paths(), reload, shutdown);
    let (watched, ()) = tokio::join!(on_change, backstop);
    if let Err(e) = watched {
        warn!(
            error = format!("{e:#}"),
            "client CA watcher stopped; changes on disk are picked up by the hourly check"
        );
    }
}

/// What a verified client certificate says about the client. Attached to every request on the
/// connection it arrived on.
#[derive(Debug, Clone)]
pub struct ClientCert {
    pub names: CertNames,
    /// SHA-256 of the DER certificate, lowercase hex.
    pub sha256: String,
}

impl ClientCert {
    /// Read the leaf certificate a client presented. A certificate whose names cannot be read
    /// still has a fingerprint, so it is never mistaken for no certificate.
    pub fn from_der(der: &[u8]) -> ClientCert {
        let digest = ring::digest::digest(&ring::digest::SHA256, der);
        ClientCert {
            names: CertNames::from_der(der).unwrap_or_default(),
            sha256: digest.as_ref().iter().map(|b| format!("{b:02x}")).collect(),
        }
    }

    /// Every name, in the order a principal is chosen: URI alternative names, DNS names, email
    /// names, then the subject's common name.
    pub fn identities(&self) -> impl Iterator<Item = &str> {
        self.names
            .uris
            .iter()
            .chain(&self.names.dns)
            .chain(&self.names.emails)
            .chain(&self.names.common_name)
            .map(String::as_str)
    }

    /// The `X-Forwarded-Client-Cert` value: `Hash=<sha256>`, then each URI and DNS name, quoted.
    pub fn xfcc(&self) -> String {
        let mut out = format!("Hash={}", self.sha256);
        for (key, values) in [("URI", &self.names.uris), ("DNS", &self.names.dns)] {
            for v in values {
                let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
                out.push_str(&format!(";{key}=\"{escaped}\""));
            }
        }
        out
    }
}

/// What happens to `X-Forwarded-Client-Cert` on the way to the app.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForwardPolicy {
    /// Drop the header if the client sent one.
    pub strip_inbound: bool,
    /// Write one for a verified certificate.
    pub forward: bool,
}

impl ForwardPolicy {
    /// `from_header`: client certificates also arrive in `[trusted_client_cert_header]`, so there
    /// is one to forward, and a client's own `X-Forwarded-Client-Cert` must go.
    pub fn from_cfg(cfg: &ClientAuthCfg, from_header: bool) -> Result<ForwardPolicy> {
        let on = Mode::parse(&cfg.mode)? != Mode::Off || from_header;
        let forward = match cfg.forward_client_cert.as_str() {
            "off" => false,
            "xfcc" => true,
            other => anyhow::bail!(
                "unknown tls.client_auth.forward_client_cert {other:?} (expected off|xfcc)"
            ),
        };
        anyhow::ensure!(
            on || !forward,
            "tls.client_auth.forward_client_cert = \"xfcc\" needs tls.client_auth.mode = \
             \"optional\" or \"required\", or [trusted_client_cert_header]: there is no verified \
             certificate to forward"
        );
        Ok(ForwardPolicy {
            strip_inbound: on,
            forward,
        })
    }
}

/// A certificate name to match: an exact name, or a prefix ending in `*`. `[auth.mtls] allowed`
/// and `trusted_client_cert_header.trusted_proxy_names` entries.
#[derive(Debug, Clone)]
pub struct NamePattern {
    text: String,
    prefix: bool,
}

impl NamePattern {
    /// `raw`, an entry of `setting`, which the errors name.
    pub fn parse(setting: &str, raw: &str) -> Result<NamePattern> {
        anyhow::ensure!(!raw.is_empty(), "{setting} entries must not be empty");
        let (text, prefix) = match raw.strip_suffix('*') {
            Some(head) => (head, true),
            None => (raw, false),
        };
        anyhow::ensure!(
            !text.contains('*'),
            "{setting} {raw:?}: `*` may only end an entry, as a prefix match"
        );
        Ok(NamePattern {
            text: text.to_string(),
            prefix,
        })
    }

    /// A bare `*`: every name.
    pub fn matches_everything(&self) -> bool {
        self.prefix && self.text.is_empty()
    }

    pub(crate) fn matches(&self, name: &str) -> bool {
        if self.prefix {
            name.starts_with(&self.text)
        } else {
            name == self.text
        }
    }
}

/// The principal `auth.mode = "mtls"` takes from `cert`: its first name that `allowed` lets
/// through, in [`ClientCert::identities`] order. With no `allowed` entries, its first name — or
/// `sha256:<fingerprint>` for a certificate with none. `None` when nothing is allowed.
pub fn principal(cert: &ClientCert, allowed: &[NamePattern]) -> Option<String> {
    if allowed.is_empty() {
        return Some(
            cert.identities()
                .next()
                .map(str::to_string)
                .unwrap_or_else(|| format!("sha256:{}", cert.sha256)),
        );
    }
    cert.identities()
        .find(|name| allowed.iter().any(|p| p.matches(name)))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientAuthCfg;

    fn cert(uris: &[&str], dns: &[&str], emails: &[&str], cn: Option<&str>) -> ClientCert {
        let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect();
        ClientCert {
            names: CertNames {
                common_name: cn.map(str::to_string),
                dns: owned(dns),
                uris: owned(uris),
                emails: owned(emails),
            },
            sha256: "ab".repeat(32),
        }
    }

    fn patterns(raw: &[&str]) -> Vec<NamePattern> {
        raw.iter()
            .map(|p| NamePattern::parse("auth.mtls.allowed", p).unwrap())
            .collect()
    }

    #[test]
    fn the_principal_prefers_uri_then_dns_then_email_then_cn() {
        let c = cert(
            &["spiffe://td/ns/web"],
            &["web.internal"],
            &["ops@example.com"],
            Some("web"),
        );
        assert_eq!(principal(&c, &[]).as_deref(), Some("spiffe://td/ns/web"));
        let c = cert(&[], &["web.internal"], &["ops@example.com"], Some("web"));
        assert_eq!(principal(&c, &[]).as_deref(), Some("web.internal"));
        let c = cert(&[], &[], &[], Some("web"));
        assert_eq!(principal(&c, &[]).as_deref(), Some("web"));
        // No names at all: the fingerprint, so such a certificate still has an identity.
        let c = cert(&[], &[], &[], None);
        assert_eq!(
            principal(&c, &[]),
            Some(format!("sha256:{}", "ab".repeat(32)))
        );
    }

    #[test]
    fn an_allow_list_picks_the_first_allowed_name_or_refuses() {
        let c = cert(&["spiffe://td/ns/web"], &["web.internal"], &[], Some("web"));
        // The URI is preferred, but only an allowed name can be the principal.
        assert_eq!(
            principal(&c, &patterns(&["web.internal"])).as_deref(),
            Some("web.internal")
        );
        assert_eq!(
            principal(&c, &patterns(&["spiffe://td/ns/*"])).as_deref(),
            Some("spiffe://td/ns/web")
        );
        assert_eq!(principal(&c, &patterns(&["spiffe://td/ns/db"])), None);
        // Exact means exact: no prefix match without the `*`.
        assert_eq!(principal(&c, &patterns(&["spiffe://td/ns/we"])), None);
    }

    #[test]
    fn a_star_may_only_end_a_pattern() {
        let parse = |raw| NamePattern::parse("auth.mtls.allowed", raw);
        assert!(parse("spiffe://td/*").is_ok());
        let e = format!("{:#}", parse("*.example.com").unwrap_err());
        assert!(
            e.contains("auth.mtls.allowed \"*.example.com\": `*` may only end"),
            "{e}"
        );
        assert!(format!("{:#}", parse("").unwrap_err()).contains("auth.mtls.allowed entries"));
        assert!(parse("*").unwrap().matches_everything());
        assert!(!parse("spiffe://*").unwrap().matches_everything());
        assert!(!parse("lb").unwrap().matches_everything());
    }

    #[test]
    fn xfcc_quotes_and_escapes_its_values() {
        let c = cert(&["spiffe://td/a\"b"], &["web.internal"], &[], None);
        assert_eq!(
            c.xfcc(),
            format!(
                "Hash={};URI=\"spiffe://td/a\\\"b\";DNS=\"web.internal\"",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn the_forward_policy_follows_the_mode() {
        let policy = |mode: &str, forward: &str| {
            ForwardPolicy::from_cfg(
                &ClientAuthCfg {
                    mode: mode.into(),
                    forward_client_cert: forward.into(),
                    ..Default::default()
                },
                false,
            )
        };
        assert_eq!(policy("off", "off").unwrap(), ForwardPolicy::default());
        assert_eq!(
            policy("optional", "off").unwrap(),
            ForwardPolicy {
                strip_inbound: true,
                forward: false
            }
        );
        assert_eq!(
            policy("required", "xfcc").unwrap(),
            ForwardPolicy {
                strip_inbound: true,
                forward: true
            }
        );
        assert!(policy("off", "xfcc").is_err(), "nothing to forward");
        assert!(policy("sometimes", "off").is_err());
        assert!(policy("required", "pem").is_err());
        // A certificate a load balancer forwards is one to forward, and to protect.
        let header = |forward: &str| {
            ForwardPolicy::from_cfg(
                &ClientAuthCfg {
                    forward_client_cert: forward.into(),
                    ..Default::default()
                },
                true,
            )
            .unwrap()
        };
        assert_eq!(
            header("xfcc"),
            ForwardPolicy {
                strip_inbound: true,
                forward: true
            }
        );
        assert!(
            header("off").strip_inbound,
            "a client's own XFCC still goes"
        );
    }

    #[test]
    fn names_are_read_from_a_real_certificate() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["Web.Internal".to_string()]).unwrap();
        params.subject_alt_names.push(rcgen::SanType::URI(
            "spiffe://td/ns/web".try_into().unwrap(),
        ));
        params.subject_alt_names.push(rcgen::SanType::Rfc822Name(
            "Ops@Example.com".try_into().unwrap(),
        ));
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Example");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "web frontend");
        let der = params.self_signed(&key).unwrap().der().to_vec();

        let c = ClientCert::from_der(&der);
        assert_eq!(c.names.dns, ["web.internal"]);
        assert_eq!(c.names.uris, ["spiffe://td/ns/web"]);
        assert_eq!(c.names.emails, ["ops@example.com"]);
        assert_eq!(c.names.common_name.as_deref(), Some("web frontend"));
        assert_eq!(c.sha256.len(), 64);
    }

    #[test]
    fn a_certificate_without_alternative_names_has_only_its_cn() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "legacy-client");
        let der = params.self_signed(&key).unwrap().der().to_vec();
        let c = ClientCert::from_der(&der);
        assert_eq!(c.identities().collect::<Vec<_>>(), ["legacy-client"]);
    }
}
