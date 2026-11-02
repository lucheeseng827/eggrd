//! How the edge reaches what it calls itself: the control plane, log and OTLP collectors, a JWKS
//! endpoint, an alert webhook, a DNS provider's API — and, through the TLS half of it, upstreams.
//!
//! Every such client is built by [`builder`] from the same four settings ([`OutboundCfg`]): the
//! CAs that may sign the endpoint's certificate, the client certificate to present, and the proxy
//! to go through. The rustls pieces ([`roots`], [`identity`], [`client_config`]) are shared with
//! the upstream connector, so a private CA or a client certificate means the same thing on every
//! connection this process opens.
//!
//! Client certificates are kept in one place for the whole process, one store per certificate and
//! key file pair, whichever client loaded it first. A client rebuilt on a config reload therefore
//! presents the store that is already watched (see [`watch_identities`]), and a rotation reaches
//! it with no reload.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use anyhow::{Context, Result};
use rustls::client::ResolvesClientCert;
use rustls::{ClientConfig, RootCertStore};

use crate::certstore::{CertSource, CertStore};
use crate::config::{OutboundCfg, OutboundDefaultsCfg};

/// A reqwest client builder for calling `url`, set up by `cfg` (with `[outbound]` where it leaves
/// a key empty), and the client certificate it presents, if any. `what` names the section in
/// errors (`log.ship`, `auth.jwt`). The caller adds its own timeout and builds it. With a client
/// certificate, every request is a new connection and a full handshake, so it always presents the
/// current certificate.
pub fn builder(
    cfg: &OutboundCfg,
    what: &str,
    url: &str,
) -> Result<(reqwest::ClientBuilder, Option<Arc<CertStore>>)> {
    builder_trusting(cfg, what, url, PublicRoots::Bundled)
}

/// What a client trusts when nothing narrows it: no `ca_path` of its own, and nothing but
/// `[outbound] extra_ca_path` added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicRoots {
    /// The public web PKI built into the binary, the same on every host. Every client but one.
    Bundled,
    /// The operating system's trust store (the platform verifier; on Linux the system bundle or
    /// `SSL_CERT_FILE`). The ACME directory client, which has always trusted it, so a private ACME
    /// CA whose root is installed on the host keeps working.
    System,
}

/// [`builder`], with `public` as what the client trusts when nothing narrows it.
pub fn builder_trusting(
    cfg: &OutboundCfg,
    what: &str,
    url: &str,
    public: PublicRoots,
) -> Result<(reqwest::ClientBuilder, Option<Arc<CertStore>>)> {
    let own_tls = !cfg.ca_path.is_empty() || !cfg.client_cert_path.is_empty();
    anyhow::ensure!(
        !own_tls || is_https(url),
        "{what}.ca_path / client_cert_path are set but {url:?} is not https://, so neither would \
         be used and the connection would not be encrypted"
    );
    anyhow::ensure!(
        cfg.client_cert_path.is_empty() == cfg.client_key_path.is_empty(),
        "{what}.client_cert_path and client_key_path must be set together"
    );
    let settings = Settings::of(cfg, url);
    let identity = match settings.identity {
        Some((cert, key, from)) => {
            identity(cert, key, what).with_context(|| from.key(what, "client_cert_path"))?
        }
        None => None,
    };
    let store = identity.as_ref().map(|i| Arc::clone(i.store()));
    let mut http = reqwest::Client::builder();
    // reqwest's own TLS config trusts the same bundled roots, and resumes sessions.
    if settings.trust != Trust::Public || identity.is_some() || public == PublicRoots::System {
        let verify = settings.trust.verify(what, public)?;
        http = http.use_preconfigured_tls(client_config_verifying(verify, identity)?);
    }
    if store.is_some() {
        // A pooled connection keeps the certificate it was opened with, and a client that pushes
        // every few seconds never lets one go idle, so a rotated certificate would never be
        // presented. These clients make a handful of requests a minute: a handshake each is cheap.
        http = http.pool_max_idle_per_host(0);
    }
    let (proxy, from) = settings.proxy;
    http = match parse_proxy(proxy).with_context(|| from.key(what, "proxy"))? {
        ProxyRoute::Environment => http,
        ProxyRoute::Direct => http.no_proxy(),
        ProxyRoute::Via(proxy) => http.proxy(*proxy),
    };
    Ok((http, store))
}

fn is_https(url: &str) -> bool {
    url.trim().starts_with("https://")
}

/// Where one key of a client's settings comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The client's own section.
    Section,
    /// `[outbound]`, for a key the section leaves empty.
    Outbound,
}

impl Origin {
    /// The setting as an error names it: `log.ship.proxy`, or `outbound.proxy (inherited by
    /// log.ship)`.
    fn key(self, what: &str, key: &str) -> String {
        match self {
            Origin::Section => format!("{what}.{key}"),
            Origin::Outbound => format!("outbound.{key} (inherited by {what})"),
        }
    }
}

/// The CAs a client trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust<'a> {
    /// The public web PKI built into the binary.
    Public,
    /// The public web PKI and the CAs in this file (`[outbound] extra_ca_path`).
    PublicAnd(&'a str),
    /// Only the CAs in this file (the section's own `ca_path`).
    Only(&'a str),
}

/// How a client checks the server's certificate: against a root store, or with a verifier of its
/// own.
pub(crate) enum Verify {
    Roots(RootCertStore),
    Verifier(Arc<dyn rustls::client::danger::ServerCertVerifier>),
}

impl Trust<'_> {
    /// How a client with this trust checks a server, `public` being what [`Trust::Public`] means
    /// for it. `what` names the section in errors.
    pub(crate) fn verify(&self, what: &str, public: PublicRoots) -> Result<Verify> {
        let system = |extra: Vec<rustls::pki_types::CertificateDer<'static>>| -> Result<Verify> {
            let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(
                extra,
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .context("loading the operating system's trust store")?;
            Ok(Verify::Verifier(Arc::new(verifier)))
        };
        match (*self, public) {
            (Trust::Public, PublicRoots::System) => system(Vec::new()),
            (Trust::PublicAnd(extra), PublicRoots::System) => {
                let certs = crate::tls::load_certs(extra)
                    .with_context(|| Origin::Outbound.key(what, "extra_ca_path"))?;
                system(certs).with_context(|| Origin::Outbound.key(what, "extra_ca_path"))
            }
            _ => Ok(Verify::Roots(self.roots(what)?)),
        }
    }

    /// The root store. `what` names the section in errors.
    pub(crate) fn roots(&self, what: &str) -> Result<RootCertStore> {
        match *self {
            Trust::Public => roots(""),
            Trust::Only(ca_path) => {
                roots(ca_path).with_context(|| Origin::Section.key(what, "ca_path"))
            }
            Trust::PublicAnd(extra) => {
                public_and(extra).with_context(|| Origin::Outbound.key(what, "extra_ca_path"))
            }
        }
    }

    /// For logs: `public`, `public+extra_ca_path` or `ca_path`.
    pub fn label(&self) -> &'static str {
        self.label_for(PublicRoots::Bundled)
    }

    /// [`Trust::label`] for a client whose public trust is `public`: `system` for the operating
    /// system's store.
    pub fn label_for(&self, public: PublicRoots) -> &'static str {
        match (self, public) {
            (Trust::Public, PublicRoots::Bundled) => "public",
            (Trust::Public, PublicRoots::System) => "system",
            (Trust::PublicAnd(_), PublicRoots::Bundled) => "public+extra_ca_path",
            (Trust::PublicAnd(_), PublicRoots::System) => "system+extra_ca_path",
            (Trust::Only(_), _) => "ca_path",
        }
    }
}

/// What one client uses: its section's own settings, and `[outbound]` for the keys it leaves
/// empty. A client certificate is inherited as a pair, never half from each. The TLS settings of
/// `[outbound]` reach `https://` URLs only, where they mean something; the proxy reaches any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings<'a> {
    pub trust: Trust<'a>,
    /// The certificate and key files.
    pub identity: Option<(&'a str, &'a str, Origin)>,
    /// `""` (the environment), `"none"`, or a proxy URL.
    pub proxy: (&'a str, Origin),
}

impl<'a> Settings<'a> {
    pub fn of(cfg: &'a OutboundCfg, url: &str) -> Settings<'a> {
        let d = &cfg.defaults;
        let https = is_https(url);
        let trust = if !cfg.ca_path.is_empty() {
            Trust::Only(&cfg.ca_path)
        } else if https && !d.extra_ca_path.is_empty() {
            Trust::PublicAnd(&d.extra_ca_path)
        } else {
            Trust::Public
        };
        let identity = if !cfg.client_cert_path.is_empty() || !cfg.client_key_path.is_empty() {
            Some((
                cfg.client_cert_path.as_str(),
                cfg.client_key_path.as_str(),
                Origin::Section,
            ))
        } else if https && !d.client_cert_path.is_empty() {
            Some((
                d.client_cert_path.as_str(),
                d.client_key_path.as_str(),
                Origin::Outbound,
            ))
        } else {
            None
        };
        let proxy = if cfg.proxy.trim().is_empty() {
            (d.proxy.as_str(), Origin::Outbound)
        } else {
            (cfg.proxy.as_str(), Origin::Section)
        };
        Settings {
            trust,
            identity,
            proxy,
        }
    }

    /// The `[outbound]` keys this client takes: `extra_ca_path`, `client_cert_path`, `proxy`.
    pub fn inherited(&self) -> Vec<&'static str> {
        let mut keys = Vec::new();
        if matches!(self.trust, Trust::PublicAnd(_)) {
            keys.push("extra_ca_path");
        }
        if matches!(self.identity, Some((_, _, Origin::Outbound))) {
            keys.push("client_cert_path");
        }
        if self.proxy.1 == Origin::Outbound && !self.proxy.0.trim().is_empty() {
            keys.push("proxy");
        }
        keys
    }

    /// Whether `[outbound]` would set TLS for this client, were its URL `https://`: it has a CA or
    /// a certificate the section does not override.
    pub fn would_inherit_tls(cfg: &OutboundCfg) -> bool {
        Settings::of(cfg, "https://") != Settings::of(cfg, "http://")
    }
}

/// The sections `cfg` turns on that take something from `[outbound]`, with what they take, for
/// the startup log and `doctor`.
pub fn inheritors(cfg: &crate::config::Config) -> Vec<(&'static str, Vec<&'static str>)> {
    cfg.outbound_clients()
        .iter()
        .filter(|c| c.enabled)
        .map(|c| (c.section, Settings::of(c.outbound, c.url).inherited()))
        .filter(|(_, keys)| !keys.is_empty())
        .collect()
}

/// Check `[outbound]` itself, used by a section or not, so a mistake in it fails at startup (and
/// in `doctor`) rather than when a reload first turns on a client that inherits it.
pub fn check_defaults(d: &OutboundDefaultsCfg) -> Result<()> {
    anyhow::ensure!(
        d.ca_path.is_empty(),
        "outbound.ca_path is not a setting: a ca_path replaces the public roots, so inherited by \
         a public endpoint (an alert webhook on a chat service, a JWKS at a SaaS identity \
         provider) it would break it. Use outbound.extra_ca_path to trust these CAs beside the \
         public ones, or ca_path in the sections whose endpoint is private"
    );
    anyhow::ensure!(
        d.client_cert_path.is_empty() == d.client_key_path.is_empty(),
        "outbound.client_cert_path and client_key_path must be set together"
    );
    if !d.extra_ca_path.is_empty() {
        public_and(&d.extra_ca_path).context("outbound.extra_ca_path")?;
    }
    if !d.client_cert_path.is_empty() {
        CertStore::load(&d.client_cert_path, &d.client_key_path, CertSource::File)
            .context("client certificate (does the key match the certificate?)")
            .context("outbound.client_cert_path")?;
    }
    parse_proxy(&d.proxy).context("outbound.proxy")?;
    Ok(())
}

/// The CAs in `ca_path`, or the public web PKI (the Mozilla roots built into the binary) when it
/// is empty. A set `ca_path` replaces the public roots: only its CAs are trusted.
pub(crate) fn roots(ca_path: &str) -> Result<RootCertStore> {
    if ca_path.is_empty() {
        return Ok(RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ));
    }
    let mut roots = RootCertStore::empty();
    add_cas(&mut roots, ca_path)?;
    Ok(roots)
}

/// The public web PKI and the CAs in `extra`.
fn public_and(extra: &str) -> Result<RootCertStore> {
    let mut roots = roots("")?;
    add_cas(&mut roots, extra)?;
    Ok(roots)
}

fn add_cas(roots: &mut RootCertStore, ca_path: &str) -> Result<()> {
    for cert in crate::tls::load_certs(ca_path)? {
        roots
            .add(cert)
            .with_context(|| format!("{ca_path}: not a usable CA certificate"))?;
    }
    Ok(())
}

/// A rustls client config over `roots`, presenting `identity` to a server that asks for a client
/// certificate, offering HTTP/1.1 — the one protocol the outbound clients here speak. Built on
/// the ring provider explicitly, like every rustls config in this crate. With an identity, it
/// never resumes a session.
pub(crate) fn client_config(
    roots: RootCertStore,
    identity: Option<ClientIdentity>,
) -> Result<ClientConfig> {
    client_config_verifying(Verify::Roots(roots), identity)
}

/// [`client_config`], checking the server with `verify`.
pub(crate) fn client_config_verifying(
    verify: Verify,
    identity: Option<ClientIdentity>,
) -> Result<ClientConfig> {
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("selecting TLS protocol versions")?;
    let builder = match verify {
        Verify::Roots(roots) => builder.with_root_certificates(roots),
        Verify::Verifier(verifier) => builder
            .dangerous()
            .with_custom_certificate_verifier(verifier),
    };
    let mut config = match identity {
        Some(identity) => {
            let mut config = builder
                .with_client_cert_resolver(Arc::new(identity) as Arc<dyn ResolvesClientCert>);
            // A resumed session carries the client certificate of the handshake it resumes, so
            // after a rotation the server would go on seeing the replaced certificate — expired or
            // revoked, possibly — for as long as its tickets last. Every connection that presents
            // a certificate presents the current one, in a full handshake.
            config.resumption = rustls::client::Resumption::disabled();
            config
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

type OnNew = Box<dyn Fn(&Arc<CertStore>) + Send>;

/// Every client certificate this process has loaded, by (certificate path, key path), and which
/// clients present each one now.
#[derive(Default)]
struct Identities {
    stores: HashMap<(String, String), Arc<CertStore>>,
    /// Live [`Claim`]s: the pair each was taken on, and by what.
    claims: HashMap<u64, ((String, String), String)>,
    next_claim: u64,
    on_new: Option<OnNew>,
}

fn identities() -> &'static Mutex<Identities> {
    static IDENTITIES: OnceLock<Mutex<Identities>> = OnceLock::new();
    IDENTITIES.get_or_init(Mutex::default)
}

/// A client certificate as one client presents it: the shared store, and that client's claim on
/// it. The claim is what makes the certificate in use, for the certificate series and
/// `GET /__edgeguard/tls`. It goes when the client's TLS config goes, so a certificate a reload
/// stopped presenting stops being reported, and alerted on, even though its store lives on.
pub struct ClientIdentity {
    store: Arc<CertStore>,
    _claim: Claim,
}

impl ClientIdentity {
    pub fn store(&self) -> &Arc<CertStore> {
        &self.store
    }
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("cert_path", &self.store.cert_path())
            .finish()
    }
}

impl ResolvesClientCert for ClientIdentity {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        ResolvesClientCert::resolve(&*self.store, root_hint_subjects, sigschemes)
    }

    fn has_certs(&self) -> bool {
        ResolvesClientCert::has_certs(&*self.store)
    }
}

/// One client's hold on a certificate, released when it is dropped.
struct Claim(u64);

impl Drop for Claim {
    fn drop(&mut self) {
        let mut identities = identities().lock().unwrap_or_else(PoisonError::into_inner);
        identities.claims.remove(&self.0);
    }
}

/// The client certificate in `cert_path` and `key_path` as `used_by` presents it (a section
/// name: `log.ship`, `upstream:<target>`): `None` when both paths are empty, an error when only
/// one is set. The same pair is the same store, however many clients present it and however often
/// they are rebuilt, so one watcher keeps it current for all of them.
pub fn identity(cert_path: &str, key_path: &str, used_by: &str) -> Result<Option<ClientIdentity>> {
    anyhow::ensure!(
        cert_path.is_empty() == key_path.is_empty(),
        "cert_path and key_path must be set together (a client certificate needs its key)"
    );
    if cert_path.is_empty() {
        return Ok(None);
    }
    let key = (cert_path.to_string(), key_path.to_string());
    let mut identities = identities().lock().unwrap_or_else(PoisonError::into_inner);
    let store = match identities.stores.get(&key) {
        Some(store) => Arc::clone(store),
        None => {
            let store = CertStore::load(cert_path, key_path, CertSource::File)
                .context("client certificate (does the key match the certificate?)")?;
            if let Some(on_new) = &identities.on_new {
                on_new(&store);
            }
            identities.stores.insert(key.clone(), Arc::clone(&store));
            store
        }
    };
    let id = identities.next_claim;
    identities.next_claim += 1;
    identities.claims.insert(id, (key, used_by.to_string()));
    Ok(Some(ClientIdentity {
        store,
        _claim: Claim(id),
    }))
}

/// A client certificate some client presents now, and which clients.
pub struct InUse {
    pub store: Arc<CertStore>,
    /// Sorted, without repeats.
    pub used_by: Vec<String>,
}

/// Every client certificate in use, by certificate path.
pub fn in_use() -> Vec<InUse> {
    let identities = identities().lock().unwrap_or_else(PoisonError::into_inner);
    let mut by_pair: std::collections::BTreeMap<&(String, String), Vec<String>> =
        std::collections::BTreeMap::new();
    for (pair, user) in identities.claims.values() {
        by_pair.entry(pair).or_default().push(user.clone());
    }
    by_pair
        .into_iter()
        .filter_map(|(pair, mut used_by)| {
            used_by.sort();
            used_by.dedup();
            let store = Arc::clone(identities.stores.get(pair)?);
            Some(InUse { store, used_by })
        })
        .collect()
}

/// Call `on_new` once for every client certificate loaded so far, and for each one first loaded
/// from now on — upstream, control plane, collectors, wherever it is presented. `main` watches
/// them with it.
pub fn watch_identities(on_new: impl Fn(&Arc<CertStore>) + Send + 'static) {
    let mut identities = identities().lock().unwrap_or_else(PoisonError::into_inner);
    for store in identities.stores.values() {
        on_new(store);
    }
    identities.on_new = Some(Box::new(on_new));
}

/// How a client reaches its endpoint (`proxy`).
#[derive(Debug)]
enum ProxyRoute {
    /// `HTTPS_PROXY` / `NO_PROXY`, as reqwest reads them.
    Environment,
    /// No proxy, whatever the environment says.
    Direct,
    /// This proxy, for this client only.
    Via(Box<reqwest::Proxy>),
}

fn parse_proxy(raw: &str) -> Result<ProxyRoute> {
    let raw = raw.trim();
    match raw {
        "" => return Ok(ProxyRoute::Environment),
        "none" => return Ok(ProxyRoute::Direct),
        _ => {}
    }
    let url =
        reqwest::Url::parse(raw).map_err(|e| anyhow::anyhow!("{:?}: {e}", redact_proxy(raw)))?;
    // An `https://` proxy would be verified against `ca_path` — the endpoint's CA, not the
    // proxy's — and a SOCKS proxy is not built in. A plain-HTTP CONNECT proxy is what egress
    // proxies are, and the tunnel it carries is still TLS end to end.
    anyhow::ensure!(
        url.scheme() == "http",
        "{:?}: expected an http:// proxy URL (a CONNECT proxy), or \"none\"",
        redact_proxy(raw)
    );
    anyhow::ensure!(url.host().is_some(), "{:?} has no host", redact_proxy(raw));
    // A password in the URL becomes the `Proxy-Authorization` on the CONNECT.
    let proxy = reqwest::Proxy::all(url).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(ProxyRoute::Via(Box::new(proxy)))
}

/// `proxy` with any password in it replaced, for logs and errors.
pub fn redact_proxy(raw: &str) -> String {
    match reqwest::Url::parse(raw.trim()) {
        Ok(mut url) if url.password().is_some() => {
            let _ = url.set_password(Some("redacted"));
            url.to_string()
        }
        _ if raw.contains('@') => "<redacted>".to_string(),
        _ => raw.trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_setting() {
        assert!(matches!(parse_proxy("").unwrap(), ProxyRoute::Environment));
        assert!(matches!(parse_proxy("none").unwrap(), ProxyRoute::Direct));
        assert!(matches!(
            parse_proxy("http://user:pw@egress.corp:3128").unwrap(),
            ProxyRoute::Via(_)
        ));
        for bad in [
            "https://egress.corp:3128",
            "socks5://egress.corp:1080",
            "egress.corp:3128",
        ] {
            assert!(parse_proxy(bad).is_err(), "{bad}");
        }
        // The password never reaches an error or a log line.
        let e = format!(
            "{:#}",
            parse_proxy("https://u:hunter2@egress:3128").err().unwrap()
        );
        assert!(!e.contains("hunter2"), "{e}");
        let e = format!("{:#}", parse_proxy("u:hunter2@egress:3128").err().unwrap());
        assert!(!e.contains("hunter2"), "{e}");
        assert_eq!(
            redact_proxy("http://u:hunter2@egress:3128"),
            "http://u:redacted@egress:3128/"
        );
        assert_eq!(redact_proxy("http://egress:3128"), "http://egress:3128");
    }

    #[test]
    fn private_tls_settings_need_https_and_must_load() {
        let err = |cfg: OutboundCfg, url: &str| {
            format!("{:#}", builder(&cfg, "log.ship", url).err().unwrap())
        };
        let ca = OutboundCfg {
            ca_path: "/etc/eggrd/ca.pem".into(),
            ..Default::default()
        };
        assert!(err(ca.clone(), "http://collector:8080").contains("log.ship.ca_path"));
        let cert = OutboundCfg {
            client_cert_path: "/etc/eggrd/edge.pem".into(),
            client_key_path: "/etc/eggrd/edge.key".into(),
            ..Default::default()
        };
        assert!(err(cert, "http://collector:8080").contains("not https://"));
        let half = OutboundCfg {
            client_cert_path: "/etc/eggrd/edge.pem".into(),
            ..Default::default()
        };
        assert!(err(half, "https://collector").contains("set together"));
        let missing = OutboundCfg {
            client_cert_path: "/no/such/edge.pem".into(),
            client_key_path: "/no/such/edge.key".into(),
            ..Default::default()
        };
        assert!(err(missing, "https://collector").contains("log.ship.client_cert_path"));
        assert!(err(ca, "https://collector").contains("log.ship.ca_path"));
        let proxy = OutboundCfg {
            proxy: "ftp://x".into(),
            ..Default::default()
        };
        assert!(err(proxy, "https://collector").contains("log.ship.proxy"));
        // Nothing set: an ordinary client, for any URL.
        assert!(builder(&OutboundCfg::default(), "log.ship", "http://collector").is_ok());
    }

    fn defaults() -> OutboundDefaultsCfg {
        OutboundDefaultsCfg {
            extra_ca_path: "/etc/eggrd/corp-ca.pem".into(),
            client_cert_path: "/etc/eggrd/edge.pem".into(),
            client_key_path: "/etc/eggrd/edge.key".into(),
            proxy: "http://egress:3128".into(),
            ca_path: String::new(),
        }
    }

    #[test]
    fn a_section_takes_outbound_for_each_key_it_leaves_empty() {
        let inherit = OutboundCfg {
            defaults: defaults(),
            ..Default::default()
        };
        let s = Settings::of(&inherit, "https://collector");
        assert_eq!(s.trust, Trust::PublicAnd("/etc/eggrd/corp-ca.pem"));
        assert_eq!(
            s.identity,
            Some((
                "/etc/eggrd/edge.pem",
                "/etc/eggrd/edge.key",
                Origin::Outbound
            ))
        );
        assert_eq!(s.proxy, ("http://egress:3128", Origin::Outbound));
        assert_eq!(
            s.inherited(),
            ["extra_ca_path", "client_cert_path", "proxy"]
        );
        assert!(Settings::would_inherit_tls(&inherit));

        // The TLS defaults mean nothing to plain http://; the proxy still applies.
        let s = Settings::of(&inherit, "http://collector");
        assert_eq!((s.trust, s.identity), (Trust::Public, None));
        assert_eq!(s.inherited(), ["proxy"]);

        // The section's own keys win, one by one.
        let own = OutboundCfg {
            ca_path: "/etc/eggrd/collector-ca.pem".into(),
            proxy: "none".into(),
            ..inherit.clone()
        };
        let s = Settings::of(&own, "https://collector");
        assert_eq!(s.trust, Trust::Only("/etc/eggrd/collector-ca.pem"));
        assert_eq!(s.proxy, ("none", Origin::Section));
        assert_eq!(
            s.inherited(),
            ["client_cert_path"],
            "the certificate still comes in"
        );

        // A certificate is the section's as soon as it names either file: never half of each.
        let half = OutboundCfg {
            client_cert_path: "/etc/eggrd/log.pem".into(),
            ..inherit.clone()
        };
        assert_eq!(
            Settings::of(&half, "https://collector").identity,
            Some(("/etc/eggrd/log.pem", "", Origin::Section))
        );
        let e = builder(&half, "log.ship", "https://collector")
            .err()
            .unwrap();
        assert!(format!("{e:#}").contains("set together"), "{e:#}");
        let key_only = OutboundCfg {
            client_key_path: "/etc/eggrd/log.key".into(),
            ..inherit.clone()
        };
        assert_eq!(
            Settings::of(&key_only, "https://collector").identity,
            Some(("", "/etc/eggrd/log.key", Origin::Section))
        );

        // Nothing anywhere: the public roots, no certificate, the environment's proxy.
        let nothing = OutboundCfg::default();
        let s = Settings::of(&nothing, "https://collector");
        assert_eq!((s.trust, s.identity), (Trust::Public, None));
        assert_eq!(s.proxy, ("", Origin::Outbound));
        assert!(s.inherited().is_empty());
        assert!(!Settings::would_inherit_tls(&nothing));
        let overridden = OutboundCfg {
            ca_path: "/etc/eggrd/collector-ca.pem".into(),
            client_cert_path: "/etc/eggrd/log.pem".into(),
            client_key_path: "/etc/eggrd/log.key".into(),
            ..inherit
        };
        assert!(!Settings::would_inherit_tls(&overridden));
    }

    #[test]
    fn an_inherited_setting_is_named_where_it_is_written() {
        let inherit = |d: OutboundDefaultsCfg| OutboundCfg {
            defaults: d,
            ..Default::default()
        };
        let err = |cfg: OutboundCfg| {
            format!(
                "{:#}",
                builder(&cfg, "log.ship", "https://collector")
                    .err()
                    .unwrap()
            )
        };
        let e = err(inherit(OutboundDefaultsCfg {
            extra_ca_path: "/no/such/ca.pem".into(),
            ..Default::default()
        }));
        assert!(
            e.contains("outbound.extra_ca_path (inherited by log.ship)"),
            "{e}"
        );
        let e = err(inherit(OutboundDefaultsCfg {
            client_cert_path: "/no/such/edge.pem".into(),
            client_key_path: "/no/such/edge.key".into(),
            ..Default::default()
        }));
        assert!(
            e.contains("outbound.client_cert_path (inherited by log.ship)"),
            "{e}"
        );
        let e = err(inherit(OutboundDefaultsCfg {
            proxy: "socks5://egress:1080".into(),
            ..Default::default()
        }));
        assert!(e.contains("outbound.proxy (inherited by log.ship)"), "{e}");
        // Unlike a section's own, inherited TLS settings on plain http:// are not an error: they
        // are not used there, and the section said nothing about TLS.
        let unloadable = inherit(OutboundDefaultsCfg {
            extra_ca_path: "/no/such/ca.pem".into(),
            client_cert_path: "/no/such/edge.pem".into(),
            client_key_path: "/no/such/edge.key".into(),
            ..Default::default()
        });
        assert!(builder(&unloadable, "log.ship", "http://127.0.0.1:4318").is_ok());
    }

    #[test]
    fn outbound_defaults_are_checked_on_their_own() {
        let check = |d: OutboundDefaultsCfg| check_defaults(&d).map_err(|e| format!("{e:#}"));
        assert!(check(OutboundDefaultsCfg::default()).is_ok());
        let e = check(OutboundDefaultsCfg {
            ca_path: "/etc/eggrd/corp-ca.pem".into(),
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            e.contains("outbound.ca_path is not a setting") && e.contains("extra_ca_path"),
            "{e}"
        );
        let e = check(OutboundDefaultsCfg {
            client_key_path: "/etc/eggrd/edge.key".into(),
            ..Default::default()
        })
        .unwrap_err();
        assert!(e.contains("set together"), "{e}");
        let e = check(OutboundDefaultsCfg {
            extra_ca_path: "/no/such/ca.pem".into(),
            ..Default::default()
        })
        .unwrap_err();
        assert!(e.contains("outbound.extra_ca_path"), "{e}");
        let e = check(OutboundDefaultsCfg {
            client_cert_path: "/no/such/edge.pem".into(),
            client_key_path: "/no/such/edge.key".into(),
            ..Default::default()
        })
        .unwrap_err();
        assert!(e.contains("outbound.client_cert_path"), "{e}");
        let e = check(OutboundDefaultsCfg {
            proxy: "https://egress:3128".into(),
            ..Default::default()
        })
        .unwrap_err();
        assert!(e.contains("outbound.proxy"), "{e}");
    }

    #[test]
    fn extra_cas_are_added_to_the_public_roots_not_put_in_their_place() {
        let dir = std::env::temp_dir().join(format!("eg-extra-ca-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let path = dir.join("corp-ca.pem");
        std::fs::write(&path, ca.pem()).unwrap();
        let path = path.display().to_string();
        let public = webpki_roots::TLS_SERVER_ROOTS.len();
        let len = |t: Trust| t.roots("log.ship").unwrap().len();
        assert_eq!(len(Trust::PublicAnd(&path)), public + 1);
        assert_eq!(
            len(Trust::Only(&path)),
            1,
            "a section's ca_path replaces them"
        );
        assert_eq!(len(Trust::Public), public);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_store_per_file_pair_and_each_is_announced_once() {
        let dir = std::env::temp_dir().join(format!("eg-outbound-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pair = |name: &str| {
            let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
            let (c, k) = (
                dir.join(format!("{name}.pem")),
                dir.join(format!("{name}.key")),
            );
            std::fs::write(&c, cert.cert.pem()).unwrap();
            std::fs::write(&k, cert.signing_key.serialize_pem()).unwrap();
            (c.display().to_string(), k.display().to_string())
        };
        let (a_cert, a_key) = pair("a.example");
        let (b_cert, b_key) = pair("b.example");

        let a = identity(&a_cert, &a_key, "log.ship").unwrap().unwrap();
        // Other tests in this binary load pairs too, so count only this test's.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let mine = dir.display().to_string();
        watch_identities(move |store| {
            if store.cert_path().starts_with(&mine) {
                record.lock().unwrap().push(store.cert_path().to_string());
            }
        });
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            std::slice::from_ref(&a_cert),
            "loaded before"
        );
        let again = identity(&a_cert, &a_key, "tracing").unwrap().unwrap();
        assert!(
            Arc::ptr_eq(a.store(), again.store()),
            "the same pair is the same store"
        );
        let b = identity(&b_cert, &b_key, "upstream").unwrap().unwrap();
        identity(&b_cert, &b_key, "upstream").unwrap().unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            [a_cert.clone(), b_cert.clone()],
            "once per pair"
        );
        assert!(identity("", "", "log.ship").unwrap().is_none());

        // In use while a client holds its identity, by every client that does.
        let mine = |path: &str| in_use().into_iter().find(|u| u.store.cert_path() == path);
        assert_eq!(mine(&a_cert).unwrap().used_by, ["log.ship", "tracing"]);
        assert_eq!(
            mine(&b_cert).unwrap().used_by,
            ["upstream"],
            "the second claim was dropped"
        );
        drop(again);
        assert_eq!(mine(&a_cert).unwrap().used_by, ["log.ship"]);
        drop((a, b));
        assert!(
            mine(&a_cert).is_none(),
            "no client presents it: not reported"
        );
        assert!(mine(&b_cert).is_none());
        // The store itself stays, watched, for the next client that names the pair.
        let back = identity(&a_cert, &a_key, "alerts").unwrap().unwrap();
        assert_eq!(seen.lock().unwrap().len(), 2, "not announced again");
        assert_eq!(mine(&a_cert).unwrap().used_by, ["alerts"]);
        drop(back);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
