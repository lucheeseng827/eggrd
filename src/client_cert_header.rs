//! Client certificates a load balancer verified and forwarded in a header
//! (`[trusted_client_cert_header]`).
//!
//! When an L7 load balancer terminates the client's mutual TLS, EdgeGuard's listener never sees
//! the client certificate: the balancer has it, and forwards it in a header. [`TrustedHeader`]
//! reads that header and makes it the request's client certificate — the same
//! [`ClientCert`] extension the TLS listener attaches — so authentication, forwarding, the access
//! log and the metrics need nothing of their own.
//!
//! A header is something any client can send, so it is believed only from the balancer: from
//! `trusted_proxies`, matched against the connection's own peer address, never
//! `X-Forwarded-For`; or from `trusted_proxy_names`, matched against the names in the TLS client
//! certificate the connection presented; or, with both, from a connection that matches both.
//! From anyone else it is dropped. Either way it is removed before the request goes upstream.

use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::http::{HeaderMap, HeaderName, Request};
use base64::Engine;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use tracing::warn;

use crate::access::Cidr;
use crate::certstore::CertNames;
use crate::client_auth::{ClientAuth, ClientCert, NamePattern};
use crate::config::TrustedClientCertHeaderCfg;

/// How the header carries the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// PEM, URL-encoded or not; a chain is leaf first.
    Pem,
    /// One certificate as base64 DER, URL-encoded or not.
    Der,
    /// Envoy's `X-Forwarded-Client-Cert`.
    Xfcc,
}

/// What became of a request's forwarded certificate: `edgeguard_client_cert_header_total{result}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderResult {
    /// From a trusted peer, read (and verified, with `ca_path`): the request's client certificate.
    Accepted,
    /// From a peer outside `trusted_proxies`, or one whose certificate `trusted_proxy_names` does
    /// not name: dropped. A forgery, or a balancer whose addresses or certificate changed.
    UntrustedPeer,
    /// From a trusted peer, but not a certificate in the configured format, or sent twice.
    Invalid,
    /// From a trusted peer, readable, but refused by the `ca_path` verification.
    Unverified,
}

impl HeaderResult {
    pub const ALL: [HeaderResult; 4] = [
        HeaderResult::Accepted,
        HeaderResult::UntrustedPeer,
        HeaderResult::Invalid,
        HeaderResult::Unverified,
    ];

    pub fn label(self) -> &'static str {
        match self {
            HeaderResult::Accepted => "accepted",
            HeaderResult::UntrustedPeer => "untrusted_peer",
            HeaderResult::Invalid => "invalid",
            HeaderResult::Unverified => "unverified",
        }
    }
}

/// `[trusted_client_cert_header]`, compiled.
pub struct TrustedHeader {
    name: HeaderName,
    format: Format,
    proxies: Vec<Cidr>,
    proxies_text: Vec<String>,
    names: Vec<NamePattern>,
    names_text: Vec<String>,
    verifier: Option<Arc<ClientAuth>>,
    /// Unix second of the last warning about a trusted peer's header: one a minute at most, since a
    /// misconfigured format fails every request.
    last_warning: AtomicI64,
}

impl std::fmt::Debug for TrustedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedHeader")
            .field("name", &self.name)
            .field("format", &self.format)
            .field("trusted_proxies", &self.proxies_text)
            .field("trusted_proxy_names", &self.names_text)
            .finish()
    }
}

impl TrustedHeader {
    /// `None` when `name` is empty. Fails on what would make the header unsafe or unusable:
    /// neither `trusted_proxies` nor `trusted_proxy_names`, a `/0` or a bare `*` among them, an
    /// unknown format, CA or CRL files that do not load.
    pub fn from_cfg(cfg: &TrustedClientCertHeaderCfg) -> Result<Option<Arc<TrustedHeader>>> {
        let name = cfg.name.trim();
        if name.is_empty() {
            return Ok(None);
        }
        let name = HeaderName::try_from(name)
            .with_context(|| format!("trusted_client_cert_header.name {name:?}"))?;
        let format = match cfg.format.as_str() {
            "pem" => Format::Pem,
            "der" => Format::Der,
            "xfcc" => Format::Xfcc,
            other => anyhow::bail!(
                "unknown trusted_client_cert_header.format {other:?} (expected pem|der|xfcc)"
            ),
        };
        anyhow::ensure!(
            !(cfg.trusted_proxies.is_empty() && cfg.trusted_proxy_names.is_empty()),
            "trusted_client_cert_header needs trusted_proxies or trusted_proxy_names: without \
             either the header would be believed from anyone, and any client could claim any \
             certificate"
        );
        let names = cfg
            .trusted_proxy_names
            .iter()
            .map(|n| NamePattern::parse("trusted_client_cert_header.trusted_proxy_names", n))
            .collect::<Result<Vec<_>>>()?;
        anyhow::ensure!(
            !names.iter().any(NamePattern::matches_everything),
            "trusted_client_cert_header.trusted_proxy_names contains \"*\", every certificate: \
             any client with one could claim any other. Name the load balancer's certificate."
        );
        let proxies = cfg
            .trusted_proxies
            .iter()
            .map(|p| Cidr::parse(p).context("trusted_client_cert_header.trusted_proxies"))
            .collect::<Result<Vec<_>>>()?;
        if let Some((text, _)) = cfg
            .trusted_proxies
            .iter()
            .zip(&proxies)
            .find(|(_, c)| c.is_everything())
        {
            anyhow::bail!(
                "trusted_client_cert_header.trusted_proxies contains {text:?}, every address: any \
                 client could claim any certificate. List the load balancer's addresses."
            );
        }
        anyhow::ensure!(
            cfg.crl_paths.is_empty() || !cfg.ca_path.is_empty(),
            "trusted_client_cert_header.crl_paths needs ca_path: a CRL is checked as part of verifying"
        );
        let verifier = if cfg.ca_path.is_empty() {
            None
        } else {
            Some(
                ClientAuth::for_header(&cfg.ca_path, &cfg.crl_paths)
                    .context("trusted_client_cert_header")?,
            )
        };
        Ok(Some(Arc::new(TrustedHeader {
            name,
            format,
            proxies,
            proxies_text: cfg.trusted_proxies.clone(),
            names,
            names_text: cfg.trusted_proxy_names.clone(),
            verifier,
            last_warning: AtomicI64::new(0),
        })))
    }

    pub fn name(&self) -> &HeaderName {
        &self.name
    }

    pub fn format(&self) -> Format {
        self.format
    }

    pub fn trusted_proxies(&self) -> &[String] {
        &self.proxies_text
    }

    pub fn trusted_proxy_names(&self) -> &[String] {
        &self.names_text
    }

    /// The verifier `ca_path` builds, for `main` to watch and the certificate series to report.
    pub fn verifier(&self) -> Option<&Arc<ClientAuth>> {
        self.verifier.as_ref()
    }

    /// Whether a connection from `peer`, which presented `hop` in its TLS handshake, is the
    /// balancer: `peer` is one of `trusted_proxies`, and `hop` has a name `trusted_proxy_names`
    /// lists, each when it is set. An IPv4 peer on a dual-stack socket arrives as
    /// `::ffff:a.b.c.d`, and is matched as the IPv4 address it is.
    pub fn trusts(&self, peer: IpAddr, hop: Option<&ClientCert>) -> bool {
        let peer = peer.to_canonical();
        let by_address = self.proxies.is_empty() || self.proxies.iter().any(|c| c.contains(peer));
        let by_name = self.names.is_empty()
            || hop.is_some_and(|cert| {
                cert.identities()
                    .any(|name| self.names.iter().any(|p| p.matches(name)))
            });
        by_address && by_name
    }

    /// Take the header off `req`, and when it came from a trusted peer and holds a certificate,
    /// make that the request's client certificate. From a trusted peer, the connection is the
    /// balancer's, and so is any certificate its handshake presented: the request has the
    /// header's certificate or none, whatever the header holds. `None` when there was no header.
    pub fn apply<B>(&self, peer: IpAddr, req: &mut Request<B>) -> Option<HeaderResult> {
        let values = take_all(req.headers_mut(), &self.name);
        let hop = req.extensions().get::<Arc<ClientCert>>().cloned();
        let trusted = self.trusts(peer, hop.as_deref());
        if trusted {
            req.extensions_mut().remove::<Arc<ClientCert>>();
        }
        if values.is_empty() {
            return None;
        }
        if !trusted {
            return Some(HeaderResult::UntrustedPeer);
        }
        let result = match self.read(&values) {
            Ok(cert) => {
                req.extensions_mut().insert(Arc::new(cert));
                return Some(HeaderResult::Accepted);
            }
            Err(Refused::Invalid(why)) => (HeaderResult::Invalid, why),
            Err(Refused::Unverified(why)) => (HeaderResult::Unverified, why),
        };
        let now = crate::certstore::now_unix();
        let last = self.last_warning.load(Ordering::Relaxed);
        if now - last >= 60
            && self
                .last_warning
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            warn!(
                header = %self.name,
                result = result.0.label(),
                reason = %result.1,
                "a trusted proxy's client certificate header was refused; the request has no client certificate (logged once a minute)"
            );
        }
        Some(result.0)
    }

    fn read(&self, values: &[Vec<u8>]) -> Result<ClientCert, Refused> {
        if values.len() > 1 {
            return Err(Refused::Invalid(format!(
                "sent {} times; a load balancer sets it once",
                values.len()
            )));
        }
        let text = String::from_utf8_lossy(&values[0]);
        let forwarded = match self.format {
            Format::Pem => Forwarded::Chain(pem_chain(&percent_decode(&text)?)?),
            Format::Der => Forwarded::Chain(vec![der(&percent_decode(&text)?)?]),
            Format::Xfcc => xfcc(&text)?,
        };
        match forwarded {
            Forwarded::Chain(chain) => {
                if let Some(verifier) = &self.verifier {
                    let (leaf, intermediates) = chain.split_first().expect("a chain has a leaf");
                    verifier
                        .verify_client_cert(leaf, intermediates, UnixTime::now())
                        .map_err(|e| Refused::Unverified(e.to_string()))?;
                }
                Ok(ClientCert::from_der(&chain[0]))
            }
            Forwarded::Details(cert) => {
                if self.verifier.is_some() {
                    return Err(Refused::Unverified(
                        "ca_path is set, and this XFCC carries no Cert or Chain to verify".into(),
                    ));
                }
                Ok(cert)
            }
        }
    }
}

/// Why a trusted peer's header gave no certificate.
enum Refused {
    Invalid(String),
    Unverified(String),
}

impl From<String> for Refused {
    fn from(why: String) -> Refused {
        Refused::Invalid(why)
    }
}

/// What a header carried: a certificate chain (leaf first), or, from an XFCC without one, what the
/// balancer said about it.
enum Forwarded {
    Chain(Vec<CertificateDer<'static>>),
    Details(ClientCert),
}

/// Remove every `name` header, returning their values.
fn take_all(headers: &mut HeaderMap, name: &HeaderName) -> Vec<Vec<u8>> {
    let values = headers
        .get_all(name)
        .iter()
        .map(|v| v.as_bytes().to_vec())
        .collect();
    headers.remove(name);
    values
}

/// `%XX` escapes decoded; everything else, `+` included, kept as it is (base64 has `+`).
fn percent_decode(text: &str) -> Result<String, String> {
    if !text.contains('%') {
        return Ok(text.to_string());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| format!("bad URL escape at byte {i}"))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "not UTF-8 once URL-decoded".to_string())
}

/// Every `CERTIFICATE` block in `text`, whatever whitespace the balancer turned its newlines into.
fn pem_chain(text: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut chain = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let body = &rest[start + BEGIN.len()..];
        let end = body
            .find(END)
            .ok_or("a BEGIN CERTIFICATE without its END")?;
        chain.push(der(&body[..end])?);
        rest = &body[end + END.len()..];
    }
    if chain.is_empty() {
        return Err("no PEM certificate in it".into());
    }
    Ok(chain)
}

/// One certificate from base64 DER, standard or URL-safe alphabet, padded or not.
fn der(text: &str) -> Result<CertificateDer<'static>, String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Err("empty".into());
    }
    let bytes = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&compact).ok())
        .ok_or("not base64")?;
    // Parsed as a certificate, not just decoded: on the TLS path rustls has done this before
    // anything reads the names, and a blob that only starts like DER must not be accepted as one.
    crate::certstore::CertInfo::from_der(&bytes)
        .map_err(|e| format!("not a DER certificate: {e:#}"))?;
    Ok(CertificateDer::from(bytes))
}

/// The client the last XFCC element describes. Each proxy appends an element, so the last is the
/// one the trusted peer added. Its `Chain` or `Cert` (URL-encoded PEM) when present; otherwise the
/// `URI`, `DNS`, `Subject` and `Hash` it reports.
fn xfcc(text: &str) -> Result<Forwarded, String> {
    let element = split_quoted(text, ',')
        .into_iter()
        .rev()
        .find(|e| !e.trim().is_empty())
        .ok_or("an empty X-Forwarded-Client-Cert")?;
    let mut names = CertNames::default();
    let mut hash = String::new();
    let (mut cert, mut chain) = (None, None);
    for pair in split_quoted(&element, ';') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let value = unquote(value.trim());
        match key.trim().to_ascii_lowercase().as_str() {
            "cert" => cert = Some(value),
            "chain" => chain = Some(value),
            "hash" => hash = value.to_ascii_lowercase(),
            "uri" => names.uris.push(value),
            "dns" => names.dns.push(value.to_ascii_lowercase()),
            "subject" => names.common_name = common_name(&value),
            _ => {}
        }
    }
    if let Some(pem) = chain.or(cert) {
        return Ok(Forwarded::Chain(pem_chain(&percent_decode(&pem)?)?));
    }
    if names.uris.is_empty() && names.dns.is_empty() && names.common_name.is_none() {
        return Err("an XFCC element with no certificate and no names".into());
    }
    Ok(Forwarded::Details(ClientCert {
        names,
        sha256: hash,
    }))
}

/// Split on `sep` outside double quotes.
fn split_quoted(text: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in text.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                current.push(c);
                escaped = true;
            }
            '"' => {
                quoted = !quoted;
                current.push(c);
            }
            c if c == sep && !quoted => parts.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    parts.push(current);
    parts
}

/// A value without its surrounding quotes and with `\"` unescaped.
fn unquote(value: &str) -> String {
    match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        Some(inner) => inner.replace("\\\"", "\"").replace("\\\\", "\\"),
        None => value.to_string(),
    }
}

/// The `CN=` of a subject written as `CN=web,OU=…,O=…`.
fn common_name(subject: &str) -> Option<String> {
    subject
        .split(',')
        .find_map(|rdn| rdn.trim().strip_prefix("CN="))
        .map(str::to_string)
        .filter(|cn| !cn.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(proxies: &[&str]) -> TrustedClientCertHeaderCfg {
        TrustedClientCertHeaderCfg {
            name: "X-Client-Cert".into(),
            trusted_proxies: proxies.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn settings_that_would_trust_anyone_are_refused() {
        assert!(
            TrustedHeader::from_cfg(&TrustedClientCertHeaderCfg::default())
                .unwrap()
                .is_none()
        );
        let err = |c: TrustedClientCertHeaderCfg| {
            format!("{:#}", TrustedHeader::from_cfg(&c).unwrap_err())
        };
        assert!(err(cfg(&[])).contains("needs trusted_proxies or trusted_proxy_names"));
        assert!(err(cfg(&["10.0.0.0/8", "0.0.0.0/0"])).contains("every address"));
        assert!(err(cfg(&["::/0"])).contains("every address"));
        assert!(err(cfg(&["10.0.0.300"])).contains("trusted_proxies"));
        let mut c = cfg(&["10.0.0.0/8"]);
        c.format = "json".into();
        assert!(err(c).contains("format"));
        let mut c = cfg(&["10.0.0.0/8"]);
        c.crl_paths = vec!["/etc/eggrd/x.crl".into()];
        assert!(err(c).contains("needs ca_path"));
    }

    #[test]
    fn the_peer_is_matched_as_the_address_it_is() {
        let h = TrustedHeader::from_cfg(&cfg(&["10.1.0.0/16", "2001:db8::/32"]))
            .unwrap()
            .unwrap();
        let trusts = |ip: &str| h.trusts(ip.parse().unwrap(), None);
        assert!(trusts("10.1.2.3"));
        assert!(trusts("::ffff:10.1.2.3"), "IPv4 on a dual-stack socket");
        assert!(trusts("2001:db8::7"));
        assert!(!trusts("10.2.0.1"));
        assert!(!trusts("::ffff:10.2.0.1"));
    }

    fn cert(uris: &[&str], dns: &[&str], cn: Option<&str>) -> ClientCert {
        ClientCert {
            names: CertNames {
                uris: uris.iter().map(|u| u.to_string()).collect(),
                dns: dns.iter().map(|d| d.to_string()).collect(),
                common_name: cn.map(str::to_string),
                ..Default::default()
            },
            sha256: "00".into(),
        }
    }

    #[test]
    fn by_name_the_balancer_is_the_certificate_it_presents() {
        let named = |names: &[&str], proxies: &[&str]| {
            TrustedHeader::from_cfg(&TrustedClientCertHeaderCfg {
                trusted_proxy_names: names.iter().map(|n| n.to_string()).collect(),
                ..cfg(proxies)
            })
            .unwrap()
            .unwrap()
        };
        let any_ip = "203.0.113.9".parse().unwrap();
        let h = named(&["spiffe://prod.example/ns/ingress/*", "lb.internal"], &[]);
        let ingress = cert(&["spiffe://prod.example/ns/ingress/envoy"], &[], None);
        let lb = cert(&[], &["lb.internal"], Some("ignored"));
        let by_cn = cert(&[], &[], Some("lb.internal"));
        let other = cert(
            &["spiffe://prod.example/ns/web/app"],
            &["web.internal"],
            None,
        );
        assert!(
            h.trusts(any_ip, Some(&ingress)),
            "a prefix, from any address"
        );
        assert!(h.trusts(any_ip, Some(&lb)), "an exact DNS name");
        assert!(
            h.trusts(any_ip, Some(&by_cn)),
            "the common name is a name too"
        );
        assert!(!h.trusts(any_ip, Some(&other)));
        assert!(!h.trusts(any_ip, None), "no certificate, no name");
        // With addresses too, both must match.
        let both = named(&["lb.internal"], &["10.1.0.0/16"]);
        assert!(both.trusts("10.1.0.5".parse().unwrap(), Some(&lb)));
        assert!(
            !both.trusts(any_ip, Some(&lb)),
            "the right name, from elsewhere"
        );
        assert!(!both.trusts("10.1.0.5".parse().unwrap(), Some(&other)));
        assert!(!both.trusts("10.1.0.5".parse().unwrap(), None));
        assert_eq!(both.trusted_proxy_names(), ["lb.internal"]);
    }

    #[test]
    fn a_name_that_matches_every_certificate_is_refused() {
        let err = |names: &[&str]| {
            let c = TrustedClientCertHeaderCfg {
                trusted_proxy_names: names.iter().map(|n| n.to_string()).collect(),
                ..cfg(&[])
            };
            format!("{:#}", TrustedHeader::from_cfg(&c).unwrap_err())
        };
        assert!(err(&["lb.internal", "*"]).contains("every certificate"));
        assert!(err(&[""]).contains("trusted_proxy_names entries must not be empty"));
        assert!(err(&["*.internal"]).contains("trusted_proxy_names \"*.internal\""));
    }

    #[test]
    fn escapes_and_encodings_are_read_as_balancers_write_them() {
        assert_eq!(
            percent_decode("a%2Bb+c%0A").unwrap(),
            "a+b+c\n",
            "`+` stays `+`"
        );
        assert!(percent_decode("a%2").is_err());
        assert!(
            der("bm90IGEgY2VydA==").is_err(),
            "base64, but not a certificate"
        );
        assert!(der("").is_err());
        assert!(pem_chain("no pem here").is_err());
        assert_eq!(
            split_quoted(r#"By=a;URI="x;y";DNS=d,Hash=h"#, ','),
            [r#"By=a;URI="x;y";DNS=d"#, "Hash=h"]
        );
        assert_eq!(unquote(r#""a \"b\"""#), r#"a "b""#);
        assert_eq!(common_name("CN=web,OU=x,O=y").as_deref(), Some("web"));
        assert_eq!(common_name("O=y"), None);
    }
}
