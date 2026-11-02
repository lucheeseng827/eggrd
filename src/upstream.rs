//! The connection to the upstream: plain HTTP for `http://`, TLS for `https://`.
//!
//! [`UpstreamConnector`] is the upstream client's connector. It opens the TCP connection with
//! hyper's own [`HttpConnector`] and, for an `https://` upstream, completes a rustls handshake on
//! it with the settings `[upstream_tls]` gives that upstream ([`UpstreamTls`]): the CAs it may be
//! signed by, the client certificate to present, and the name to verify. Settings are chosen by
//! the host and port being dialled, because that is all a connector is told — so they apply per
//! upstream, not per route.
//!
//! The client pools connections, so a handshake happens per connection, not per request. Settings
//! are read at startup; a client certificate replaced on disk is picked up by new connections
//! (see [`UpstreamTls::identities`]), while pooled ones keep the identity they were opened with.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use axum::http::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tower::Service;

use crate::certstore::CertStore;
use crate::config::UpstreamTlsCfg;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// TLS settings for every `https://` upstream, compiled from `[upstream_tls]`.
pub struct UpstreamTls {
    /// For an upstream with no `[[upstream_tls.targets]]` entry.
    default: Profile,
    /// Keyed by the upstream's host (as [`Uri::host`] gives it, lowercased) and port.
    targets: HashMap<(String, u16), Profile>,
    /// Every client certificate in use, once each.
    identities: Vec<Arc<CertStore>>,
}

/// How to reach one upstream over TLS.
struct Profile {
    config: Arc<ClientConfig>,
    /// Overrides the URL's host as the name verified and sent as SNI.
    server_name: Option<ServerName<'static>>,
}

impl std::fmt::Debug for UpstreamTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTls")
            .field("targets", &self.targets.keys().collect::<Vec<_>>())
            .field("identities", &self.identities)
            .finish()
    }
}

impl UpstreamTls {
    /// Load the CA bundles and client certificates `cfg` names. Fails on anything that would
    /// otherwise surface as a `502` on the first request: an unreadable or empty CA bundle, a
    /// certificate without its key, an invalid name, a target that is not an `https://` URL or is
    /// listed twice.
    pub fn from_cfg(cfg: &UpstreamTlsCfg) -> Result<Self> {
        let mut identities: HashMap<(String, String), Arc<CertStore>> = HashMap::new();
        let mut build =
            |ca_path: &str, cert_path: &str, key_path: &str, server_name: &str, used_by: &str| {
                build_profile(
                    ca_path,
                    cert_path,
                    key_path,
                    server_name,
                    used_by,
                    &mut identities,
                )
            };

        let default = build(
            &cfg.ca_path,
            &cfg.cert_path,
            &cfg.key_path,
            &cfg.server_name,
            "upstream",
        )
        .context("[upstream_tls]")?;

        let mut targets = HashMap::new();
        for t in &cfg.targets {
            let key = target_key(&t.target)
                .with_context(|| format!("[[upstream_tls.targets]] target = {:?}", t.target))?;
            let inherit = |own: &str, global: &str| -> String {
                if own.is_empty() { global } else { own }.to_string()
            };
            // A client certificate is a pair: an entry naming either half replaces both.
            let (cert, key_file) = if t.cert_path.is_empty() && t.key_path.is_empty() {
                (cfg.cert_path.clone(), cfg.key_path.clone())
            } else {
                (t.cert_path.clone(), t.key_path.clone())
            };
            let profile = build(
                &inherit(&t.ca_path, &cfg.ca_path),
                &cert,
                &key_file,
                &inherit(&t.server_name, &cfg.server_name),
                &format!("upstream:{}", t.target),
            )
            .with_context(|| format!("[[upstream_tls.targets]] target = {:?}", t.target))?;
            anyhow::ensure!(
                targets.insert(key, profile).is_none(),
                "[[upstream_tls.targets]] lists {:?} more than once (same host and port)",
                t.target
            );
        }

        Ok(UpstreamTls {
            default,
            targets,
            identities: identities.into_values().collect(),
        })
    }

    /// The client certificates in use, so they can be watched and reloaded on change.
    pub fn identities(&self) -> &[Arc<CertStore>] {
        &self.identities
    }

    fn profile(&self, host: &str, port: u16) -> &Profile {
        self.targets
            .get(&(host.to_ascii_lowercase(), port))
            .unwrap_or(&self.default)
    }
}

/// The `(host, port)` an `https://` target is dialled at, in the form the connector looks it up.
pub(crate) fn target_key(target: &str) -> Result<(String, u16)> {
    let uri: Uri = target.parse().context("not a URL")?;
    anyhow::ensure!(
        uri.scheme_str() == Some("https"),
        "must be an https:// URL: TLS settings only apply to https upstreams"
    );
    let host = uri.host().context("no host")?;
    Ok((host.to_ascii_lowercase(), uri.port_u16().unwrap_or(443)))
}

fn build_profile(
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
    server_name: &str,
    used_by: &str,
    identities: &mut HashMap<(String, String), Arc<CertStore>>,
) -> Result<Profile> {
    let roots = crate::outbound::roots(ca_path).context("ca_path")?;
    // The same file pair is the same store process-wide (see `outbound::identity`); this map only
    // lists the ones these settings present.
    let identity = crate::outbound::identity(cert_path, key_path, used_by)?;
    if let Some(identity) = &identity {
        identities
            .entry((cert_path.to_string(), key_path.to_string()))
            .or_insert_with(|| Arc::clone(identity.store()));
    }
    let config = crate::outbound::client_config(roots, identity)?;

    let server_name = if server_name.is_empty() {
        None
    } else {
        Some(
            ServerName::try_from(server_name.to_string())
                .with_context(|| format!("server_name {server_name:?} is not a DNS name or IP"))?,
        )
    };
    Ok(Profile {
        config: Arc::new(config),
        server_name,
    })
}

/// The upstream client's connector: TCP for `http://`, TCP then TLS for `https://`.
#[derive(Clone)]
pub struct UpstreamConnector {
    http: HttpConnector,
    tls: Arc<UpstreamTls>,
    connect_timeout: Option<std::time::Duration>,
    /// Pick the TLS settings of this `(host, port)` rather than of the one dialled. Set only on
    /// the connector a health check uses for another port of an `https://` target, so the check
    /// verifies and presents as requests to that target do.
    tls_as: Option<(String, u16)>,
}

impl UpstreamConnector {
    /// `connect_timeout` bounds connecting (`validation.upstream_connect_timeout`): the TCP
    /// connection, and for `https://` the TLS handshake with it, so a target that accepts and then
    /// never answers the handshake is a connection failure too. `None` leaves it to the request's
    /// own deadline.
    pub fn new(tls: Arc<UpstreamTls>, connect_timeout: Option<std::time::Duration>) -> Self {
        let mut http = HttpConnector::new();
        // It is handed `https://` URIs too; the TLS layer is ours, above it.
        http.enforce_http(false);
        http.set_connect_timeout(connect_timeout);
        UpstreamConnector {
            http,
            tls,
            connect_timeout,
            tls_as: None,
        }
    }

    /// This connector, choosing the TLS settings of `target` (an upstream base URL) whatever port
    /// it dials: `[[upstream_tls.targets]]`'s entry for that target, or `[upstream_tls]`. For a
    /// health check on another port (`health_check.port`), which would otherwise be looked up by
    /// that port and get the defaults. Itself, for a target that is not `https://`.
    pub fn with_tls_of(&self, target: &str) -> UpstreamConnector {
        UpstreamConnector {
            tls_as: target_key(target).ok(),
            ..self.clone()
        }
    }
}

impl Service<Uri> for UpstreamConnector {
    type Response = UpstreamStream;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<UpstreamStream, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mut http = self.http.clone();
        let tls = Arc::clone(&self.tls);
        let connect_timeout = self.connect_timeout;
        let tls_as = self.tls_as.clone();
        Box::pin(async move {
            match uri.scheme_str() {
                Some("http") => Ok(UpstreamStream::Plain(http.call(uri).await?)),
                Some("https") => {
                    let host = uri.host().ok_or("upstream URL has no host")?;
                    let profile = match &tls_as {
                        Some((host, port)) => tls.profile(host, *port),
                        None => tls.profile(host, uri.port_u16().unwrap_or(443)),
                    };
                    let server_name = match &profile.server_name {
                        Some(name) => name.clone(),
                        None => url_server_name(host)?,
                    };
                    let config = Arc::clone(&profile.config);
                    let connect = async {
                        let tcp = http.call(uri).await?.into_inner();
                        let stream = TlsConnector::from(config).connect(server_name, tcp).await?;
                        Ok::<_, BoxError>(stream)
                    };
                    let stream = match connect_timeout {
                        Some(limit) => {
                            tokio::time::timeout(limit, connect).await.map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    format!("no TLS handshake within {limit:?}"),
                                )
                            })??
                        }
                        None => connect.await?,
                    };
                    Ok(UpstreamStream::Tls(Box::new(TokioIo::new(stream))))
                }
                other => Err(format!("unsupported upstream scheme {other:?}").into()),
            }
        })
    }
}

/// The name to verify for a URL host: a DNS name, or an IP literal (bracketed for IPv6 in a URL).
fn url_server_name(host: &str) -> Result<ServerName<'static>, BoxError> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Ok(ServerName::try_from(bare.to_string())?)
}

/// A connection to the upstream, plain or TLS. The TLS state is boxed: it is over a kilobyte, and
/// would otherwise make every plain connection that size too.
pub enum UpstreamStream {
    Plain(TokioIo<TcpStream>),
    Tls(Box<TokioIo<tokio_rustls::client::TlsStream<TcpStream>>>),
}

impl Connection for UpstreamStream {
    fn connected(&self) -> Connected {
        match self {
            UpstreamStream::Plain(s) => s.connected(),
            UpstreamStream::Tls(s) => s.inner().get_ref().0.connected(),
        }
    }
}

impl hyper::rt::Read for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            UpstreamStream::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            UpstreamStream::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_flush(cx),
            UpstreamStream::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            UpstreamStream::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            UpstreamStream::Plain(s) => s.is_write_vectored(),
            UpstreamStream::Tls(s) => s.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            UpstreamStream::Tls(s) => Pin::new(&mut **s).poll_write_vectored(cx, bufs),
        }
    }
}

/// How one exchange with an upstream ended, as far as the edge waited for it: the
/// `result` label of `edgeguard_upstream_requests_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamResult {
    /// It answered, below `500`.
    Ok,
    /// It answered `5xx`.
    Http5xx,
    /// No connection: refused, unroutable, a name that does not resolve.
    ConnectError,
    /// The TLS handshake failed, or the upstream refused the edge's certificate.
    TlsError,
    /// No answer within `validation.upstream_timeout`.
    Timeout,
    /// The connection was closed or reset before the response was complete.
    Reset,
    /// Anything else.
    Error,
}

impl UpstreamResult {
    /// Every result, in label order.
    pub const ALL: [UpstreamResult; 7] = [
        UpstreamResult::Ok,
        UpstreamResult::Http5xx,
        UpstreamResult::ConnectError,
        UpstreamResult::TlsError,
        UpstreamResult::Timeout,
        UpstreamResult::Reset,
        UpstreamResult::Error,
    ];

    pub fn label(self) -> &'static str {
        match self {
            UpstreamResult::Ok => "ok",
            UpstreamResult::Http5xx => "http_5xx",
            UpstreamResult::ConnectError => "connect_error",
            UpstreamResult::TlsError => "tls_error",
            UpstreamResult::Timeout => "timeout",
            UpstreamResult::Reset => "reset",
            UpstreamResult::Error => "error",
        }
    }

    /// The result of an answer with `status`.
    pub fn from_status(status: u16) -> UpstreamResult {
        if status >= 500 {
            UpstreamResult::Http5xx
        } else {
            UpstreamResult::Ok
        }
    }

    /// The result of a failed exchange, from the error the client or the response body gave.
    ///
    /// TLS is looked for first and anywhere in the chain: a handshake failure is also a connect
    /// failure to hyper, and an alert the server sends after the client's half of a TLS 1.3
    /// handshake (a refused client certificate) only surfaces when the response is read. rustls's
    /// error sits inside an `io::Error`, which `source()` steps over, so each one is opened.
    pub fn classify(e: &(dyn std::error::Error + 'static)) -> UpstreamResult {
        use std::io::ErrorKind;
        let (mut connect, mut reset) = (false, false);
        let mut cur = Some(e);
        while let Some(err) = cur {
            if err.is::<rustls::Error>() {
                return UpstreamResult::TlsError;
            }
            if let Some(io) = err.downcast_ref::<io::Error>() {
                if io
                    .get_ref()
                    .is_some_and(|inner| inner.is::<rustls::Error>())
                {
                    return UpstreamResult::TlsError;
                }
                reset |= matches!(
                    io.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                        | ErrorKind::UnexpectedEof
                );
            }
            if let Some(client) = err.downcast_ref::<hyper_util::client::legacy::Error>() {
                connect |= client.is_connect();
            }
            if let Some(hyper) = err.downcast_ref::<hyper::Error>() {
                reset |= hyper.is_incomplete_message() || hyper.is_canceled();
            }
            cur = err.source();
        }
        if connect {
            UpstreamResult::ConnectError
        } else if reset {
            UpstreamResult::Reset
        } else {
            UpstreamResult::Error
        }
    }
}

/// An error and its causes, outermost first: `client error (Connect): invalid peer certificate:
/// UnknownIssuer` rather than hyper's bare `client error (Connect)`.
pub fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        // Some layers repeat their cause in their own message; don't print it twice.
        if !out.ends_with(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpstreamTlsTarget;

    #[test]
    fn a_failure_is_classified_by_its_cause() {
        // rustls's error inside the `io::Error` tokio-rustls returns, which `source()` skips.
        let tls = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        assert_eq!(UpstreamResult::classify(&tls), UpstreamResult::TlsError);
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert_eq!(
                UpstreamResult::classify(&io::Error::from(kind)),
                UpstreamResult::Reset
            );
        }
        assert_eq!(
            UpstreamResult::classify(&io::Error::other("anything else")),
            UpstreamResult::Error
        );
        assert_eq!(UpstreamResult::from_status(200), UpstreamResult::Ok);
        assert_eq!(UpstreamResult::from_status(499), UpstreamResult::Ok);
        assert_eq!(UpstreamResult::from_status(500), UpstreamResult::Http5xx);
        assert_eq!(UpstreamResult::from_status(504), UpstreamResult::Http5xx);
    }

    /// A self-signed pair in a fresh directory; returns (cert path, key path).
    fn pair() -> (String, String) {
        let dir = std::env::temp_dir().join(format!(
            "eg-upstream-unit-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("c.pem").to_string_lossy().into_owned();
        let key = dir.join("k.pem").to_string_lossy().into_owned();
        crate::selfsigned::write_to(&["edge.example".to_string()], 30, &cert, &key).unwrap();
        (cert, key)
    }

    fn target(url: &str) -> UpstreamTlsTarget {
        UpstreamTlsTarget {
            target: url.into(),
            ..Default::default()
        }
    }

    fn err(cfg: &UpstreamTlsCfg) -> String {
        match UpstreamTls::from_cfg(cfg) {
            Ok(_) => panic!("{cfg:?} should be refused"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn the_defaults_load_with_no_files() {
        let tls = UpstreamTls::from_cfg(&UpstreamTlsCfg::default()).unwrap();
        assert!(tls.identities().is_empty());
    }

    #[test]
    fn targets_are_looked_up_by_host_and_port_and_fall_back_to_the_defaults() {
        let tls = UpstreamTls::from_cfg(&UpstreamTlsCfg {
            targets: vec![
                UpstreamTlsTarget {
                    server_name: "api.internal".into(),
                    ..target("https://API.Example.com/base")
                },
                target("https://[::1]:8443"),
            ],
            ..Default::default()
        })
        .unwrap();
        let api = tls.profile("api.example.com", 443);
        assert_eq!(
            api.server_name,
            Some(ServerName::try_from("api.internal").unwrap())
        );
        assert!(!Arc::ptr_eq(&api.config, &tls.default.config));
        assert!(!Arc::ptr_eq(
            &tls.profile("[::1]", 8443).config,
            &tls.default.config
        ));
        // Another port, or another host, is not that target.
        assert!(Arc::ptr_eq(
            &tls.profile("api.example.com", 8443).config,
            &tls.default.config
        ));
        assert!(Arc::ptr_eq(
            &tls.profile("other.example.com", 443).config,
            &tls.default.config
        ));
    }

    #[test]
    fn a_target_must_be_an_https_url_listed_once() {
        let e = err(&UpstreamTlsCfg {
            targets: vec![target("http://api.example.com")],
            ..Default::default()
        });
        assert!(e.contains("https://"), "{e}");
        // `:443` is the default port, so these name the same upstream.
        let e = err(&UpstreamTlsCfg {
            targets: vec![
                target("https://api.example.com"),
                target("https://api.example.com:443/v2"),
            ],
            ..Default::default()
        });
        assert!(e.contains("more than once"), "{e}");
    }

    #[test]
    fn a_client_certificate_needs_its_key_and_a_bad_file_is_refused_at_load() {
        let (cert, _) = pair();
        let e = err(&UpstreamTlsCfg {
            cert_path: cert,
            ..Default::default()
        });
        assert!(e.contains("set together"), "{e}");
        let e = err(&UpstreamTlsCfg {
            ca_path: "/no/such/ca.pem".into(),
            ..Default::default()
        });
        assert!(e.contains("ca_path"), "{e}");
        let e = err(&UpstreamTlsCfg {
            server_name: "not a name".into(),
            ..Default::default()
        });
        assert!(e.contains("server_name"), "{e}");
    }

    #[test]
    fn a_client_certificate_shared_by_targets_is_loaded_once() {
        let (cert, key) = pair();
        let tls = UpstreamTls::from_cfg(&UpstreamTlsCfg {
            cert_path: cert,
            key_path: key,
            targets: vec![target("https://a.example"), target("https://b.example")],
            ..Default::default()
        })
        .unwrap();
        // One file pair, one store: one watcher, one reload.
        assert_eq!(tls.identities().len(), 1);
    }

    #[test]
    fn url_hosts_become_names_to_verify() {
        assert_eq!(
            url_server_name("app.example.com").unwrap(),
            ServerName::try_from("app.example.com").unwrap()
        );
        assert!(matches!(
            url_server_name("[::1]").unwrap(),
            ServerName::IpAddress(_)
        ));
        assert!(matches!(
            url_server_name("10.0.0.7").unwrap(),
            ServerName::IpAddress(_)
        ));
    }

    #[test]
    fn error_chain_shows_the_cause_once() {
        #[derive(Debug)]
        struct Outer(io::Error);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("client error (Connect)")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let e = Outer(io::Error::other("invalid peer certificate: UnknownIssuer"));
        assert_eq!(
            error_chain(&e),
            "client error (Connect): invalid peer certificate: UnknownIssuer"
        );
    }
}
