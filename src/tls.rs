//! TLS termination via `rustls` + `tokio-rustls`.
//!
//! axum 0.7 has no built-in TLS, so we run a small accept loop: take a TCP connection,
//! complete the rustls handshake, then hand the encrypted stream to hyper, serving the same
//! axum [`Router`] the plaintext path uses. Certificates come either from PEM files
//! ([`load_server_config`]) or from ACME (which writes those same files; see [`crate::acme`]).

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tower::{Service, ServiceExt};
use tracing::{debug, info, warn};

/// Install a process-wide default crypto provider (ring). Idempotent and best-effort: if a
/// provider is already installed (e.g. by the JWKS HTTP client) this is a no-op.
///
/// `ring` is the only provider linked (see the rustls entry in Cargo.toml), so rustls would
/// resolve it from crate features anyway. Installing it explicitly keeps that independent of
/// the dependency graph: a future dep that re-enables `rustls/aws_lc_rs` would otherwise make
/// every feature-based `CryptoProvider` lookup ambiguous — and those lookups panic.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a rustls [`ServerConfig`] from a PEM certificate chain and private key. Uses an
/// explicit ring provider so it doesn't depend on which provider happens to be the process
/// default. Advertises HTTP/1.1 via ALPN (the proxy speaks HTTP/1.1 upstream).
pub fn load_server_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("selecting TLS protocol versions")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building rustls ServerConfig (does the key match the certificate?)")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("opening certificate file {path}"))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates from {path}"))?;
    anyhow::ensure!(!certs.is_empty(), "no certificates found in {path}");
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("opening private key file {path}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing private key from {path}"))?
        .with_context(|| format!("no private key found in {path}"))
}

/// Serve `app` over TLS on `listener` until `shutdown` flips true. Each connection is
/// handshaked and served on its own task, so a slow handshake can't block new accepts and a
/// graceful shutdown stops accepting while letting the listener drop.
pub async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(config);
    // `into_make_service_with_connect_info` injects `ConnectInfo(peer)` per connection, which
    // the proxy handler relies on for client-IP resolution.
    let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();

    info!(listen = %listener.local_addr().map(|a| a.to_string()).unwrap_or_default(), "TLS listener up");

    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
                continue;
            }
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => { warn!(error = %e, "TLS accept error"); continue; }
            },
        };

        let acceptor = acceptor.clone();
        // Connection-scoped tower service carrying this peer's ConnectInfo.
        let tower_service = unwrap_infallible(make_service.call(peer).await);

        tokio::spawn(async move {
            // Bound the handshake so a client that never completes it can't pin a task/socket
            // indefinitely (this runs before any auth/rate-limit checks).
            let tls_stream = match tokio::time::timeout(
                Duration::from_secs(10),
                acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    debug!(error = %e, %peer, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    debug!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
                tower_service.clone().oneshot(request)
            });
            if let Err(e) = ConnBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, hyper_service)
                .await
            {
                debug!(error = %e, %peer, "error serving TLS connection");
            }
        });
    }
    Ok(())
}

/// The ACME HTTP-01 challenge prefix. The redirect listener answers `404` here instead of
/// redirecting: a CA validating a challenge must read the token over plain HTTP, and bouncing it
/// to a port whose certificate is the very thing being issued would deadlock issuance. Nothing on
/// this path is served by the redirect listener itself — `crate::acme` binds `:80` for the
/// duration of an order and the redirect listener starts only after it has released the port.
const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Decide the `Location` for an HTTP request that should be served over HTTPS.
///
/// Returns `None` when the request must not be redirected — an absent, malformed, or non-allowed
/// `Host`. That case matters: `Host` is attacker-controlled, so reflecting it unchecked turns
/// this listener into an open redirect that borrows the site's name to send visitors elsewhere.
/// A security proxy must not ship the very hole it exists to close, so a host is only reflected
/// after it passes a syntactic check and, when `allowed` is non-empty, an allow-list check.
///
/// `tls_port` is appended when it is not 443, so a proxy on `:8443` redirects to `:8443` rather
/// than to a port nothing is listening on.
pub fn redirect_location(
    host_header: Option<&str>,
    path_and_query: &str,
    tls_port: u16,
    allowed: &[String],
) -> Option<String> {
    let host = host_header?;
    let bare = split_authority(host)?;
    if !allowed.is_empty() && !allowed.iter().any(|a| a.eq_ignore_ascii_case(bare)) {
        return None;
    }
    Some(if tls_port == 443 {
        format!("https://{bare}{path_and_query}")
    } else {
        format!("https://{bare}:{tls_port}{path_and_query}")
    })
}

/// Split a `Host` header into its host part, rejecting anything that is not a bare authority.
///
/// The whole header is validated, not just the part before the first colon. Taking
/// `host.split(':').next()` alone would quietly *repair* a malformed authority instead of
/// refusing it: `attacker.example:443@victim.example` would reduce to `attacker.example` and
/// produce a redirect, when a header that is not a valid authority has to be a `400`. A port is
/// only stripped once the remainder is confirmed to be digits, so userinfo, a second colon, or
/// any other junk fails the whole header rather than one component of it.
fn split_authority(host: &str) -> Option<&str> {
    // `None` = no port at all; `Some(p)` = a colon was present and `p` is everything after it,
    // which must then be a non-empty run of digits. Collapsing those two cases is what let
    // `host.example:` (a colon with nothing after it) through.
    let (bare, port) = match host.rfind(']') {
        // IPv6 literal: everything through the closing bracket is the host, and only `:<port>`
        // may follow it — any other trailing text is not an authority.
        Some(close) => {
            let rest = &host[close + 1..];
            match rest.strip_prefix(':') {
                Some(p) => (&host[..=close], Some(p)),
                None if rest.is_empty() => (&host[..=close], None),
                None => return None,
            }
        }
        None => match host.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (host, None),
        },
    };
    if let Some(digits) = port {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    is_valid_host(bare).then_some(bare)
}

/// Accept only what can appear in an authority: hostname characters, or a bracketed IPv6 literal.
/// This is deliberately strict — it is the gate that keeps a header like
/// `Host: evil.example/@` or one carrying CR/LF out of a `Location` we sign our name to.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return !inner.is_empty() && inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    // No leading/trailing dot or hyphen, and nothing outside the LDH set.
    !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// The redirect listener's router: one catch-all that answers every method and path.
fn redirect_router(tls_port: u16, status: StatusCode, allowed: Vec<String>) -> Router {
    let allowed = Arc::new(allowed);
    Router::new().fallback(move |req: Request<axum::body::Body>| {
        let allowed = Arc::clone(&allowed);
        async move {
            let path_and_query = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");

            if path_and_query.starts_with(ACME_CHALLENGE_PREFIX) {
                return (StatusCode::NOT_FOUND, "not found\n").into_response();
            }

            let host = req
                .headers()
                .get(axum::http::header::HOST)
                .and_then(|h| h.to_str().ok());

            match redirect_location(host, path_and_query, tls_port, &allowed) {
                Some(location) => match HeaderValue::from_str(&location) {
                    Ok(value) => (status, [(axum::http::header::LOCATION, value)]).into_response(),
                    Err(_) => (StatusCode::BAD_REQUEST, "bad host\n").into_response(),
                },
                None => (
                    StatusCode::BAD_REQUEST,
                    "this port serves only an HTTPS redirect; send a valid Host header\n",
                )
                    .into_response(),
            }
        }
    })
}

/// Validate a configured `tls.redirect_status`.
///
/// Called from startup *before* the plaintext listener binds, because the only other check used
/// to run inside the spawned serving task: a `redirect_status = 200` failed there, the task
/// logged a warning and ended, and the proxy carried on serving HTTPS with nothing on the
/// redirect port — so a typo turned into "connection refused" for every bare-hostname visitor
/// rather than a refusal to start. [`serve_redirect`] still calls it as a guard.
pub fn parse_redirect_status(status: u16) -> Result<StatusCode> {
    let parsed = StatusCode::from_u16(status)
        .with_context(|| format!("invalid tls.redirect_status {status}"))?;
    // NOT `is_redirection()`, which is true for the whole 3xx class and so accepts codes that do
    // not navigate: `304 Not Modified` is a cache validator, `305`/`306` are deprecated, and
    // `300 Multiple Choices` needs a body to choose from. A listener answering `304` with a
    // `Location` leaves the client sitting on plaintext — the exact failure this feature exists
    // to prevent, arrived at through a config value we accepted.
    anyhow::ensure!(
        matches!(status, 301 | 302 | 303 | 307 | 308),
        "tls.redirect_status must be 301, 302, 303, 307 or 308 (got {parsed}); \
         308 preserves the method and body, 301 is the older browser-facing convention"
    );
    Ok(parsed)
}

/// Serve plain-HTTP redirects to HTTPS on `listener` until `shutdown` flips.
///
/// This exists because the common failure is not "the operator refused TLS" — it is a user typing
/// a bare hostname, the browser trying `:80` first, and the request either failing or being
/// answered in plaintext by the app. Terminating TLS only helps if plaintext traffic actually
/// arrives at it.
///
/// `status` should be 308 to preserve the method and body of a non-GET request, or 301 for the
/// classic browser-facing behaviour; [`crate::config::TlsCfg`] documents the choice.
pub async fn serve_redirect(
    listener: TcpListener,
    tls_port: u16,
    status: u16,
    allowed: Vec<String>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let status = parse_redirect_status(status)?;

    info!(
        listen = %listener.local_addr().map(|a| a.to_string()).unwrap_or_default(),
        to_port = tls_port,
        %status,
        "HTTP→HTTPS redirect listener up"
    );

    axum::serve(
        listener,
        redirect_router(tls_port, status, allowed).into_make_service(),
    )
    .with_graceful_shutdown(async move {
        let mut shutdown = shutdown;
        while shutdown.changed().await.is_ok() {
            if *shutdown.borrow() {
                break;
            }
        }
    })
    .await
    .context("HTTP→HTTPS redirect server error")
}

fn unwrap_infallible<T>(result: Result<T, std::convert::Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(never) => match never {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_server_config_errors_on_missing_files() {
        assert!(load_server_config("/no/such/cert.pem", "/no/such/key.pem").is_err());
    }

    fn loc(host: Option<&str>, pq: &str, port: u16) -> Option<String> {
        redirect_location(host, pq, port, &[])
    }

    #[test]
    fn redirects_preserving_path_and_query() {
        assert_eq!(
            loc(Some("app.example.com"), "/a/b?x=1&y=2", 443).as_deref(),
            Some("https://app.example.com/a/b?x=1&y=2")
        );
    }

    #[test]
    fn rewrites_to_the_tls_port_when_it_is_not_443() {
        // The client connected to :80; the certificate is served on :8443, so sending them back
        // to the default port would point them at nothing.
        assert_eq!(
            loc(Some("localhost:80"), "/", 8443).as_deref(),
            Some("https://localhost:8443/")
        );
    }

    #[test]
    fn strips_the_plaintext_port_from_the_host_header() {
        assert_eq!(
            loc(Some("app.example.com:80"), "/", 443).as_deref(),
            Some("https://app.example.com/")
        );
    }

    #[test]
    fn keeps_ipv6_literals_bracketed() {
        assert_eq!(
            loc(Some("[::1]:80"), "/health", 8443).as_deref(),
            Some("https://[::1]:8443/health")
        );
        assert_eq!(loc(Some("[not-an-ip]"), "/", 443), None);
    }

    #[test]
    fn refuses_a_missing_or_malformed_host() {
        // Each of these would otherwise end up verbatim in a `Location` header sent under this
        // site's name — the open-redirect / header-injection case this gate exists for.
        assert_eq!(loc(None, "/", 443), None);
        assert_eq!(loc(Some(""), "/", 443), None);
        assert_eq!(loc(Some("evil.example/@good.example"), "/", 443), None);
        assert_eq!(loc(Some("host\r\nX-Injected: 1"), "/", 443), None);
        assert_eq!(loc(Some("has space"), "/", 443), None);
        assert_eq!(loc(Some("user@evil.example"), "/", 443), None);
        // The whole authority is validated, not just the part before the first colon. Splitting
        // on ':' alone would reduce this to "attacker.example" and redirect, silently repairing
        // a malformed header instead of refusing it — and parsing a Host differently from the
        // hop in front of us is how host-confusion bugs start.
        assert_eq!(
            loc(Some("attacker.example:443@victim.example"), "/", 443),
            None
        );
        assert_eq!(loc(Some("host.example:80:81"), "/", 443), None);
        assert_eq!(loc(Some("host.example:"), "/", 443), None);
        assert_eq!(loc(Some("host.example:notaport"), "/", 443), None);
        assert_eq!(loc(Some("[::1]:junk"), "/", 443), None);
        assert_eq!(loc(Some(".leading-dot"), "/", 443), None);
        assert_eq!(loc(Some(&"a".repeat(254)), "/", 443), None);
    }

    #[test]
    fn allow_list_pins_the_redirect_target() {
        let allowed = vec!["app.example.com".to_string()];
        assert!(redirect_location(Some("app.example.com"), "/", 443, &allowed).is_some());
        // Syntactically fine, but not a name we serve — so we do not lend our domain to it.
        assert_eq!(
            redirect_location(Some("attacker.example"), "/", 443, &allowed),
            None
        );
        // Host matching is case-insensitive, per RFC 3986.
        assert!(redirect_location(Some("APP.Example.com:80"), "/", 443, &allowed).is_some());
    }

    #[tokio::test]
    async fn redirect_router_answers_end_to_end() {
        use axum::body::Body;
        use tower::ServiceExt;

        let app = redirect_router(8443, StatusCode::PERMANENT_REDIRECT, vec![]);

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/submit?a=1")
                    .header("host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // 308 rather than 301/302 so the POST is replayed as a POST over TLS.
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            res.headers().get("location").unwrap(),
            "https://localhost:8443/submit?a=1"
        );

        // The ACME challenge path must not be redirected: HTTP-01 validation reads it in
        // plaintext, and bouncing it to the port whose certificate is being issued would
        // deadlock the order.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/acme-challenge/tok")
                    .header("host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.headers().get("location").is_none());

        // No Host at all (HTTP/1.0) gets a 400, not a redirect to nowhere.
        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn redirect_status_accepts_only_navigational_redirects() {
        for ok in [301, 302, 303, 307, 308] {
            assert!(parse_redirect_status(ok).is_ok(), "{ok} should be accepted");
        }
        // Startup calls this before binding, so these must be errors, not a task that dies.
        for bad in [200, 404, 0] {
            assert!(
                parse_redirect_status(bad).is_err(),
                "{bad} should be rejected"
            );
        }
        // 3xx, but not navigation: 304 is a cache validator, 305/306 are deprecated, and 300
        // needs a body to choose from. Answering any of them with a `Location` leaves the client
        // on plaintext, so `is_redirection()` is the wrong test.
        for not_navigational in [300, 304, 305, 306] {
            assert!(
                parse_redirect_status(not_navigational).is_err(),
                "{not_navigational} is 3xx but does not navigate; it must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn serve_redirect_rejects_a_non_3xx_status() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let (_tx, rx) = watch::channel(false);
        // A typo'd `redirect_status = 200` must fail loudly at startup rather than answering
        // every plaintext request with an empty 200 that looks like the app.
        assert!(serve_redirect(listener, 443, 200, vec![], rx)
            .await
            .is_err());
    }
}
