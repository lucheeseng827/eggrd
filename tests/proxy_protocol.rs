//! `server.proxy_protocol` through the real accept loop and pipeline: a header from a trusted L4
//! balancer names the client for rate limits, access rules, `X-Forwarded-For` and the logs — on
//! plain HTTP and ahead of a TLS handshake — while a header from anyone else, or one that does
//! not parse, closes the connection, and a connection without one is served as it is.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderMap;
use axum::Router;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

mod common;
use common::{uri, Ca, Dir};

use edgeguard::config::Config;
use edgeguard::metrics::Metrics;
use edgeguard::proxy_protocol::ProxyProtocol;
use edgeguard::serve::{serve, ServeOpts};
use edgeguard::{build_router, build_state};

const V2_SIG: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

/// Answers with the `X-Forwarded-For` the edge sent, and the forwarded client certificate.
async fn upstream() -> SocketAddr {
    let app = Router::new().fallback(|headers: HeaderMap| async move {
        let get = |name: &str| {
            headers
                .get(name)
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_else(|| "-".into())
        };
        format!(
            "xff={} xfcc={}",
            get("x-forwarded-for"),
            get("x-forwarded-client-cert")
        )
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn cfg(up: SocketAddr, trusted: &str) -> Config {
    let mut cfg = Config::default();
    cfg.server.upstream = format!("http://{up}");
    // Long, so a refused connection is told apart from one left waiting for a request.
    cfg.server.header_read_timeout = "10s".into();
    cfg.server.proxy_protocol = true;
    cfg.server.proxy_protocol_trusted = vec![trusted.into()];
    cfg.ratelimit.enabled = false;
    cfg
}

struct Edge {
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    _stop: watch::Sender<bool>,
}

/// The pipeline on `serve`, its listener registered as `public` the way `main` does it.
async fn edge(cfg: Config, tls: Option<Arc<rustls::ServerConfig>>) -> Edge {
    let opts = ServeOpts::from_cfg(&cfg.server).unwrap();
    let state = build_state(Arc::new(cfg)).unwrap();
    let metrics = Arc::clone(&state.metrics);
    let opts = opts.with_stats(metrics.listener_stats("public"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(serve(listener, tls, build_router(state), opts, rx));
    Edge {
        addr,
        metrics,
        _stop: stop,
    }
}

fn v1(client: &str) -> Vec<u8> {
    let (ip, port) = client.rsplit_once(':').unwrap();
    let proto = if ip.contains(':') { "TCP6" } else { "TCP4" };
    let ip = ip.trim_start_matches('[').trim_end_matches(']');
    let dst = if proto == "TCP4" { "10.0.0.1" } else { "::1" };
    format!("PROXY {proto} {ip} {dst} {port} 443\r\n").into_bytes()
}

/// A v2 `PROXY` over AF_INET for `client`, with an AWS VPC endpoint TLV after the addresses.
fn v2(client: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(client) = client else {
        panic!("v4 only")
    };
    let mut addrs = client.ip().octets().to_vec();
    addrs.extend_from_slice(&[10, 0, 0, 1]);
    addrs.extend_from_slice(&client.port().to_be_bytes());
    addrs.extend_from_slice(&443u16.to_be_bytes());
    addrs.extend_from_slice(&[0xea, 0x00, 0x05, 0x01, b'v', b'p', b'c', b'e']);
    let mut h = V2_SIG.to_vec();
    h.extend_from_slice(&[0x21, 0x11]);
    h.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
    h.extend_from_slice(&addrs);
    h
}

/// A v2 `LOCAL`: the balancer's own health check.
fn v2_local() -> Vec<u8> {
    let mut h = V2_SIG.to_vec();
    h.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    h
}

/// Whether the edge closes a connection that starts with `preamble` and a request, all in one
/// write, at once and without a byte of reply: refused, not served or left waiting.
async fn closed(addr: SocketAddr, preamble: &[u8]) -> bool {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut bytes = preamble.to_vec();
    bytes.extend_from_slice(b"GET /orders HTTP/1.1\r\nHost: edge\r\n\r\n");
    let _ = s.write_all(&bytes).await;
    let mut out = Vec::new();
    match tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await {
        // EOF, or a reset: either way, nothing may have come back.
        Ok(_) => out.is_empty(),
        Err(_) => false,
    }
}

/// One `GET` on a fresh connection that starts with `preamble`, as raw HTTP/1.1. `None` when the
/// edge closes the connection instead of answering.
async fn get_after(addr: SocketAddr, preamble: &[u8], extra: &str) -> Option<(u16, String)> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(preamble).await.unwrap();
    request(&mut s, extra).await
}

async fn request<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    extra: &str,
) -> Option<(u16, String)> {
    let req = format!("GET /orders HTTP/1.1\r\nHost: edge\r\n{extra}Connection: close\r\n\r\n");
    // The edge may already have closed: a refused connection fails the write or the read.
    if s.write_all(req.as_bytes()).await.is_err() {
        return None;
    }
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
        .await
        .expect("the edge answered or closed");
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text.get(9..12)?.parse().ok()?;
    let body = text.split_once("\r\n\r\n")?.1.to_string();
    Some((status, body))
}

fn counter(metrics: &Metrics, result: &str) -> u64 {
    let line =
        format!("edgeguard_proxy_protocol_total{{listener=\"public\",result=\"{result}\"}} ");
    metrics
        .render()
        .lines()
        .find_map(|l| l.strip_prefix(&line)?.parse().ok())
        .unwrap_or_else(|| panic!("no {line}"))
}

#[tokio::test]
async fn a_trusted_balancers_v1_and_v2_headers_name_the_client() {
    let up = upstream().await;
    let edge = edge(cfg(up, "127.0.0.1"), None).await;
    for (preamble, client) in [
        (v1("203.0.113.7:51234"), "203.0.113.7"),
        (v1("[2001:db8::7]:51234"), "2001:db8::7"),
        (v2("198.51.100.9:4000".parse().unwrap()), "198.51.100.9"),
    ] {
        let (status, body) = get_after(edge.addr, &preamble, "").await.expect("served");
        assert_eq!(status, 200, "{body}");
        assert!(body.starts_with(&format!("xff={client} ")), "{body}");
    }
    assert_eq!(counter(&edge.metrics, "proxied"), 3);
}

#[tokio::test]
async fn the_proxied_address_is_the_one_access_rules_and_rate_limits_see() {
    let up = upstream().await;
    let mut c = cfg(up, "127.0.0.1");
    c.access.deny = vec!["203.0.113.0/24".into()];
    let edge = edge(c, None).await;
    let blocked = get_after(edge.addr, &v1("203.0.113.7:1"), "")
        .await
        .unwrap();
    assert_eq!(
        blocked.0, 403,
        "denied by its own address, not the balancer's"
    );
    let other = get_after(edge.addr, &v1("198.51.100.9:1"), "")
        .await
        .unwrap();
    assert_eq!(other.0, 200);

    // One client's burst is its own: another behind the same balancer is not limited with it.
    let mut c = cfg(up, "127.0.0.1");
    c.ratelimit.enabled = true;
    c.ratelimit.rate = "1/min".into();
    c.ratelimit.burst = 1;
    let edge = self::edge(c, None).await;
    assert_eq!(
        get_after(edge.addr, &v1("203.0.113.7:1"), "")
            .await
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        get_after(edge.addr, &v1("203.0.113.7:2"), "")
            .await
            .unwrap()
            .0,
        429
    );
    assert_eq!(
        get_after(edge.addr, &v1("198.51.100.9:1"), "")
            .await
            .unwrap()
            .0,
        200
    );
}

#[tokio::test]
async fn a_header_from_an_untrusted_peer_closes_the_connection_and_a_plain_request_is_served() {
    let up = upstream().await;
    let edge = edge(cfg(up, "10.0.0.0/8"), None).await;
    assert!(
        closed(edge.addr, &v1("203.0.113.7:1")).await,
        "a client choosing its own address"
    );
    assert!(closed(edge.addr, &v2("203.0.113.7:1".parse().unwrap())).await);
    assert_eq!(counter(&edge.metrics, "untrusted"), 2);

    // A direct caller (a health check, a pod in the cluster) is served as itself.
    let (status, body) = get_after(edge.addr, b"", "").await.unwrap();
    assert_eq!((status, body.as_str()), (200, "xff=127.0.0.1 xfcc=-"));
    assert_eq!(counter(&edge.metrics, "direct"), 1);
    assert_eq!(counter(&edge.metrics, "proxied"), 0);
}

#[tokio::test]
async fn a_trusted_peer_without_a_header_and_a_health_check_are_served_as_the_balancer() {
    let up = upstream().await;
    let edge = edge(cfg(up, "127.0.0.0/8"), None).await;
    for preamble in [&b""[..], &v2_local(), b"PROXY UNKNOWN\r\n"] {
        let (status, body) = get_after(edge.addr, preamble, "").await.expect("served");
        assert_eq!(
            (status, body.as_str()),
            (200, "xff=127.0.0.1 xfcc=-"),
            "{preamble:?}"
        );
    }
    assert_eq!(counter(&edge.metrics, "missing"), 1);
    assert_eq!(counter(&edge.metrics, "local"), 2);
}

#[tokio::test]
async fn an_invalid_header_or_a_silent_connection_is_closed() {
    let up = upstream().await;
    let edge = self::edge(cfg(up, "127.0.0.1"), None).await;
    for bad in [
        &b"PROXY TCP4 2001:db8::7 10.0.0.1 1 2\r\n"[..],
        b"PROXY HTTP/1.1\r\n",
        &[V2_SIG, &[0x11, 0x11, 0, 0][..]].concat(),
    ] {
        assert!(closed(edge.addr, bad).await, "{bad:?}");
    }
    assert_eq!(counter(&edge.metrics, "invalid"), 3);

    let mut c = cfg(up, "127.0.0.1");
    c.server.header_read_timeout = "300ms".into();
    let edge = self::edge(c, None).await;
    let mut silent = TcpStream::connect(edge.addr).await.unwrap();
    let mut buf = [0u8; 16];
    let closed = tokio::time::timeout(Duration::from_secs(3), silent.read(&mut buf)).await;
    assert!(
        matches!(closed, Ok(Ok(0) | Err(_))),
        "closed after header_read_timeout"
    );
    assert_eq!(counter(&edge.metrics, "timeout"), 1);
}

/// The TLS listener from a throwaway CA, and a client that trusts it.
fn tls(dir: &Dir) -> (Arc<rustls::ServerConfig>, tokio_rustls::TlsConnector) {
    edgeguard::tls::init_crypto();
    let ca = Ca::new("edge CA");
    let (cert, key) = dir.pair("edge", &ca.server(&["localhost"]));
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    let server = edgeguard::tls::server_config(store).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca.pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    (server, tokio_rustls::TlsConnector::from(Arc::new(client)))
}

#[tokio::test]
async fn on_a_tls_listener_the_header_comes_before_the_handshake() {
    let dir = Dir::new();
    let (server, connector) = tls(&dir);
    let up = upstream().await;
    let edge = edge(cfg(up, "127.0.0.1"), Some(server)).await;
    let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
    tcp.write_all(&v2("203.0.113.7:51234".parse().unwrap()))
        .await
        .unwrap();
    let mut s = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("the handshake follows the header");
    let (status, body) = request(&mut s, "").await.unwrap();
    assert_eq!((status, body.as_str()), (200, "xff=203.0.113.7 xfcc=-"));

    // And a direct TLS client, with no header, still gets its handshake.
    let tcp = TcpStream::connect(edge.addr).await.unwrap();
    let mut s = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("a ClientHello is not a header");
    assert_eq!(request(&mut s, "").await.unwrap().0, 200);
    assert_eq!(counter(&edge.metrics, "proxied"), 1);
    assert_eq!(counter(&edge.metrics, "missing"), 1);
}

#[tokio::test]
async fn http2_with_prior_knowledge_follows_a_header() {
    let up = upstream().await;
    let edge = edge(cfg(up, "127.0.0.1"), None).await;
    let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
    tcp.write_all(&v1("203.0.113.7:1")).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tcp),
    )
    .await
    .expect("h2 after the header");
    tokio::spawn(conn);
    let req = axum::http::Request::get("http://edge/orders")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = send.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(axum::body::Body::new(resp.into_body()), 1 << 16)
        .await
        .unwrap();
    assert!(body.starts_with(b"xff=203.0.113.7 "), "{body:?}");
}

#[tokio::test]
async fn a_certificate_header_is_trusted_by_the_hop_that_wrote_it_not_the_client_it_names() {
    let up = upstream().await;
    let ca = Ca::new("partner CA");
    let pem = ca
        .client_with(vec![uri("spiffe://prod/ns/web")], "web", 7)
        .cert
        .replace('\n', " ");
    let header = format!("X-Client-Cert: {pem}\r\n");
    let with_header_trusted_from = |trusted: &str| {
        let mut c = cfg(up, "127.0.0.1");
        c.auth.mode = "mtls".into();
        c.tls.client_auth.forward_client_cert = "xfcc".into();
        c.trusted_client_cert_header.name = "X-Client-Cert".into();
        c.trusted_client_cert_header.trusted_proxies = vec![trusted.into()];
        c
    };
    // An L7 balancer (HAProxy in HTTP mode, say) that writes the header and the PROXY line: the
    // TCP peer is the one trusted for both.
    let edge = edge(with_header_trusted_from("127.0.0.1"), None).await;
    let (status, body) = get_after(edge.addr, &v1("203.0.113.7:1"), &header)
        .await
        .unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("xff=203.0.113.7 xfcc=Hash="), "{body}");

    // The client a PROXY header names is not who wrote the certificate header.
    let edge = self::edge(with_header_trusted_from("203.0.113.0/24"), None).await;
    let refused = get_after(edge.addr, &v1("203.0.113.7:1"), &header)
        .await
        .unwrap();
    assert_eq!(refused.0, 401);
    assert!(edge
        .metrics
        .render()
        .contains("edgeguard_client_cert_header_total{result=\"untrusted_peer\"} 1"));
}

#[tokio::test]
async fn only_listeners_that_read_headers_export_the_series() {
    let up = upstream().await;
    let edge = edge(cfg(up, "127.0.0.1"), None).await;
    // A second listener on the same registry without it, as the admin listener runs.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin = listener.local_addr().unwrap();
    let (_stop, rx) = watch::channel(false);
    let opts = ServeOpts::default().with_stats(edge.metrics.listener_stats("admin"));
    tokio::spawn(serve(listener, None, Router::new(), opts, rx));
    get_after(admin, b"", "").await.unwrap();
    get_after(edge.addr, b"", "").await.unwrap();

    let text = edge.metrics.render();
    assert!(text.contains("# TYPE edgeguard_proxy_protocol_total counter"));
    for result in [
        "proxied",
        "local",
        "missing",
        "direct",
        "untrusted",
        "invalid",
        "timeout",
    ] {
        assert!(
            text.contains(&format!(
                "edgeguard_proxy_protocol_total{{listener=\"public\",result=\"{result}\"}} "
            )),
            "{result}"
        );
    }
    assert!(!text.contains("edgeguard_proxy_protocol_total{listener=\"admin\""));
    assert!(text.contains("edgeguard_connections_open{listener=\"admin\"}"));
}

#[test]
fn settings_that_would_let_a_client_choose_its_address_fail_startup() {
    let mut c = Config::default();
    c.server.proxy_protocol = true;
    let err = format!("{:#}", ServeOpts::from_cfg(&c.server).unwrap_err());
    assert!(err.contains("proxy_protocol_trusted is required"), "{err}");
    c.server.proxy_protocol_trusted = vec!["0.0.0.0/0".into()];
    assert!(ServeOpts::from_cfg(&c.server).is_err());
    c.server.proxy_protocol_trusted = vec!["10.0.0.0/8".into()];
    assert!(ServeOpts::from_cfg(&c.server)
        .unwrap()
        .proxy_protocol
        .is_some_and(|pp: Arc<ProxyProtocol>| pp.trusts("10.1.2.3".parse().unwrap())));
}
