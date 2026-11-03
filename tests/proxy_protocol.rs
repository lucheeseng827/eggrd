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
        .one_line_pem();
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

/// The admin listener as `main` runs it: the admin router, on [`ServeOpts::for_admin`] of the
/// public listener's settings, registered as `admin`.
async fn admin_edge(cfg: Config) -> Edge {
    let opts = ServeOpts::from_cfg(&cfg.server).unwrap().for_admin();
    let state = build_state(Arc::new(cfg)).unwrap();
    let metrics = Arc::clone(&state.metrics);
    let opts = opts.with_stats(metrics.listener_stats("admin"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(serve(
        listener,
        None,
        edgeguard::build_admin_router(state),
        opts,
        rx,
    ));
    Edge {
        addr,
        metrics,
        _stop: stop,
    }
}

/// `GET /__edgeguard/ready` after `preamble`, as an NLB health check sends it.
async fn ready_after(addr: SocketAddr, preamble: &[u8]) -> Option<u16> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut bytes = preamble.to_vec();
    bytes.extend_from_slice(
        b"GET /__edgeguard/ready HTTP/1.1\r\nHost: 10.0.0.1:9090\r\nConnection: close\r\n\r\n",
    );
    s.write_all(&bytes).await.ok()?;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
        .await
        .expect("the edge answered or closed");
    String::from_utf8_lossy(&out).get(9..12)?.parse().ok()
}

/// `edgeguard_proxy_protocol_total{listener="admin",result}` as the registry renders it.
fn admin_counter(metrics: &Metrics, result: &str) -> u64 {
    let line = format!("edgeguard_proxy_protocol_total{{listener=\"admin\",result=\"{result}\"}} ");
    metrics
        .render()
        .lines()
        .find_map(|l| l.strip_prefix(&line)?.parse().ok())
        .unwrap_or_else(|| panic!("no {line}"))
}

#[tokio::test]
async fn the_admin_listener_answers_a_balancers_health_check_that_carries_a_header() {
    // An AWS NLB with proxy protocol v2 on sends a `LOCAL` header on every health-check
    // connection, also to a separate health-check port. Unread, it made `GET /ready` unparseable
    // ("invalid HTTP method parsed") and failed every target.
    let up = upstream().await;
    let edge = admin_edge(cfg(up, "127.0.0.0/8")).await;
    assert_eq!(
        ready_after(edge.addr, &v2_local()).await,
        Some(200),
        "v2 LOCAL"
    );
    assert_eq!(
        ready_after(edge.addr, b"PROXY UNKNOWN\r\n").await,
        Some(200),
        "v1 UNKNOWN"
    );
    assert_eq!(
        ready_after(edge.addr, &v1("203.0.113.7:51234")).await,
        Some(200),
        "v1 TCP4"
    );
    assert_eq!(
        ready_after(edge.addr, &v2("198.51.100.9:4000".parse().unwrap())).await,
        Some(200),
        "v2 PROXY"
    );
    assert_eq!(admin_counter(&edge.metrics, "local"), 2);
    assert_eq!(admin_counter(&edge.metrics, "proxied"), 2);

    // A kubelet probe or a Prometheus scrape from the trusted range sends no header. It is
    // served, and counted `direct`, not `missing`: on the admin port no header is the norm, and
    // `missing` without `proxied` would fire EdgeGuardProxyProtocolMissing.
    assert_eq!(ready_after(edge.addr, b"").await, Some(200), "no header");
    assert_eq!(admin_counter(&edge.metrics, "direct"), 1);
    assert_eq!(admin_counter(&edge.metrics, "missing"), 0);
}

#[tokio::test]
async fn the_admin_listener_refuses_a_header_from_an_untrusted_peer() {
    let up = upstream().await;
    let edge = admin_edge(cfg(up, "10.0.0.0/8")).await;
    for preamble in [
        v2_local(),
        b"PROXY UNKNOWN\r\n".to_vec(),
        v1("203.0.113.7:1"),
    ] {
        assert!(closed(edge.addr, &preamble).await, "{preamble:?}");
    }
    assert_eq!(admin_counter(&edge.metrics, "untrusted"), 3);
    // Without a header, a direct caller is served as before.
    assert_eq!(ready_after(edge.addr, b"").await, Some(200));
    assert_eq!(admin_counter(&edge.metrics, "direct"), 1);
}

#[tokio::test]
async fn without_proxy_protocol_the_admin_listener_reads_no_header() {
    let up = upstream().await;
    let mut c = cfg(up, "127.0.0.1");
    c.server.proxy_protocol = false;
    c.server.proxy_protocol_trusted.clear();
    let edge = admin_edge(c).await;
    assert_eq!(ready_after(edge.addr, b"").await, Some(200));
    assert_ne!(
        ready_after(edge.addr, &v2_local()).await,
        Some(200),
        "a header is a malformed request when proxy_protocol is off"
    );
    assert!(!edge
        .metrics
        .render()
        .contains("edgeguard_proxy_protocol_total{listener=\"admin\""));
}

/// The value of one rendered series, given as its name and labels.
fn tls_counter(metrics: &Metrics, series: &str) -> u64 {
    metrics
        .render()
        .lines()
        .find_map(|l| l.strip_prefix(series)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("no {series}"))
}

#[tokio::test]
async fn a_connection_reset_before_any_byte_counts_as_no_client_hello_with_proxy_protocol() {
    // With PROXY protocol on, the first read is the header's. A reset there (ECONNRESET, nothing
    // read) used to count nowhere, while the same reset without PROXY protocol counted in
    // `no_client_hello`.
    let dir = Dir::new();
    let (server, _) = tls(&dir);
    let up = upstream().await;
    let edge = edge(cfg(up, "127.0.0.1"), Some(server)).await;
    let series = |name: &str| tls_counter(&edge.metrics, name);
    for _ in 0..3 {
        let tcp = TcpStream::connect(edge.addr).await.unwrap();
        // Wait until the edge holds it, so the reset reaches an accepted connection's read.
        for _ in 0..100 {
            if series("edgeguard_connections_open{listener=\"public\"}") == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Deprecated because a non-zero linger blocks the thread on drop; zero never does.
        #[allow(deprecated)]
        let linger = tcp.set_linger(Some(Duration::ZERO));
        linger.unwrap();
        drop(tcp); // SO_LINGER 0: an RST, not a FIN
        for _ in 0..100 {
            if series("edgeguard_connections_open{listener=\"public\"}") == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    assert_eq!(
        series("edgeguard_tls_no_client_hello_total{listener=\"public\"}"),
        3
    );
    assert_eq!(
        series("edgeguard_tls_handshakes_total{listener=\"public\"}"),
        0
    );
    assert_eq!(
        series("edgeguard_tls_handshake_failures_total{listener=\"public\",reason=\"other\"}"),
        0
    );
}

#[tokio::test]
async fn an_admin_request_is_not_in_the_public_listeners_in_flight_count() {
    // The admin listener counts its own requests; a probe on it is never a public request.
    let up = upstream().await;
    let cfg = cfg(up, "127.0.0.1");
    let opts = ServeOpts::from_cfg(&cfg.server).unwrap();
    let state = build_state(Arc::new(cfg)).unwrap();
    let metrics = Arc::clone(&state.metrics);
    let public = metrics.listener_stats("public");
    let admin_opts = opts.for_admin().with_stats(metrics.listener_stats("admin"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_stop, rx) = watch::channel(false);
    tokio::spawn(serve(
        listener,
        None,
        edgeguard::build_admin_router(state),
        admin_opts,
        rx,
    ));
    // A scrape on the admin listener counts itself while it renders.
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /__edgeguard/metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("edgeguard_requests_in_flight{listener=\"admin\"} 1\n"),
        "{text}"
    );
    assert!(
        text.contains("edgeguard_requests_in_flight{listener=\"public\"} 0\n"),
        "{text}"
    );
    assert_eq!(public.in_flight(), 0);
}

#[tokio::test]
async fn a_tls_health_check_that_closes_before_a_client_hello_is_not_a_failed_handshake() {
    let dir = Dir::new();
    let (server, connector) = tls(&dir);
    let up = upstream().await;
    let edge = edge(cfg(up, "127.0.0.1"), Some(server)).await;
    let failures = |reason: &str| {
        tls_counter(
            &edge.metrics,
            &format!(
                "edgeguard_tls_handshake_failures_total{{listener=\"public\",reason=\"{reason}\"}}"
            ),
        )
    };
    let no_hello = || {
        tls_counter(
            &edge.metrics,
            "edgeguard_tls_no_client_hello_total{listener=\"public\"}",
        )
    };

    // An NLB's PROXY protocol health check: the LOCAL header, then close. And a plain TCP check.
    for preamble in [v2_local(), Vec::new()] {
        let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
        tcp.write_all(&preamble).await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf)).await;
    }
    // The edge counts in its connection task, after the client sees the close.
    for _ in 0..50 {
        if no_hello() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let handshakes = || {
        tls_counter(
            &edge.metrics,
            "edgeguard_tls_handshakes_total{listener=\"public\"}",
        )
    };
    assert_eq!(no_hello(), 2);
    assert_eq!(failures("other"), 0, "not a failed handshake");
    assert_eq!(handshakes(), 0, "not a handshake at all");

    // A ClientHello that is cut off is still one.
    let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
    tcp.write_all(&v2_local()).await.unwrap();
    tcp.write_all(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")
        .await
        .unwrap();
    tcp.shutdown().await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf)).await;
    for _ in 0..50 {
        if failures("other") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(failures("other"), 1);
    assert_eq!(no_hello(), 2);
    assert_eq!(handshakes(), 1, "a failed handshake is in the total");

    // And a real client still gets its handshake, after a header or without one.
    let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
    tcp.write_all(&v2_local()).await.unwrap();
    let mut s = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("the handshake follows the header");
    assert_eq!(request(&mut s, "").await.unwrap().0, 200);
    assert_eq!(handshakes(), 2);
    assert_eq!(no_hello(), 2);
}

/// A PROXY v1 header for a client, 44 bytes, to drip.
const SLOW_HEADER: &[u8] = b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 443\r\n";
/// A request head that never ends: dripped until the edge closes the connection.
const SLOW_HEAD: &[u8] = b"GET /__edgeguard/health HTTP/1.1\r\nHost: edge\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// `bytes` to `w`, one at a time, `gap` apart. Paced against a schedule from the start rather
/// than a sleep after each byte: Windows rounds every sleep up to its timer tick (about 15.6 ms),
/// so 45 sleeps of 16 ms took nearly twice as long as asked and ran the header past the timeout.
async fn drip<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8], gap: Duration) {
    let start = tokio::time::Instant::now();
    for (i, b) in (1u32..).zip(bytes) {
        if w.write_all(std::slice::from_ref(b)).await.is_err() || w.flush().await.is_err() {
            return;
        }
        tokio::time::sleep_until(start + gap * i).await;
    }
}

/// Drip `SLOW_HEAD` into `s` until the edge closes it; how long after `start` that was.
async fn drip_head_until_closed<S>(s: S, start: tokio::time::Instant) -> Duration
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut r, mut w) = tokio::io::split(s);
    let closed = tokio::spawn(async move {
        let mut buf = [0u8; 256];
        while let Ok(n) = r.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
        start.elapsed()
    });
    let writer = tokio::spawn(async move {
        drip(&mut w, SLOW_HEAD, Duration::from_millis(50)).await;
        w
    });
    let elapsed = tokio::time::timeout(Duration::from_secs(10), closed)
        .await
        .expect("the edge closed the connection")
        .unwrap();
    writer.abort();
    elapsed
}

/// One `header_read_timeout` (1 s here) covers the PROXY header and the request head together:
/// a client dripping both is closed after about 1 s. It used to get the timeout twice, about 2 s.
fn assert_one_timeout(elapsed: Duration, what: &str) {
    assert!(
        elapsed >= Duration::from_millis(800) && elapsed < Duration::from_millis(1600),
        "{what}: closed after {elapsed:?}, not about 1 s"
    );
}

fn slow_cfg(up: SocketAddr) -> Config {
    let mut c = cfg(up, "127.0.0.1");
    c.server.header_read_timeout = "1s".into();
    c
}

#[tokio::test]
async fn a_dripped_proxy_header_and_head_get_one_header_read_timeout_on_plain_http() {
    let up = upstream().await;
    let edge = edge(slow_cfg(up), None).await;
    let start = tokio::time::Instant::now();
    let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
    // About 0.7 s of the 1 s on the header, then the head.
    drip(&mut tcp, SLOW_HEADER, Duration::from_millis(16)).await;
    assert_one_timeout(drip_head_until_closed(tcp, start).await, "public, plain");
}

#[tokio::test]
async fn a_dripped_proxy_header_and_head_get_one_header_read_timeout_on_the_admin_listener() {
    let up = upstream().await;
    let edge = admin_edge(slow_cfg(up)).await;
    let start = tokio::time::Instant::now();
    let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
    drip(&mut tcp, SLOW_HEADER, Duration::from_millis(16)).await;
    assert_one_timeout(drip_head_until_closed(tcp, start).await, "admin");
}

#[tokio::test]
async fn a_dripped_proxy_header_and_head_get_one_header_read_timeout_on_tls() {
    let dir = Dir::new();
    let (server, connector) = tls(&dir);
    let up = upstream().await;
    let edge = edge(slow_cfg(up), Some(server)).await;
    let start = tokio::time::Instant::now();
    let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
    drip(&mut tcp, SLOW_HEADER, Duration::from_millis(16)).await;
    // The handshake has a bound of its own and is not counted; it takes milliseconds here.
    let s = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("the handshake follows the header");
    assert_one_timeout(drip_head_until_closed(s, start).await, "public, TLS");
}

#[tokio::test]
async fn a_kept_alive_connection_is_not_cut_by_the_first_requests_deadline() {
    let up = upstream().await;
    let edge = admin_edge(slow_cfg(up)).await;
    let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
    let health = b"GET /__edgeguard/health HTTP/1.1\r\nHost: edge\r\n\r\n";
    async fn read_ok(tcp: &mut TcpStream) {
        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        while !got.ends_with(b"\r\n\r\nok") {
            let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf))
                .await
                .expect("an answer")
                .unwrap();
            assert!(n > 0, "closed: {:?}", String::from_utf8_lossy(&got));
            got.extend_from_slice(&buf[..n]);
        }
        assert!(got.starts_with(b"HTTP/1.1 200"));
    }
    tcp.write_all(&[SLOW_HEADER, &health[..]].concat())
        .await
        .unwrap();
    read_ok(&mut tcp).await;
    // Idle past the first request's deadline (1 s from accept) but within the next request's own.
    tokio::time::sleep(Duration::from_millis(700)).await;
    tcp.write_all(health).await.unwrap();
    read_ok(&mut tcp).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    tcp.write_all(health).await.unwrap();
    read_ok(&mut tcp).await;
    // A dripped later request still gets its own timeout: about 1 s from when it began.
    let start = tokio::time::Instant::now();
    assert_one_timeout(drip_head_until_closed(tcp, start).await, "a later request");
}

#[tokio::test]
async fn with_header_read_timeout_off_a_slow_proxy_header_and_head_are_served() {
    let up = upstream().await;
    let mut c = cfg(up, "127.0.0.1");
    c.server.header_read_timeout = "0".into();
    let edge = admin_edge(c).await;
    let mut tcp = TcpStream::connect(edge.addr).await.unwrap();
    drip(&mut tcp, SLOW_HEADER, Duration::from_millis(16)).await;
    drip(
        &mut tcp,
        b"GET /__edgeguard/health HTTP/1.1\r\nHost: edge\r\nConnection: close\r\n\r\n",
        Duration::from_millis(20),
    )
    .await;
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&out)
    );
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
