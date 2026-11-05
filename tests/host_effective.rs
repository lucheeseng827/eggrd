//! One host per request, whatever the protocol: a WAF Host rule sees an HTTP/2 request's
//! `:authority` (cleartext HTTP/2 sends no `Host` header) and an HTTP/1.1 absolute-form target,
//! `X-Forwarded-Host` carries the same host, and a request naming two hosts is refused.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request};
use axum::Router;
use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use edgeguard::config::Config;
use edgeguard::serve::{serve, ServeOpts};
use edgeguard::{build_admin_router, build_public_router, build_router, build_state};

/// Answers with the `X-Forwarded-Host` the edge sent, counting the requests that reach it.
async fn upstream(hits: Arc<AtomicUsize>) -> SocketAddr {
    let app = Router::new().fallback(move |headers: HeaderMap| {
        let hits = Arc::clone(&hits);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            headers
                .get("x-forwarded-host")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_else(|| "-".into())
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// The pipeline on a plain listener (HTTP/1.1 and HTTP/2 with prior knowledge), with a WAF
/// rule refusing `evil.example` and an empty host, as the Host allow-list rule does.
async fn edge(waf: bool) -> (SocketAddr, watch::Sender<bool>) {
    edge_counted(waf, Arc::default()).await
}

/// [`edge`], its upstream counting into `hits`.
async fn edge_counted(waf: bool, hits: Arc<AtomicUsize>) -> (SocketAddr, watch::Sender<bool>) {
    let cfg = config(waf, hits).await;
    let state = build_state(Arc::new(cfg)).unwrap();
    listen(build_router(state)).await
}

/// `router` on a plain listener (HTTP/1.1 and HTTP/2 with prior knowledge).
async fn listen(router: Router) -> (SocketAddr, watch::Sender<bool>) {
    let opts = ServeOpts::from_cfg(&Config::default().server).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(serve(listener, None, router, opts, rx));
    (addr, stop)
}

/// The config [`edge`] runs, its upstream counting into `hits`.
async fn config(waf: bool, hits: Arc<AtomicUsize>) -> Config {
    let up = upstream(hits).await;
    toml::from_str(&format!(
        r#"
[server]
upstream = "http://{up}"
[auth]
mode = "none"
[ratelimit]
enabled = false
[validation]
websocket_passthrough = true
[waf]
mode = "{mode}"
inspect_headers = true
[[waf.rules]]
id = "host-allowlist"
target = "headers"
pattern = '(?mi)^host:[ \t]*(?:evil\.example(?::[0-9]+)?)?[ \t]*$'
"#,
        mode = if waf { "block" } else { "off" }
    ))
    .unwrap()
}

/// One HTTP/2 prior-knowledge request: `uri`'s authority is `:authority`; `host`, if given, is
/// also sent as a `host` header.
async fn h2(addr: SocketAddr, uri: &str, host: Option<&str>) -> (u16, String) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tcp),
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    let mut req = Request::get(uri);
    if let Some(h) = host {
        req = req.header("host", h);
    }
    let resp = send
        .send_request(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// One raw HTTP/1.1 request, `head` being everything up to the blank line.
async fn h1(addr: SocketAddr, head: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("{head}Connection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

#[tokio::test]
async fn an_http2_authority_is_checked_like_a_host_header() {
    let (addr, _stop) = edge(true).await;
    // The 0.7.0 bypass: the forged host only in `:authority`.
    assert_eq!(h2(addr, "http://evil.example/", None).await.0, 403);
    assert_eq!(h2(addr, "http://evil.example:8080/", None).await.0, 403);
    // The right host passes, and the app's X-Forwarded-Host is the host that was checked.
    assert_eq!(
        h2(addr, "http://app.example.test/", None).await,
        (200, "app.example.test".into())
    );
    // HTTP/1.1 as before.
    assert_eq!(
        h1(addr, "GET / HTTP/1.1\r\nHost: evil.example\r\n").await.0,
        403
    );
    assert_eq!(
        h1(addr, "GET / HTTP/1.1\r\nHost: app.example.test\r\n").await,
        (200, "app.example.test".into())
    );
}

#[tokio::test]
async fn an_absolute_form_target_is_the_host_and_must_agree_with_host() {
    let (addr, _stop) = edge(true).await;
    // RFC 9112: the absolute-form authority is the host. Agreeing with Host: checked as that.
    assert_eq!(
        h1(
            addr,
            "GET http://app.example.test/ HTTP/1.1\r\nHost: app.example.test\r\n"
        )
        .await,
        (200, "app.example.test".into())
    );
    // Disagreeing, either way round: refused before anything checks either.
    assert_eq!(
        h1(
            addr,
            "GET http://evil.example/ HTTP/1.1\r\nHost: app.example.test\r\n"
        )
        .await
        .0,
        400
    );
    assert_eq!(
        h1(
            addr,
            "GET http://app.example.test/ HTTP/1.1\r\nHost: evil.example\r\n"
        )
        .await
        .0,
        400
    );
    // Host twice.
    assert_eq!(
        h1(
            addr,
            "GET / HTTP/1.1\r\nHost: app.example.test\r\nHost: evil.example\r\n"
        )
        .await
        .0,
        400
    );
    // No host at all. HTTP/1.1 requires one (RFC 9112 §3.2): 400, before the WAF.
    assert_eq!(h1(addr, "GET / HTTP/1.1\r\n").await.0, 400);
    // HTTP/1.0 may omit it: it goes on hostless, the WAF sees an empty host line, and the Host
    // rule refuses it.
    assert_eq!(h1(addr, "GET / HTTP/1.0\r\n").await.0, 403);
}

#[tokio::test]
async fn without_a_host_rule_an_http10_request_without_host_is_served() {
    // Old health checkers send HTTP/1.0 without Host; with no Host rule they keep working.
    let (addr, _stop) = edge(false).await;
    assert_eq!(h1(addr, "GET / HTTP/1.0\r\n").await, (200, "-".into()));
    // HTTP/1.1 without Host is still refused: the protocol requires it.
    assert_eq!(h1(addr, "GET / HTTP/1.1\r\n").await.0, 400);
}

#[tokio::test]
async fn an_http2_request_without_an_authority_is_refused() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (addr, _stop) = edge_counted(false, Arc::clone(&hits)).await;
    // An origin-form target: hyper sends no `:authority` and no `host`.
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tcp),
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    let req = Request::get("/").body(Body::empty()).unwrap();
    if let Ok(resp) = send.send_request(req).await {
        assert_eq!(resp.status().as_u16(), 400);
    }
    // Whether the client sent it (and got 400) or would not: nothing reached the app. The
    // decision itself is unit-tested (`proxy::tests::one_effective_host_per_request`).
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    // And a request with an authority does reach it, over the same kind of connection.
    assert_eq!(h2(addr, "http://app.example.test/", None).await.0, 200);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_http2_authority_and_host_that_differ_are_refused() {
    let (addr, _stop) = edge(false).await;
    assert_eq!(
        h2(addr, "http://app.example.test/", Some("evil.example"))
            .await
            .0,
        400
    );
    // Agreeing, they are one host.
    assert_eq!(
        h2(addr, "http://app.example.test/", Some("app.example.test")).await,
        (200, "app.example.test".into())
    );
    // Without the WAF, the authority still names X-Forwarded-Host.
    assert_eq!(
        h2(addr, "http://evil.example/", None).await,
        (200, "evil.example".into())
    );
}

#[tokio::test]
async fn a_websocket_handshake_is_screened_by_the_waf() {
    let (addr, _stop) = edge(true).await;
    let head = |host: &str| {
        format!("GET /ws HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: echo\r\n")
    };
    assert_eq!(h1(addr, &head("evil.example")).await.0, 403);
    // The right host is not blocked: it reaches the upstream, which does not upgrade.
    let (status, _) = h1(addr, &head("app.example.test")).await;
    assert_ne!(status, 403, "over-blocked");
    assert_ne!(status, 400);
}

#[tokio::test]
async fn a_host_that_is_not_ascii_text_is_refused() {
    // 0.7.0 served it, and the WAF skipped the value (it reads header values as text), so a Host
    // allow-list rule never saw it. Now it is refused before the WAF, with or without one.
    for waf in [true, false] {
        let (addr, _stop) = edge(waf).await;
        assert_eq!(
            h1(addr, "GET / HTTP/1.1\r\nHost: caf\u{e9}.example\r\n")
                .await
                .0,
            400,
            "waf = {waf}"
        );
    }
}

#[tokio::test]
async fn the_ops_endpoints_answer_without_a_host_or_with_a_wrong_one() {
    // What load balancer, kubelet and Docker health checks hit: never held to the host check or
    // the WAF's Host rule, on whichever listener serves them, and still 404 on the public one in
    // split mode, as before.
    let cfg = Arc::new(config(true, Arc::default()).await);
    let (single, _a) = listen(build_router(build_state(Arc::clone(&cfg)).unwrap())).await;
    let (admin, _b) = listen(build_admin_router(build_state(Arc::clone(&cfg)).unwrap())).await;
    let (public, _c) = listen(build_public_router(build_state(cfg).unwrap())).await;
    for path in ["/__edgeguard/health", "/__edgeguard/ready"] {
        for (addr, want, listener) in [
            (single, 200, "single-port"),
            (admin, 200, "admin"),
            (public, 404, "public"),
        ] {
            for head in [
                format!("GET {path} HTTP/1.1\r\n"),
                format!("GET {path} HTTP/1.1\r\nHost: evil.example\r\n"),
                format!("GET {path} HTTP/1.1\r\nHost: caf\u{e9}.example\r\n"),
                format!("GET {path} HTTP/1.1\r\nHost: a\r\nHost: b\r\n"),
                format!("GET {path} HTTP/1.0\r\n"),
            ] {
                assert_eq!(h1(addr, &head).await.0, want, "{listener}: {head:?}");
            }
            let uri = format!("http://evil.example{path}");
            assert_eq!(h2(addr, &uri, None).await.0, want, "{listener}: h2 {uri}");
        }
    }
    // A proxied request on the same listeners is held to them.
    assert_eq!(
        h1(single, "GET / HTTP/1.1\r\nHost: evil.example\r\n")
            .await
            .0,
        403
    );
    assert_eq!(h1(public, "GET / HTTP/1.1\r\n").await.0, 400);
}

#[tokio::test]
async fn a_waf_block_counts_the_same_outcome_on_a_websocket_handshake() {
    let (addr, _stop) = edge(true).await;
    assert_eq!(
        h1(addr, "GET / HTTP/1.1\r\nHost: evil.example\r\n").await.0,
        403
    );
    assert_eq!(
        h1(
            addr,
            "GET /ws HTTP/1.1\r\nHost: evil.example\r\nConnection: Upgrade\r\nUpgrade: echo\r\n"
        )
        .await
        .0,
        403
    );
    let (status, metrics) = h1(addr, "GET /__edgeguard/metrics HTTP/1.1\r\nHost: m\r\n").await;
    assert_eq!(status, 200);
    assert!(
        metrics.contains("edgeguard_requests_total{outcome=\"forbidden\"} 2\n"),
        "{metrics}"
    );
}

#[tokio::test]
async fn an_empty_or_blank_host_is_no_host() {
    for waf in [true, false] {
        let hits = Arc::new(AtomicUsize::new(0));
        let (addr, _stop) = edge_counted(waf, Arc::clone(&hits)).await;
        for blank in ["Host:", "Host: ", "Host:   "] {
            // HTTP/1.1 requires a host: refused before the WAF, never forwarded with an empty
            // X-Forwarded-Host.
            assert_eq!(
                h1(addr, &format!("GET / HTTP/1.1\r\n{blank}\r\n")).await.0,
                400,
                "waf = {waf}: {blank:?}"
            );
            // HTTP/1.0 may omit it: as with no Host line at all.
            let (status, body) = h1(addr, &format!("GET / HTTP/1.0\r\n{blank}\r\n")).await;
            if waf {
                assert_eq!(status, 403, "{blank:?}");
            } else {
                assert_eq!((status, body.as_str()), (200, "-"), "{blank:?}");
            }
        }
        // HTTP/2: an origin-form target (no `:authority`) with an empty or blank `host`.
        for blank in ["", "   "] {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let (mut send, conn) = hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(),
                hyper_util::rt::TokioIo::new(tcp),
            )
            .await
            .unwrap();
            tokio::spawn(conn);
            let req = Request::get("/")
                .header("host", blank)
                .body(Body::empty())
                .unwrap();
            if let Ok(resp) = send.send_request(req).await {
                assert_eq!(resp.status().as_u16(), 400, "waf = {waf}: h2 {blank:?}");
            }
        }
        // With no Host rule, only the HTTP/1.0 requests reached the app.
        let served = if waf { 0 } else { 3 };
        assert_eq!(hits.load(Ordering::SeqCst), served, "waf = {waf}");
    }
}
