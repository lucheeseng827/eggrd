//! Per-upstream health through the real pipeline, read back from `/__edgeguard/metrics`: each way
//! an upstream can fail lands under its own `result`, and the upstream's time to headers agrees
//! with the access log's `upstream_ms`.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;
use common::{Ca, Dir};

use edgeguard::config::{Config, LogShipCfg, UpstreamRoute};
use edgeguard::{build_router, build_state};

/// `/ok` answers, `/fail` answers `503`, `/slow` answers after 200 ms, `/hang` after 5 s, `/big`
/// with 4 KiB.
async fn upstream() -> SocketAddr {
    let app = Router::new()
        .route("/ok", get(|| async { "ok" }))
        .route(
            "/fail",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "down") }),
        )
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                "slow"
            }),
        )
        .route("/big", get(|| async { "x".repeat(4096) }))
        .route(
            "/hang",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "late"
            }),
        )
        .fallback(|| async { "ok" });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// A server that reads the request and then misbehaves: closes without answering, or sends
/// headers promising 100 bytes and closes after 10.
async fn broken(promise_a_body: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                if promise_a_body {
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n0123456789")
                        .await;
                }
                // Dropped: the connection closes.
            });
        }
    });
    addr
}

/// A port with nothing listening on it.
async fn closed_port() -> SocketAddr {
    // Bound but not listening, so connections are refused, and held for the rest of the run:
    // freed, the port could be handed to another test's upstream running alongside.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = socket.local_addr().unwrap();
    std::mem::forget(socket);
    addr
}

/// A TLS upstream whose certificate is from a CA the edge does not trust.
async fn untrusted_tls(dir: &Dir) -> (SocketAddr, watch::Sender<bool>) {
    edgeguard::tls::init_crypto();
    let (cert, key) = dir.pair("up", &Ca::new("unknown CA").server(&["localhost"]));
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    let tls = edgeguard::tls::server_config_with_client_auth(store, None).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(edgeguard::serve::serve(
        listener,
        Some(tls),
        Router::new().fallback(|| async { "tls" }),
        edgeguard::serve::ServeOpts::default(),
        rx,
    ));
    (addr, stop)
}

fn route(path: &str, target: String) -> UpstreamRoute {
    UpstreamRoute {
        path: path.into(),
        target,
        ..Default::default()
    }
}

fn base(up: SocketAddr) -> Config {
    let mut cfg = Config::default();
    cfg.server.upstream = format!("http://{up}");
    cfg.auth.mode = "none".into();
    cfg.ratelimit.enabled = false;
    cfg.validation.upstream_timeout = "500ms".into();
    cfg
}

async fn proxy(cfg: Config) -> (SocketAddr, Arc<edgeguard::metrics::Metrics>) {
    let state = build_state(Arc::new(cfg)).unwrap();
    let metrics = Arc::clone(&state.metrics);
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (addr, metrics)
}

/// Every sample of `family` as (labels, value).
fn samples(text: &str, family: &str) -> Vec<(BTreeMap<String, String>, f64)> {
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix(family)?.strip_prefix('{')?;
            let (labels, value) = rest.rsplit_once("} ")?;
            let labels = labels
                .split("\",")
                .filter_map(|kv| {
                    let (k, v) = kv.split_once("=\"")?;
                    Some((k.to_string(), v.trim_end_matches('"').to_string()))
                })
                .collect();
            Some((labels, value.parse().unwrap()))
        })
        .collect()
}

/// The non-zero results for each upstream: `{"http://…": {"ok": 2, …}}`.
fn results(text: &str) -> BTreeMap<String, BTreeMap<String, f64>> {
    let mut out: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
    for (labels, v) in samples(text, "edgeguard_upstream_requests_total") {
        let per = out.entry(labels["upstream"].clone()).or_default();
        if v > 0.0 {
            per.insert(labels["result"].clone(), v);
        }
    }
    out
}

#[tokio::test]
async fn each_way_an_upstream_can_fail_has_its_own_result() {
    let dir = Dir::new();
    let up = upstream().await;
    let (refused, reset, short_body) =
        (closed_port().await, broken(false).await, broken(true).await);
    let (tls, _stop_tls) = untrusted_tls(&dir).await;
    let mut cfg = base(up);
    // Long enough for a refusal to arrive: on Windows a refused connect to loopback takes about
    // two seconds (the SYN is retried after the RST), and past the timeout it would count as one.
    // `/hang` (5 s) still times out.
    cfg.validation.upstream_timeout = "4s".into();
    cfg.upstreams = vec![
        route("/refused/", format!("http://{refused}")),
        route("/reset/", format!("http://{reset}")),
        route("/short/", format!("http://{short_body}")),
        route("/tls/", format!("https://localhost:{}", tls.port())),
    ];
    let (addr, metrics) = proxy(cfg).await;

    let client = reqwest::Client::new();
    let status = |path: &'static str| {
        let client = client.clone();
        async move {
            client
                .get(format!("http://{addr}{path}"))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(status("/ok").await, 200);
    assert_eq!(status("/ok").await, 200);
    assert_eq!(status("/fail").await, 503);
    assert_eq!(status("/hang").await, 504);
    assert_eq!(status("/refused/x").await, 502);
    assert_eq!(status("/reset/x").await, 502);
    assert_eq!(status("/short/x").await, 502);
    assert_eq!(status("/tls/x").await, 502);

    let got = results(&metrics.render());
    let one = |r: &str| BTreeMap::from([(r.to_string(), 1.0)]);
    assert_eq!(
        got[&format!("http://127.0.0.1:{}", up.port())],
        BTreeMap::from([
            ("ok".to_string(), 2.0),
            ("http_5xx".to_string(), 1.0),
            ("timeout".to_string(), 1.0),
        ])
    );
    assert_eq!(
        got[&format!("http://127.0.0.1:{}", refused.port())],
        one("connect_error")
    );
    assert_eq!(
        got[&format!("http://127.0.0.1:{}", reset.port())],
        one("reset")
    );
    assert_eq!(
        got[&format!("http://127.0.0.1:{}", short_body.port())],
        one("reset"),
        "headers, then the connection closed mid-body"
    );
    assert_eq!(
        got[&format!("https://localhost:{}", tls.port())],
        one("tls_error")
    );

    // Every result is written for each upstream, zeros included.
    let text = metrics.render();
    let all = samples(&text, "edgeguard_upstream_requests_total");
    assert_eq!(all.len(), 5 * 7, "{all:?}");
    // Only exchanges that got headers are timed: the two `ok`, the `503`, and the short body's.
    let timed: f64 = samples(&text, "edgeguard_upstream_duration_seconds_count")
        .iter()
        .map(|(_, v)| v)
        .sum();
    assert_eq!(timed, 4.0);
}

/// The buffered path reads the body under the response cap or without one, by two different
/// routes; a body cut short is a `reset` on both, and a body over the cap is the edge's refusal,
/// not the upstream's failure.
#[tokio::test]
async fn a_body_cut_short_is_a_reset_with_or_without_a_response_cap() {
    let up = upstream().await;
    let short_body = broken(true).await;
    for cap in ["0", "1KiB"] {
        let mut cfg = base(up);
        cfg.validation.max_response_body = cap.into();
        cfg.upstreams = vec![route("/short/", format!("http://{short_body}"))];
        let (addr, metrics) = proxy(cfg).await;
        let client = reqwest::Client::new();
        for path in ["/short/x", "/big"] {
            let status = client
                .get(format!("http://{addr}{path}"))
                .send()
                .await
                .unwrap()
                .status();
            // Over the cap the client gets a 502; without one, the whole body.
            let expected = if path == "/big" && cap == "0" {
                200
            } else {
                502
            };
            assert_eq!(status, expected, "cap {cap}, {path}");
        }
        let got = results(&metrics.render());
        assert_eq!(
            got[&format!("http://127.0.0.1:{}", short_body.port())],
            BTreeMap::from([("reset".to_string(), 1.0)]),
            "cap {cap}"
        );
        assert_eq!(
            got[&format!("http://127.0.0.1:{}", up.port())],
            BTreeMap::from([("ok".to_string(), 1.0)]),
            "cap {cap}: a body over the cap is still an answer"
        );
    }
}

type Records = Arc<Mutex<Vec<serde_json::Value>>>;

async fn collector() -> (String, Records) {
    let records: Records = Arc::default();
    let sink = Arc::clone(&records);
    let app = Router::new().route(
        "/",
        post(move |body: String| {
            let sink = Arc::clone(&sink);
            async move {
                for line in body.lines().filter(|l| !l.is_empty()) {
                    sink.lock()
                        .unwrap()
                        .push(serde_json::from_str(line).unwrap());
                }
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, records)
}

#[tokio::test]
async fn the_upstream_time_agrees_with_the_access_log() {
    let up = upstream().await;
    let (url, records) = collector().await;
    let mut cfg = base(up);
    cfg.log.ship = LogShipCfg {
        enabled: true,
        url,
        batch: 1,
        interval_secs: 1,
        ..Default::default()
    };
    let state = build_state(Arc::new(cfg.clone())).unwrap();
    let (_stop, rx) = watch::channel(false);
    let shipper = edgeguard::logship::spawn(&cfg.log.ship, "edge".into(), rx)
        .unwrap()
        .unwrap();
    state.metrics.set_log_shipper(shipper);
    let metrics = Arc::clone(&state.metrics);
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    assert_eq!(
        reqwest::get(format!("http://{addr}/slow"))
            .await
            .unwrap()
            .status(),
        200
    );
    let record = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(r) = records.lock().unwrap().first().cloned() {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the access record");
    let upstream_ms = record["upstream_ms"].as_u64().unwrap();
    let text = metrics.render();
    let sum = samples(&text, "edgeguard_upstream_duration_seconds_sum")[0].1 * 1000.0;
    assert!(upstream_ms >= 200, "{record}");
    // The log truncates to whole milliseconds; the histogram keeps microseconds.
    assert!(
        (sum - upstream_ms as f64) >= 0.0 && (sum - upstream_ms as f64) < 1.0,
        "histogram {sum} ms vs access log {upstream_ms} ms"
    );
    // The client's latency includes the upstream's; what is left is the edge's own.
    assert!(record["latency_ms"].as_u64().unwrap() >= upstream_ms);
}

/// A body that sends nothing for 300 ms, then one chunk.
struct LateBody {
    sleep: std::pin::Pin<Box<tokio::time::Sleep>>,
    sent: bool,
}

impl hyper::body::Body for LateBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<bytes::Bytes>, Self::Error>>> {
        if self.sent {
            return std::task::Poll::Ready(None);
        }
        if self.sleep.as_mut().poll(cx).is_pending() {
            return std::task::Poll::Pending;
        }
        self.sent = true;
        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(
            bytes::Bytes::from_static(b"late body"),
        ))))
    }
}

/// Answers its headers at once and its body 300 ms later.
async fn slow_body_upstream() -> SocketAddr {
    let app = Router::new().fallback(|| async {
        axum::body::Body::new(LateBody {
            sleep: Box::pin(tokio::time::sleep(Duration::from_millis(300))),
            sent: false,
        })
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// The `(count, sum in seconds)` of `edgeguard_edge_overhead_seconds`.
fn overhead(text: &str) -> (f64, f64) {
    let one = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
            .unwrap_or_else(|| panic!("no {name} in\n{text}"))
    };
    (
        one("edgeguard_edge_overhead_seconds_count"),
        one("edgeguard_edge_overhead_seconds_sum"),
    )
}

/// The edge's own time is what is left once the wait on the upstream — its headers and, buffered,
/// its body — is taken out of the time to response headers.
#[tokio::test]
async fn edge_overhead_leaves_out_the_wait_on_the_upstream() {
    let up = upstream().await;
    let slow_body = slow_body_upstream().await;
    let mut cfg = base(up);
    cfg.validation.upstream_timeout = "5s".into();
    cfg.upstreams = vec![route("/body/", format!("http://{slow_body}"))];
    cfg.auth.mode = "apikey".into();
    cfg.auth.api_keys = vec!["k".into()];
    let (addr, metrics) = proxy(cfg).await;
    let client = reqwest::Client::new();
    let get = |path: &'static str, key: bool| {
        let mut req = client.get(format!("http://{addr}{path}"));
        if key {
            req = req.header("x-api-key", "k");
        }
        async move { req.send().await.unwrap().status().as_u16() }
    };
    // Slow headers (200 ms), then slow body (300 ms, buffered: the client waits for it too).
    assert_eq!(get("/slow", true).await, 200);
    assert_eq!(get("/body/x", true).await, 200);
    // Answered by the edge: no upstream, no overhead to speak of.
    assert_eq!(get("/slow", false).await, 401);

    let text = metrics.render();
    let route_sum = samples(&text, "edgeguard_route_request_duration_seconds_sum")
        .iter()
        .map(|(_, v)| v)
        .sum::<f64>();
    assert!(route_sum >= 0.5, "the client waited for both: {route_sum}");
    let (count, sum) = overhead(&text);
    assert_eq!(count, 2.0, "the two the upstream answered");
    assert!(
        sum < 0.1,
        "the 500 ms of upstream waiting is not the edge's: {sum}"
    );
}

#[tokio::test]
async fn streamed_and_upgrade_exchanges_are_counted_on_their_headers() {
    let up = upstream().await;
    let mut cfg = base(up);
    cfg.validation.stream_responses = true;
    cfg.validation.websocket_passthrough = true;
    let (addr, metrics) = proxy(cfg).await;
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("http://{addr}/ok"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // A WebSocket handshake the upstream refuses with a 503.
    let refused = client
        .get(format!("http://{addr}/fail"))
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(refused, 503);
    let got = results(&metrics.render());
    assert_eq!(
        got[&format!("http://127.0.0.1:{}", up.port())],
        BTreeMap::from([("ok".to_string(), 1.0), ("http_5xx".to_string(), 1.0)])
    );
}
