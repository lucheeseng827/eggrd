//! `server.trust_forwarded_for` through the real pipeline: the client is the `X-Forwarded-For`
//! entry the trusted proxy appended (`server.forwarded_hops` from the right), never what the client
//! wrote on the left. Rate limits, `[access]` rules and the `X-Forwarded-For` the app receives all
//! see that one address.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;

use edgeguard::config::Config;
use edgeguard::metrics::Metrics;
use edgeguard::serve::{serve, ServeOpts};
use edgeguard::{build_router, build_state};

/// Answers with the `X-Forwarded-For` the edge sent.
async fn upstream() -> SocketAddr {
    let app = Router::new().fallback(|headers: HeaderMap| async move {
        headers
            .get("x-forwarded-for")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_else(|| "-".into())
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

struct Edge {
    url: String,
    metrics: Arc<Metrics>,
    _stop: watch::Sender<bool>,
}

/// The pipeline on `serve`, as `main` runs the public listener.
async fn edge(cfg: Config) -> Edge {
    let opts = ServeOpts::from_cfg(&cfg.server).unwrap();
    let state = build_state(Arc::new(cfg)).unwrap();
    let metrics = Arc::clone(&state.metrics);
    let opts = opts.with_stats(metrics.listener_stats("public"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(serve(listener, None, build_router(state), opts, rx));
    Edge {
        url: format!("http://{addr}"),
        metrics,
        _stop: stop,
    }
}

/// `trust_forwarded_for` behind `hops` appending proxies, rate limits off.
fn cfg(up: SocketAddr, hops: usize) -> Config {
    let mut c = Config::default();
    c.server.upstream = format!("http://{up}");
    c.server.trust_forwarded_for = true;
    c.server.forwarded_hops = hops;
    c.ratelimit.enabled = false;
    c
}

/// One request carrying `xff` as the balancer forwards it: what the client wrote, then what each
/// proxy appended. Status and the `X-Forwarded-For` the app received.
async fn via(edge: &Edge, xff: &[&str]) -> (u16, String) {
    let mut req = reqwest::Client::new().get(format!("{}/orders", edge.url));
    for line in xff {
        req = req.header("x-forwarded-for", *line);
    }
    let resp = req.send().await.unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

/// `edgeguard_forwarded_for_total{result}` as the registry renders it.
fn counted(metrics: &Metrics, result: &str) -> u64 {
    let line = format!("edgeguard_forwarded_for_total{{result=\"{result}\"}} ");
    metrics
        .render()
        .lines()
        .find_map(|l| l.strip_prefix(&line)?.parse().ok())
        .unwrap_or_else(|| panic!("no {line}"))
}

#[tokio::test]
async fn a_client_cannot_choose_its_address_by_writing_x_forwarded_for_through_the_balancer() {
    let up = upstream().await;
    let mut c = cfg(up, 1);
    c.ratelimit.enabled = true;
    c.ratelimit.rate = "1/min".into();
    c.ratelimit.burst = 1;
    let edge = edge(c).await;
    // The real client, 198.51.100.7, behind an appending balancer. Each request writes a new
    // spoofed address on the left; it used to be taken as the client, so every request got its
    // own rate-limit bucket.
    let (status, seen) = via(&edge, &["203.0.113.1, 198.51.100.7"]).await;
    assert_eq!((status, seen.as_str()), (200, "198.51.100.7"));
    for spoof in 2..5 {
        let xff = format!("203.0.113.{spoof}, 198.51.100.7");
        assert_eq!(
            via(&edge, &[&xff]).await.0,
            429,
            "{xff}: one client, one bucket"
        );
    }
    // Another real client behind the same balancer has its own.
    assert_eq!(via(&edge, &["203.0.113.1, 198.51.100.8"]).await.0, 200);
    assert_eq!(counted(&edge.metrics, "used"), 5);
}

#[tokio::test]
async fn access_rules_see_the_balancers_entry() {
    let up = upstream().await;
    let mut c = cfg(up, 1);
    c.access.deny = vec!["198.51.100.0/24".into()];
    let edge = edge(c).await;
    // Prepending an allowed address does not get a denied client in.
    assert_eq!(via(&edge, &["10.9.9.9, 198.51.100.7"]).await.0, 403);
    // Nor does a spoofed denied address lock out an allowed client.
    assert_eq!(via(&edge, &["198.51.100.7, 192.0.2.10"]).await.0, 200);
}

#[tokio::test]
async fn forwarded_hops_counts_a_chain_of_proxies() {
    let up = upstream().await;
    let edge = edge(cfg(up, 2)).await;
    // client-written, the client as CloudFront saw it, CloudFront's edge as the ALB saw it.
    let (_, seen) = via(&edge, &["203.0.113.1, 198.51.100.7, 130.176.0.1"]).await;
    assert_eq!(seen, "198.51.100.7");
    // Split over two header lines, as some proxies send it.
    let (_, seen) = via(&edge, &["203.0.113.1, 198.51.100.7", "130.176.0.1"]).await;
    assert_eq!(seen, "198.51.100.7");
    // Shorter than the chain: the TCP peer, counted.
    let (_, seen) = via(&edge, &["198.51.100.7"]).await;
    assert_eq!(seen, "127.0.0.1");
    assert_eq!(counted(&edge.metrics, "short"), 1);
    assert_eq!(counted(&edge.metrics, "used"), 2);
}

#[tokio::test]
async fn an_unreadable_entry_falls_back_to_the_peer() {
    let up = upstream().await;
    let edge = edge(cfg(up, 1)).await;
    assert_eq!(via(&edge, &["198.51.100.7, unknown"]).await.1, "127.0.0.1");
    assert_eq!(via(&edge, &[]).await.1, "127.0.0.1");
    assert_eq!(
        via(&edge, &["1.2.3.4, [2001:db8::7]:4711"]).await.1,
        "2001:db8::7"
    );
    assert_eq!(counted(&edge.metrics, "invalid"), 1);
    assert_eq!(counted(&edge.metrics, "absent"), 1);
    assert_eq!(counted(&edge.metrics, "used"), 1);
}

/// A collector on plain HTTP that keeps every body posted to it, by path.
async fn collector() -> (SocketAddr, Arc<std::sync::Mutex<Vec<(String, String)>>>) {
    let seen: Arc<std::sync::Mutex<Vec<(String, String)>>> = Arc::default();
    let keep = Arc::clone(&seen);
    let app = Router::new().fallback(move |uri: axum::http::Uri, body: String| {
        let keep = Arc::clone(&keep);
        async move {
            keep.lock().unwrap().push((uri.path().to_string(), body));
            "ok"
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, seen)
}

#[tokio::test]
async fn the_shipped_log_record_and_the_span_carry_the_resolved_client() {
    let up = upstream().await;
    let (sink, seen) = collector().await;
    let mut c = cfg(up, 1);
    c.log.ship.enabled = true;
    c.log.ship.url = format!("http://{sink}/logs");
    c.log.ship.batch = 1;
    c.log.ship.interval_secs = 1;
    c.tracing.enabled = true;
    c.tracing.endpoint = format!("http://{sink}/v1/traces");
    c.tracing.batch = 1;
    c.tracing.interval_secs = 1;
    let (stop, rx) = watch::channel(false);
    let state = build_state(Arc::new(c.clone())).unwrap();
    if let Some(s) = edgeguard::logship::spawn(&c.log.ship, "edge".into(), rx.clone()).unwrap() {
        state.metrics.set_log_shipper(s);
    }
    if let Some(s) = edgeguard::telemetry::spawn_span_shipper(&c.tracing, rx.clone()).unwrap() {
        state.metrics.set_span_shipper(s);
    }
    let metrics = Arc::clone(&state.metrics);
    let opts = ServeOpts::from_cfg(&c.server)
        .unwrap()
        .with_stats(metrics.listener_stats("public"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, None, build_router(state), opts, rx));
    let edge = Edge {
        url: format!("http://{addr}"),
        metrics,
        _stop: stop,
    };
    assert_eq!(via(&edge, &["203.0.113.1, 198.51.100.7"]).await.0, 200);

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let posted = |path: &str| {
        seen.lock()
            .unwrap()
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, b)| b.clone())
    };
    let (logs, spans) = loop {
        if let (Some(l), Some(s)) = (posted("/logs"), posted("/v1/traces")) {
            break (l, s);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{:?}",
            seen.lock().unwrap()
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(logs.contains("\"client_ip\":\"198.51.100.7\""), "{logs}");
    assert!(!logs.contains("203.0.113.1"), "{logs}");
    let span: serde_json::Value = serde_json::from_str(&spans).unwrap();
    let attrs = span["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
        .as_array()
        .unwrap()
        .clone();
    let client = attrs
        .iter()
        .find(|a| a["key"] == "client.address")
        .map(|a| a["value"]["stringValue"].clone());
    assert_eq!(client, Some(serde_json::json!("198.51.100.7")), "{spans}");
}

#[tokio::test]
async fn without_trust_the_header_is_ignored_and_not_counted() {
    let up = upstream().await;
    let mut c = cfg(up, 1);
    c.server.trust_forwarded_for = false;
    let edge = edge(c).await;
    assert_eq!(
        via(&edge, &["203.0.113.1, 198.51.100.7"]).await.1,
        "127.0.0.1"
    );
    assert!(!edge
        .metrics
        .render()
        .contains("edgeguard_forwarded_for_total"));
}
