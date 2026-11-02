//! Per-route and per-consumer metrics through the real pipeline, read back from
//! `/__edgeguard/metrics`: bounded route labels, consumers by principal with the cap, bytes on the
//! buffered and the streamed path, and counters that survive a reload.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use base64::Engine;
use tokio::net::TcpListener;

use edgeguard::config::{Config, RouteRateLimit, UpstreamRoute};
use edgeguard::{build_router, build_runtime, build_state};

const BODY: &str = "hello from upstream";

async fn upstream() -> SocketAddr {
    let app = Router::new().fallback(|| async { BODY });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn base(up: SocketAddr) -> Config {
    let mut cfg = Config::default();
    cfg.server.upstream = format!("http://{up}");
    cfg.auth.mode = "none".into();
    cfg.ratelimit.enabled = false;
    cfg
}

/// The proxy, and a handle to swap its runtime (as a reload does).
async fn proxy(
    cfg: Config,
) -> (
    SocketAddr,
    Arc<arc_swap::ArcSwap<edgeguard::proxy::Runtime>>,
) {
    let state = build_state(Arc::new(cfg)).unwrap();
    let runtime = Arc::clone(&state.runtime);
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
    (addr, runtime)
}

/// Every sample of `family` as (labels, value): `{route="api",method="GET"} 3` →
/// `({"route": "api", "method": "GET"}, 3)`.
async fn samples(addr: SocketAddr, family: &str) -> Vec<(BTreeMap<String, String>, f64)> {
    let text = reqwest::get(format!("http://{addr}/__edgeguard/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
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

fn sum(samples: &[(BTreeMap<String, String>, f64)]) -> f64 {
    samples.iter().map(|(_, v)| v).sum()
}

#[tokio::test]
async fn a_thousand_paths_produce_only_the_configured_route_labels() {
    let up = upstream().await;
    let mut cfg = base(up);
    cfg.upstreams = vec![UpstreamRoute {
        path: "/api/".into(),
        target: format!("http://{up}"),
        name: "api".into(),
        ..Default::default()
    }];
    cfg.ratelimit.routes = vec![RouteRateLimit {
        path: "/api/login".into(),
        ..Default::default()
    }];
    let (addr, _) = proxy(cfg).await;

    let client = reqwest::Client::new();
    for i in 0..1000 {
        let path = match i % 4 {
            0 => format!("/api/items/{i}"),
            1 => "/api/login".to_string(),
            2 => format!("/random/{}", uuid::Uuid::new_v4().simple()),
            _ => format!("/apiary/{i}?q={i}"),
        };
        assert_eq!(
            client
                .get(format!("http://{addr}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }

    let routes = samples(addr, "edgeguard_route_requests_total").await;
    let labels: BTreeSet<_> = routes.iter().map(|(l, _)| l["route"].clone()).collect();
    assert_eq!(
        labels,
        BTreeSet::from(["api".into(), "/api/login".into(), "default".into()]),
        "one label per configured route, plus default — never a request path"
    );
    let by_route = |name: &str| -> f64 {
        routes
            .iter()
            .filter(|(l, _)| l["route"] == name)
            .map(|(_, v)| v)
            .sum()
    };
    assert_eq!(by_route("api"), 250.0);
    assert_eq!(by_route("/api/login"), 250.0);
    assert_eq!(by_route("default"), 500.0, "/random and /apiary");
    assert!(routes
        .iter()
        .all(|(l, _)| l["method"] == "GET" && l["status_class"] == "2xx"));
    let latency = samples(addr, "edgeguard_route_request_duration_seconds_count").await;
    assert_eq!(sum(&latency), 1000.0);
}

#[tokio::test]
async fn consumers_are_counted_by_principal_with_bytes_on_both_response_paths() {
    for streaming in [false, true] {
        let up = upstream().await;
        let mut cfg = base(up);
        cfg.auth.mode = "apikey".into();
        cfg.auth.api_keys = vec!["key-one".into(), "key-two".into()];
        cfg.validation.stream_responses = streaming;
        let (addr, _) = proxy(cfg).await;

        let client = reqwest::Client::new();
        let send = |key: Option<&'static str>| {
            let mut req = client.get(format!("http://{addr}/things"));
            if let Some(k) = key {
                req = req.header("x-api-key", k);
            }
            async move { req.send().await.unwrap().status().as_u16() }
        };
        for _ in 0..3 {
            assert_eq!(send(Some("key-one")).await, 200);
        }
        for _ in 0..2 {
            assert_eq!(send(Some("key-two")).await, 200);
        }
        for _ in 0..4 {
            assert_eq!(send(None).await, 401);
        }

        let consumers = samples(addr, "edgeguard_consumer_requests_total").await;
        let mut ok: Vec<f64> = consumers
            .iter()
            .filter(|(l, _)| l["consumer"].starts_with("apikey:") && l["status_class"] == "2xx")
            .map(|(_, v)| *v)
            .collect();
        ok.sort_by(f64::total_cmp);
        assert_eq!(ok, [2.0, 3.0], "one series per key, by its id");
        assert!(
            consumers
                .iter()
                .all(|(l, _)| !l["consumer"].contains("key-")),
            "never the key itself"
        );
        assert!(consumers.contains(&(
            BTreeMap::from([
                ("consumer".into(), "_anon".into()),
                ("status_class".into(), "4xx".into())
            ]),
            4.0
        )));
        // Every request is some consumer's, so the totals agree.
        let routes = samples(addr, "edgeguard_route_requests_total").await;
        assert_eq!(sum(&consumers), 9.0);
        assert_eq!(sum(&routes), 9.0);

        let bytes = samples(addr, "edgeguard_consumer_bytes_total").await;
        let out: Vec<f64> = bytes
            .iter()
            .filter(|(l, _)| l["consumer"].starts_with("apikey:") && l["direction"] == "out")
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(out.len(), 2);
        assert!(
            out.iter().all(|v| *v > (2 * BODY.len()) as f64),
            "streaming={streaming}: response bytes counted to the consumer: {out:?}"
        );
    }
}

#[tokio::test]
async fn the_consumer_cap_folds_the_rest_and_zero_turns_consumers_off() {
    let up = upstream().await;
    let mut cfg = base(up);
    cfg.auth.mode = "basic".into();
    cfg.auth.users = (0..10)
        .map(|i| (format!("user{i}"), "pw".to_string()))
        .collect();
    cfg.metrics.consumer_series_max = 3;
    let (addr, _) = proxy(cfg.clone()).await;
    let client = reqwest::Client::new();
    for i in 0..10 {
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("user{i}:pw"));
        let status = client
            .get(format!("http://{addr}/"))
            .header("authorization", format!("Basic {auth}"))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200);
    }
    let consumers = samples(addr, "edgeguard_consumer_requests_total").await;
    let names: BTreeSet<_> = consumers
        .iter()
        .map(|(l, _)| l["consumer"].clone())
        .collect();
    assert_eq!(
        names.len(),
        4,
        "three users and the overflow series: {names:?}"
    );
    assert!(names.contains("_over_cap"));
    assert_eq!(sum(&consumers), 10.0);

    cfg.metrics.consumer_series_max = 0;
    let (addr, _) = proxy(cfg).await;
    let auth = base64::engine::general_purpose::STANDARD.encode("user1:pw");
    client
        .get(format!("http://{addr}/"))
        .header("authorization", format!("Basic {auth}"))
        .send()
        .await
        .unwrap();
    assert!(samples(addr, "edgeguard_consumer_requests_total")
        .await
        .is_empty());
    assert_eq!(
        sum(&samples(addr, "edgeguard_route_requests_total").await),
        1.0,
        "route series are unaffected"
    );
}

#[tokio::test]
async fn route_counters_survive_a_reload() {
    let up = upstream().await;
    let cfg = base(up);
    let (addr, runtime) = proxy(cfg.clone()).await;
    for _ in 0..5 {
        reqwest::get(format!("http://{addr}/")).await.unwrap();
    }
    runtime.store(Arc::new(build_runtime(Arc::new(cfg)).unwrap()));
    reqwest::get(format!("http://{addr}/")).await.unwrap();
    assert_eq!(
        sum(&samples(addr, "edgeguard_route_requests_total").await),
        6.0,
        "a counter that reset on reload would read 1"
    );
}
