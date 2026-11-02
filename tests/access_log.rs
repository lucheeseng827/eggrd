//! The access record (schema 2) through the real pipeline, read back from a stub `[log.ship]`
//! collector: who called, which route and upstream, how long the upstream took, how many bytes,
//! the TLS version and client certificate — and when a streamed response's line is written.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use hyper::body::{Body as HttpBody, Frame};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;
use common::{uri, Ca, Dir};

use edgeguard::config::{Config, LogShipCfg, UpstreamRoute};
use edgeguard::{build_router, build_state};

const CHUNK: &[u8] = b"0123456789abcdef";

/// A response body that sends `left` chunks, one every 150 ms.
struct Dribble {
    left: usize,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl HttpBody for Dribble {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.left == 0 {
            return Poll::Ready(None);
        }
        if self.sleep.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.left -= 1;
        let next = tokio::time::Instant::now() + Duration::from_millis(150);
        self.sleep.as_mut().reset(next);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(CHUNK)))))
    }
}

/// `/slow` answers its headers at once, then three chunks over ~300 ms; anything else answers
/// `hello`.
async fn upstream() -> SocketAddr {
    let app = Router::new()
        .route(
            "/slow",
            get(|| async {
                Body::new(Dribble {
                    left: 3,
                    sleep: Box::pin(tokio::time::sleep(Duration::ZERO)),
                })
            }),
        )
        .fallback(|| async { "hello" });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

type Records = Arc<Mutex<Vec<Value>>>;

/// An NDJSON collector: every record POSTed to it.
async fn collector() -> (String, Records) {
    async fn ingest(State(records): State<Records>, body: String) {
        let mut all = records.lock().unwrap();
        for line in body.lines().filter(|l| !l.is_empty()) {
            all.push(serde_json::from_str(line).unwrap());
        }
    }
    let records: Records = Arc::default();
    let app = Router::new()
        .route("/", post(ingest))
        .with_state(Arc::clone(&records));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, records)
}

fn base(up: SocketAddr, collector: &str) -> Config {
    let mut cfg = Config::default();
    cfg.server.upstream = format!("http://{up}");
    cfg.auth.mode = "none".into();
    cfg.ratelimit.enabled = false;
    cfg.log.ship = LogShipCfg {
        enabled: true,
        url: collector.into(),
        batch: 1,
        interval_secs: 1,
        ..Default::default()
    };
    cfg
}

/// The pipeline's router with a shipper installed, as `main` installs it.
fn app(cfg: Config) -> (Router, watch::Sender<bool>) {
    let state = build_state(Arc::new(cfg.clone())).unwrap();
    let (stop, rx) = watch::channel(false);
    let shipper = edgeguard::logship::spawn(&cfg.log.ship, "edge-test".into(), rx)
        .unwrap()
        .unwrap();
    state.metrics.set_log_shipper(shipper);
    (build_router(state), stop)
}

async fn proxy(cfg: Config) -> (SocketAddr, watch::Sender<bool>) {
    let (app, stop) = app(cfg);
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
    (addr, stop)
}

/// The record whose target is `target`, once the collector has it.
async fn record(records: &Records, target: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(r) = records
                .lock()
                .unwrap()
                .iter()
                .find(|r| r["target"] == target)
            {
                return r.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no record for {target}"))
}

#[tokio::test]
async fn a_proxied_request_says_who_called_which_route_and_upstream() {
    let up = upstream().await;
    let (url, records) = collector().await;
    let mut cfg = base(up, &url);
    cfg.auth.mode = "apikey".into();
    cfg.auth.api_keys = vec!["partner-key".into()];
    cfg.upstreams = vec![UpstreamRoute {
        path: "/api/".into(),
        target: format!("http://user:secret@{up}"),
        name: "api".into(),
        ..Default::default()
    }];
    let (addr, _stop) = proxy(cfg).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/orders?token=abc123secretvalue"))
        .header("x-api-key", "partner-key")
        .header("user-agent", "partner-sdk/2.1")
        .body("{\"qty\":3}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let r = record(&records, "/api/orders?token=<redacted>").await;
    assert_eq!(r["schema"], 2);
    assert_eq!(r["route"], "api");
    assert!(r["principal"].as_str().unwrap().starts_with("apikey:"));
    assert!(!r.to_string().contains("partner-key"), "never the key");
    assert_eq!(r["user_agent"], "partner-sdk/2.1");
    assert_eq!(
        r["upstream"],
        format!("http://127.0.0.1:{}", up.port()),
        "no userinfo"
    );
    assert!(r["upstream_ms"].is_u64());
    assert!(
        r["bytes_in"].as_u64().unwrap() >= 9,
        "the body, and headers"
    );
    assert!(r["bytes_out"].as_u64().unwrap() >= 5);
    assert!(r["tls_version"].is_null() && r["client_cert"].is_null());
    assert_eq!(r["edge_id"], "edge-test");
}

#[tokio::test]
async fn a_request_refused_at_the_edge_has_no_upstream_and_no_caller() {
    let up = upstream().await;
    let (url, records) = collector().await;
    let mut cfg = base(up, &url);
    cfg.auth.mode = "apikey".into();
    cfg.auth.api_keys = vec!["partner-key".into()];
    let (addr, _stop) = proxy(cfg).await;
    let status = reqwest::get(format!("http://{addr}/private"))
        .await
        .unwrap()
        .status();
    assert_eq!(status, 401);
    let r = record(&records, "/private").await;
    assert_eq!(r["outcome"], "unauthorized");
    assert_eq!(r["route"], "default");
    for key in [
        "principal",
        "upstream",
        "upstream_ms",
        "bytes_in",
        "bytes_out",
    ] {
        assert!(r[key].is_null(), "{key}: {r}");
    }
}

#[tokio::test]
async fn a_streamed_response_is_logged_when_its_last_byte_is_sent() {
    let up = upstream().await;
    for streaming in [true, false] {
        let (url, records) = collector().await;
        let mut cfg = base(up, &url);
        cfg.validation.stream_responses = streaming;
        let (addr, _stop) = proxy(cfg).await;

        let body = reqwest::get(format!("http://{addr}/slow"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(body.len(), 3 * CHUNK.len());
        let r = record(&records, "/slow").await;
        let latency = r["latency_ms"].as_u64().unwrap();
        let duration = r["duration_ms"].as_u64().unwrap();
        assert!(
            duration >= 250,
            "streaming={streaming}: the whole body: {r}"
        );
        if streaming {
            // Headers went out at once; the line waited for the body.
            assert!(latency < 250, "{r}");
        } else {
            // Buffered: the edge held the headers until it had the whole body.
            assert!(latency >= 250, "{r}");
        }
        assert!(
            r["bytes_out"].as_u64().unwrap() > (3 * CHUNK.len()) as u64,
            "streaming={streaming}: body and headers counted: {r}"
        );
    }
}

#[tokio::test]
async fn the_principal_can_be_hashed_or_left_out() {
    let up = upstream().await;
    for (mode, check) in [
        (
            "hash",
            Box::new(|p: &Value| p.as_str().unwrap().starts_with("sha256:"))
                as Box<dyn Fn(&Value) -> bool>,
        ),
        ("off", Box::new(|p: &Value| p.is_null())),
    ] {
        let (url, records) = collector().await;
        let mut cfg = base(up, &url);
        cfg.auth.mode = "basic".into();
        cfg.auth.users = [("alice@example.com".to_string(), "pw".to_string())].into();
        cfg.log.principal = toml::Value::String(mode.into()).try_into().unwrap();
        let (addr, _stop) = proxy(cfg).await;
        let status = reqwest::Client::new()
            .get(format!("http://{addr}/me"))
            .basic_auth("alice@example.com", Some("pw"))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200);
        let r = record(&records, "/me").await;
        assert!(check(&r["principal"]), "{mode}: {r}");
        assert!(!r.to_string().contains("alice"), "{mode}: {r}");
    }
}

#[tokio::test]
async fn an_mtls_request_records_the_tls_version_and_the_client_certificate() {
    edgeguard::tls::init_crypto();
    let dir = Dir::new();
    let (server_ca, client_ca) = (Ca::new("server"), Ca::new("client"));
    let up = upstream().await;
    let (url, records) = collector().await;
    let mut cfg = base(up, &url);
    cfg.tls.enabled = true;
    cfg.tls.client_auth.mode = "required".into();
    cfg.tls.client_auth.ca_path = dir.write("client-ca.pem", &client_ca.pem);
    cfg.auth.mode = "mtls".into();

    let client_auth = edgeguard::client_auth::ClientAuth::from_cfg(&cfg.tls)
        .unwrap()
        .unwrap();
    let (cert, key) = dir.pair("server", &server_ca.server(&["localhost"]));
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    let tls = edgeguard::tls::server_config_with_client_auth(store, Some(client_auth)).unwrap();
    let (router, _stop) = app(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_stop_listener, rx) = watch::channel(false);
    tokio::spawn(edgeguard::serve::serve(
        listener,
        Some(tls),
        router,
        edgeguard::serve::ServeOpts::default(),
        rx,
    ));

    let leaf = client_ca.client_with(vec![uri("spiffe://prod.example/ns/web/frontend")], "web", 9);
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(server_ca.pem.as_bytes()).unwrap())
        .identity(reqwest::Identity::from_pem(&leaf.identity_pem()).unwrap())
        .build()
        .unwrap();
    let status = client
        .get(format!("https://localhost:{}/hello", addr.port()))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 200);

    let r = record(&records, "/hello").await;
    assert_eq!(r["tls_version"], "TLSv1.3");
    assert_eq!(r["client_cert"], "spiffe://prod.example/ns/web/frontend");
    assert_eq!(r["principal"], "spiffe://prod.example/ns/web/frontend");
}
