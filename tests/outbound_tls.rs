//! Every HTTP client the edge makes itself — access-log shipping, request tracing, OTLP metrics,
//! the JWKS fetch, the alert webhook, LLM telemetry — against an endpoint behind a private CA that
//! requires a client certificate. Each reaches it only with its own section's `ca_path` and client
//! certificate, so a client that ignored its settings would deliver nothing here.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::OriginalUri;
use axum::http::Method;
use axum::response::IntoResponse;
use axum::{Extension, Router};
use base64::Engine;
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;
use common::{connect_proxy, Ca, Dir};

use edgeguard::client_auth::{ClientAuth, ClientCert};
use edgeguard::config::{Config, OutboundCfg, TlsCfg};
use edgeguard::{build_router, build_state};

/// One request the endpoint answered: method, path, the client certificate's name, the body.
#[derive(Debug, Clone)]
struct Hit {
    method: String,
    path: String,
    cert: String,
    body: String,
}

type Hits = Arc<Mutex<Vec<Hit>>>;

struct Endpoint {
    base: String,
    port: u16,
    hits: Hits,
    _stop: watch::Sender<bool>,
}

/// A collector on TLS for `localhost`, its certificate from `server_ca`, requiring a client
/// certificate from `edge_ca`, on rustls's server defaults. It records every request and answers
/// `200` — with `jwks` on `GET /jwks`, `{}` otherwise.
async fn endpoint(dir: &Dir, server_ca: &Ca, edge_ca: &Ca, jwks: &str) -> Endpoint {
    edgeguard::tls::init_crypto();
    let hits: Hits = Arc::default();
    let seen = Arc::clone(&hits);
    let jwks = jwks.to_string();
    let app = Router::new().fallback(
        move |method: Method,
              OriginalUri(uri): OriginalUri,
              cert: Option<Extension<Arc<ClientCert>>>,
              body: String| {
            let seen = Arc::clone(&seen);
            let jwks = jwks.clone();
            async move {
                let cert = cert
                    .and_then(|Extension(c)| c.identities().next().map(str::to_string))
                    .unwrap_or_else(|| "-".into());
                seen.lock().unwrap().push(Hit {
                    method: method.to_string(),
                    path: uri.path().to_string(),
                    cert,
                    body,
                });
                if uri.path() == "/jwks" {
                    jwks.into_response()
                } else {
                    "{}".into_response()
                }
            }
        },
    );

    let tls = TlsCfg {
        enabled: true,
        client_auth: edgeguard::config::ClientAuthCfg {
            mode: "required".into(),
            ca_path: dir.write("edge-ca.pem", &edge_ca.pem),
            ..Default::default()
        },
        ..Default::default()
    };
    let client_auth = ClientAuth::from_cfg(&tls).unwrap().unwrap();
    let (cert, key) = dir.pair("endpoint", &server_ca.server(&["localhost"]));
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_client_cert_verifier(client_auth)
    .with_cert_resolver(store);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(edgeguard::serve::serve(
        listener,
        Some(Arc::new(config)),
        app,
        edgeguard::serve::ServeOpts::default(),
        rx,
    ));
    Endpoint {
        base: format!("https://localhost:{port}"),
        port,
        hits,
        _stop: stop,
    }
}

/// The PKI of one test: the endpoint's CA, the edges' CA, and the settings that trust the one and
/// present a certificate (`edge-1`) from the other.
struct Pki {
    dir: Dir,
    server_ca: Ca,
    edge_ca: Ca,
    outbound: OutboundCfg,
}

fn pki() -> Pki {
    let dir = Dir::new();
    let (server_ca, edge_ca) = (Ca::new("collector CA"), Ca::new("edge CA"));
    let (cert, key) = dir.pair("edge", &edge_ca.client("edge-1"));
    let outbound = OutboundCfg {
        ca_path: dir.write("collector-ca.pem", &server_ca.pem),
        client_cert_path: cert,
        client_key_path: key,
        ..Default::default()
    };
    Pki {
        dir,
        server_ca,
        edge_ca,
        outbound,
    }
}

/// The requests to `path` once there is at least one, or none after 5 s.
async fn hits_to(hits: &Hits, path: &str) -> Vec<Hit> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let found: Vec<Hit> = hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.path == path)
            .cloned()
            .collect();
        if !found.is_empty() || tokio::time::Instant::now() > deadline {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn upstream() -> SocketAddr {
    let app = Router::new().fallback(|| async { "hello" });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// The pipeline on a plain listener, with the log and span shippers `main` would start.
async fn proxy(cfg: Config) -> (SocketAddr, watch::Sender<bool>) {
    let state = build_state(Arc::new(cfg.clone())).unwrap();
    let (stop, rx) = watch::channel(false);
    if let Some(s) = edgeguard::logship::spawn(&cfg.log.ship, "edge".into(), rx.clone()).unwrap() {
        state.metrics.set_log_shipper(s);
    }
    if let Some(s) = edgeguard::telemetry::spawn_span_shipper(&cfg.tracing, rx).unwrap() {
        state.metrics.set_span_shipper(s);
    }
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
    (addr, stop)
}

fn base(up: SocketAddr) -> Config {
    let mut cfg = Config::default();
    cfg.server.upstream = format!("http://{up}");
    cfg.auth.mode = "none".into();
    cfg.ratelimit.enabled = false;
    cfg
}

#[tokio::test]
async fn access_logs_and_spans_reach_a_collector_on_a_private_ca() {
    let p = pki();
    let collector = endpoint(&p.dir, &p.server_ca, &p.edge_ca, "").await;
    let mut cfg = base(upstream().await);
    cfg.log.ship.enabled = true;
    cfg.log.ship.url = format!("{}/logs", collector.base);
    cfg.log.ship.batch = 1;
    cfg.log.ship.interval_secs = 1;
    cfg.log.ship.outbound = p.outbound.clone();
    cfg.tracing.enabled = true;
    cfg.tracing.endpoint = format!("{}/v1/traces", collector.base);
    cfg.tracing.batch = 1;
    cfg.tracing.interval_secs = 1;
    cfg.tracing.outbound = p.outbound.clone();
    let (addr, _stop) = proxy(cfg).await;

    let status = reqwest::get(format!("http://{addr}/orders"))
        .await
        .unwrap()
        .status();
    assert_eq!(status, 200);

    let logs = hits_to(&collector.hits, "/logs").await;
    assert!(!logs.is_empty(), "no access record arrived");
    assert!(logs
        .iter()
        .all(|h| h.cert == "edge-1" && h.method == "POST"));
    assert!(
        logs[0].body.contains("\"target\":\"/orders\""),
        "{}",
        logs[0].body
    );
    let spans = hits_to(&collector.hits, "/v1/traces").await;
    assert!(!spans.is_empty(), "no span arrived");
    assert!(spans.iter().all(|h| h.cert == "edge-1"));
    assert!(spans[0].body.contains("resourceSpans"), "{}", spans[0].body);
}

#[tokio::test]
async fn otlp_metrics_reach_a_collector_on_a_private_ca() {
    let p = pki();
    let collector = endpoint(&p.dir, &p.server_ca, &p.edge_ca, "").await;
    let cfg = edgeguard::config::OtlpMetricsCfg {
        enabled: true,
        endpoint: format!("{}/v1/metrics", collector.base),
        // Only the push on shutdown, so the test does not wait an interval.
        interval_secs: 3600,
        outbound: p.outbound.clone(),
        ..Default::default()
    };
    let (stop, rx) = watch::channel(false);
    let task = edgeguard::otlp_metrics::spawn_exporter(
        &cfg,
        Arc::new(edgeguard::metrics::Metrics::new()),
        rx,
    )
    .unwrap()
    .expect("enabled");
    stop.send(true).unwrap();
    task.await.unwrap();
    let pushes = hits_to(&collector.hits, "/v1/metrics").await;
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].cert, "edge-1");
    assert!(pushes[0].body.contains("resourceMetrics"));
}

#[tokio::test]
async fn a_jwks_behind_a_private_ca_verifies_tokens() {
    let p = pki();
    // An ES256 signing key, and the JWKS that publishes it.
    let key = rcgen::KeyPair::generate().unwrap();
    let raw = key.public_key_raw();
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let jwks = serde_json::json!({ "keys": [{
        "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
        "x": b64(&raw[1..33]), "y": b64(&raw[33..65]),
    }]})
    .to_string();
    let idp = endpoint(&p.dir, &p.server_ca, &p.edge_ca, &jwks).await;
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header {
            kid: Some("k1".into()),
            ..jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256)
        },
        &serde_json::json!({ "sub": "alice", "exp": 4_102_444_800u64 }),
        &jsonwebtoken::EncodingKey::from_ec_pem(key.serialize_pem().as_bytes()).unwrap(),
    )
    .unwrap();

    let up = upstream().await;
    let call = |outbound: OutboundCfg| {
        let mut cfg = base(up);
        cfg.auth.mode = "jwt".into();
        cfg.auth.jwt.algorithm = "ES256".into();
        cfg.auth.jwt.jwks_url = format!("{}/jwks", idp.base);
        cfg.auth.jwt.outbound = outbound;
        let token = token.clone();
        async move {
            let (addr, _stop) = proxy(cfg).await;
            reqwest::Client::new()
                .get(format!("http://{addr}/me"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(call(p.outbound.clone()).await, 200);
    let fetches = hits_to(&idp.hits, "/jwks").await;
    assert_eq!(fetches.len(), 1, "fetched once, then cached");
    assert_eq!(fetches[0].cert, "edge-1");

    // Without the CA the keys cannot be fetched, so no token verifies.
    let no_ca = OutboundCfg {
        ca_path: String::new(),
        ..p.outbound.clone()
    };
    assert_eq!(call(no_ca).await, 401);
    assert_eq!(hits_to(&idp.hits, "/jwks").await.len(), 1);
}

#[tokio::test]
async fn alerts_and_llm_telemetry_reach_their_endpoints_on_a_private_ca() {
    let p = pki();
    let hook = endpoint(&p.dir, &p.server_ca, &p.edge_ca, "").await;

    let alerts = edgeguard::alert::AlertRuntime::build(&edgeguard::config::AlertsCfg {
        enabled: true,
        webhook_url: format!("{}/alert", hook.base),
        outbound: p.outbound.clone(),
        ..Default::default()
    })
    .unwrap();
    alerts.fire_budget_alert("monthly", 0.95);
    let fired = hits_to(&hook.hits, "/alert").await;
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0].cert, "edge-1");
    assert!(fired[0].body.contains("monthly"));

    let telemetry =
        edgeguard::telemetry::TelemetryRuntime::build(&edgeguard::config::TelemetryCfg {
            enabled: true,
            endpoint: format!("{}/llm/v1/traces", hook.base),
            outbound: p.outbound.clone(),
            ..Default::default()
        })
        .unwrap();
    telemetry.emit(edgeguard::telemetry::SpanRecord {
        ctx: edgeguard::telemetry::TraceContext::from_traceparent(None),
        name: "chat gpt-test".into(),
        model: "gpt-test".into(),
        provider: None,
        prompt_tokens: 3,
        completion_tokens: 5,
        cached_tokens: 0,
        reasoning_tokens: 0,
        cost_micros: None,
        start_unix_nano: 1,
        end_unix_nano: 2,
        ttft: None,
        tpot: None,
        status_ok: true,
        input: None,
        output: None,
        session_id: None,
    });
    let spans = hits_to(&hook.hits, "/llm/v1/traces").await;
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].cert, "edge-1");
    assert!(spans[0].body.contains("gpt-test"));
}

/// A client that pushes often never lets a keep-alive connection go idle, so if it pooled
/// connections it would go on presenting the certificate it opened the first one with.
#[tokio::test]
async fn a_rotated_certificate_reaches_a_client_that_was_already_connected() {
    let p = pki();
    let hook = endpoint(&p.dir, &p.server_ca, &p.edge_ca, "").await;
    let alerts = edgeguard::alert::AlertRuntime::build(&edgeguard::config::AlertsCfg {
        enabled: true,
        webhook_url: format!("{}/alert", hook.base),
        outbound: p.outbound.clone(),
        ..Default::default()
    })
    .unwrap();
    alerts.fire_budget_alert("first", 0.95);
    assert_eq!(hits_to(&hook.hits, "/alert").await.len(), 1);
    // Long enough for the first connection to be back in a pool, if there were one.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // What the watcher in `main` does when the files change.
    p.dir.pair("edge", &p.edge_ca.client("edge-1-rotated"));
    edgeguard::outbound::identity(
        &p.outbound.client_cert_path,
        &p.outbound.client_key_path,
        "test",
    )
    .unwrap()
    .unwrap()
    .store()
    .reload()
    .unwrap();
    alerts.fire_budget_alert("second", 0.95);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while hits_to(&hook.hits, "/alert").await.len() < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let names: Vec<String> = hits_to(&hook.hits, "/alert")
        .await
        .into_iter()
        .map(|h| h.cert)
        .collect();
    assert_eq!(names, ["edge-1", "edge-1-rotated"]);
}

#[tokio::test]
async fn a_collector_is_reached_through_the_configured_proxy() {
    let p = pki();
    let collector = endpoint(&p.dir, &p.server_ca, &p.edge_ca, "").await;
    let (proxy_addr, connects) = connect_proxy().await;
    let mut cfg = base(upstream().await);
    cfg.log.ship.enabled = true;
    cfg.log.ship.url = format!("{}/logs", collector.base);
    cfg.log.ship.batch = 1;
    cfg.log.ship.interval_secs = 1;
    cfg.log.ship.outbound = OutboundCfg {
        proxy: format!("http://{proxy_addr}"),
        ..p.outbound.clone()
    };
    let (addr, _stop) = proxy(cfg).await;
    reqwest::get(format!("http://{addr}/")).await.unwrap();

    let logs = hits_to(&collector.hits, "/logs").await;
    assert!(!logs.is_empty());
    assert_eq!(logs[0].cert, "edge-1", "TLS end to end through the tunnel");
    let connects = connects.lock().unwrap().clone();
    assert_eq!(
        connects[0].0,
        format!("CONNECT localhost:{} HTTP/1.1", collector.port)
    );
    assert_eq!(connects[0].1, None, "no credentials in the URL, none sent");
}

/// `[outbound]` written once, in a config file: the sections that set nothing take its CA, its
/// client certificate and its proxy; one that sets its own proxy keeps it.
#[tokio::test]
async fn outbound_defaults_reach_the_sections_that_set_nothing() {
    let p = pki();
    let collector = endpoint(&p.dir, &p.server_ca, &p.edge_ca, "").await;
    let (proxy_addr, connects) = connect_proxy().await;
    let up = upstream().await;
    let file = p.dir.write(
        "edgeguard.toml",
        &format!(
            "[server]\nupstream = \"http://{up}\"\n\n[auth]\nmode = \"none\"\n\n\
             [ratelimit]\nenabled = false\n\n\
             [outbound]\nextra_ca_path = {ca:?}\nclient_cert_path = {cert:?}\n\
             client_key_path = {key:?}\nproxy = \"http://{proxy_addr}\"\n\n\
             [log.ship]\nenabled = true\nurl = \"{base}/logs\"\nbatch = 1\ninterval_secs = 1\n\n\
             [alerts]\nenabled = true\nwebhook_url = \"{base}/alert\"\nproxy = \"none\"\n",
            ca = p.outbound.ca_path,
            cert = p.outbound.client_cert_path,
            key = p.outbound.client_key_path,
            base = collector.base,
        ),
    );
    let cfg = Config::load(Some(&file)).unwrap();
    assert!(
        cfg.log.ship.outbound.ca_path.is_empty(),
        "nothing in the section itself"
    );

    let (addr, _stop) = proxy(cfg.clone()).await;
    reqwest::get(format!("http://{addr}/orders")).await.unwrap();
    let logs = hits_to(&collector.hits, "/logs").await;
    assert!(!logs.is_empty(), "no access record arrived");
    assert_eq!(
        logs[0].cert, "edge-1",
        "the inherited certificate, over the inherited CA"
    );
    assert_eq!(
        connects.lock().unwrap()[0].0,
        format!("CONNECT localhost:{} HTTP/1.1", collector.port),
        "through the inherited proxy"
    );

    let tunnels = connects.lock().unwrap().len();
    let alerts = edgeguard::alert::AlertRuntime::build(&cfg.alerts).unwrap();
    alerts.fire_budget_alert("monthly", 0.95);
    let fired = hits_to(&collector.hits, "/alert").await;
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0].cert, "edge-1");
    assert_eq!(
        connects.lock().unwrap().len(),
        tunnels,
        "proxy = \"none\" in [alerts] went direct"
    );

    // A section's own ca_path replaces the inherited trust: here, a CA that did not sign the
    // collector, so nothing is delivered.
    let mut own = cfg.alerts.clone();
    own.outbound.ca_path = p.dir.write("wrong-ca.pem", &p.edge_ca.pem);
    let alerts = edgeguard::alert::AlertRuntime::build(&own).unwrap();
    alerts.fire_budget_alert("wrong-ca", 0.95);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !collector
            .hits
            .lock()
            .unwrap()
            .iter()
            .any(|h| h.body.contains("wrong-ca")),
        "a section's ca_path is the only trust it has"
    );
}

#[tokio::test]
async fn a_collector_setting_that_does_not_load_fails_where_main_starts_it() {
    let mut cfg = Config::default();
    cfg.log.ship.enabled = true;
    cfg.log.ship.url = "https://collector.internal/logs".into();
    cfg.log.ship.outbound.ca_path = "/no/such/ca.pem".into();
    let (_stop, rx) = watch::channel(false);
    let e = edgeguard::logship::spawn(&cfg.log.ship, "edge".into(), rx)
        .err()
        .expect("an unloadable CA is an error, not a shipper that silently never ships");
    assert!(format!("{e:#}").contains("log.ship.ca_path"), "{e:#}");
}
