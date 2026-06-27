//! Integration tests: drive the real proxy pipeline (`build_state` + `build_router`, the
//! same entry points the binary uses) against an in-process stub upstream, and assert the
//! end-to-end request/response behavior.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response, StatusCode},
    routing::any,
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use tokio::net::TcpListener;

use edgeguard::config::{
    AuthCfg, Config, CorsCfg, HeadersCfg, JwtCfg, PerKeyRateLimit, RateLimitCfg, RouteRateLimit,
    ServerCfg, UpstreamRoute, WafCfg, WafRule,
};
use edgeguard::{build_admin_router, build_public_router, build_router, build_state};

/// Stub upstream: 200 + a body, plus a `Set-Cookie` and the leaky headers EdgeGuard should
/// harden/strip on the way back out.
async fn spawn_upstream() -> SocketAddr {
    async fn handler() -> Response<Body> {
        let mut resp = Response::new(Body::from("hello from upstream"));
        let h = resp.headers_mut();
        h.insert(header::SET_COOKIE, HeaderValue::from_static("sid=abc123"));
        h.insert("server", HeaderValue::from_static("UpstreamServer/9.9"));
        h.insert("x-powered-by", HeaderValue::from_static("Express"));
        resp
    }
    let app = Router::new().fallback(any(handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Spawn EdgeGuard with `cfg`; return its bound address.
async fn spawn_proxy(cfg: Config) -> SocketAddr {
    let state = build_state(Arc::new(cfg)).unwrap();
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
    addr
}

/// Spawn EdgeGuard with `cfg`, returning its address **and** a handle to the shared quota verdict,
/// so a test can flip `over_quota` and assert the proxy's hard-stop gate.
async fn spawn_proxy_with_quota(cfg: Config) -> (SocketAddr, Arc<edgeguard::cp::QuotaState>) {
    let state = build_state(Arc::new(cfg)).unwrap();
    let quota = state.quota.clone();
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
    (addr, quota)
}

/// Stub upstream that sleeps `delay` before responding, to exercise the upstream timeout.
async fn spawn_slow_upstream(delay: Duration) -> SocketAddr {
    let app = Router::new().fallback(any(move || async move {
        tokio::time::sleep(delay).await;
        "slow"
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A port nothing is listening on (bind then drop), to simulate a down upstream.
async fn dead_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}

/// Baseline config: Basic auth with one user, rate limiting off (so a shared limiter token
/// can't make assertions flaky — the 429 test turns it on explicitly).
fn base_cfg(upstream: String) -> Config {
    Config {
        server: ServerCfg {
            upstream,
            ..Default::default()
        },
        auth: AuthCfg {
            mode: "basic".into(),
            users: BTreeMap::from([("admin".to_string(), "secret".to_string())]),
            ..Default::default()
        },
        ratelimit: RateLimitCfg {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", B64.encode(format!("{user}:{pass}")))
}

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

async fn send(addr: SocketAddr, method: &str, path: &str, auth: Option<&str>, body: Bytes) -> Resp {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"));
    if let Some(a) = auth {
        builder = builder.header(header::AUTHORIZATION, a);
    }
    let req = builder.body(Full::new(body)).unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
    }
}

async fn get(addr: SocketAddr, auth: Option<&str>) -> Resp {
    send(addr, "GET", "/", auth, Bytes::new()).await
}

/// The opt-in managed-mode quota hard-stop: when the shared verdict flips to over-quota, the proxy
/// returns `429` (with a `Retry-After` hint) for the tenant's traffic, while the internal ops
/// endpoints keep serving; clearing the verdict restores service.
#[tokio::test]
async fn over_quota_hard_stops_with_429() {
    use std::sync::atomic::Ordering;

    let upstream = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{upstream}"));
    cfg.control_plane.enforce_quota = true;
    let (addr, quota) = spawn_proxy_with_quota(cfg).await;

    // Under quota -> authenticated request proxies normally.
    let ok = get(addr, Some(&basic("admin", "secret"))).await;
    assert_eq!(ok.status, StatusCode::OK);

    // Over quota -> hard stop, before auth even (the whole tenant is paused), with a reset hint.
    quota.over_quota.store(true, Ordering::Relaxed);
    quota.reset_epoch.store(4_000_000_000, Ordering::Relaxed);
    let blocked = get(addr, Some(&basic("admin", "secret"))).await;
    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers.get(header::RETRY_AFTER).is_some());
    // Even an unauthenticated request is paused (the gate runs before auth).
    assert_eq!(get(addr, None).await.status, StatusCode::TOO_MANY_REQUESTS);

    // Ops endpoints are exempt — health checks must not flap when a tenant is over quota.
    let health = send(addr, "GET", "/__edgeguard/health", None, Bytes::new()).await;
    assert_eq!(health.status, StatusCode::OK);

    // Clearing the verdict (next successful poll) restores normal service.
    quota.over_quota.store(false, Ordering::Relaxed);
    let restored = get(addr, Some(&basic("admin", "secret"))).await;
    assert_eq!(restored.status, StatusCode::OK);
}

/// With `enforce_quota` off (the default), an over-quota verdict is ignored — metering without a cap.
#[tokio::test]
async fn quota_not_enforced_when_disabled() {
    use std::sync::atomic::Ordering;

    let upstream = spawn_upstream().await;
    let cfg = base_cfg(format!("http://{upstream}")); // enforce_quota defaults to false
    let (addr, quota) = spawn_proxy_with_quota(cfg).await;
    quota.over_quota.store(true, Ordering::Relaxed);
    // The gate is inert, so the request still proxies.
    assert_eq!(
        get(addr, Some(&basic("admin", "secret"))).await.status,
        StatusCode::OK
    );
}

/// Send a request with arbitrary headers (for the API-key / JWT / header-size tests).
async fn send_with_headers(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Bytes,
) -> Resp {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let req = builder.body(Full::new(body)).unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let rheaders = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        headers: rheaders,
        body: String::from_utf8_lossy(&bytes).to_string(),
    }
}

/// Sign an HS256 JWT for the JWT-gate test.
fn sign_hs256(secret: &str, claims: serde_json::Value) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn far_future() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600
}

#[tokio::test]
async fn api_key_gate_accepts_known_keys_only() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth = AuthCfg {
        mode: "apikey".into(),
        api_keys: vec!["sk_test_123".into()],
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;

    // No key -> 401.
    assert_eq!(get(proxy, None).await.status, StatusCode::UNAUTHORIZED);
    // Custom header.
    assert_eq!(
        send_with_headers(
            proxy,
            "GET",
            "/",
            &[("x-api-key", "sk_test_123")],
            Bytes::new()
        )
        .await
        .status,
        StatusCode::OK
    );
    // Authorization: Bearer.
    assert_eq!(
        send_with_headers(
            proxy,
            "GET",
            "/",
            &[("authorization", "Bearer sk_test_123")],
            Bytes::new()
        )
        .await
        .status,
        StatusCode::OK
    );
    // Wrong key -> 401.
    assert_eq!(
        send_with_headers(proxy, "GET", "/", &[("x-api-key", "wrong")], Bytes::new())
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn jwt_gate_hs256_validates_bearer_tokens() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth = AuthCfg {
        mode: "jwt".into(),
        jwt: JwtCfg {
            algorithm: "HS256".into(),
            secret: "integration-secret".into(),
            issuer: "edgeguard-it".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;

    // Missing token -> 401 with a Bearer challenge.
    let none = get(proxy, None).await;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        none.headers.get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer"
    );

    // Valid token -> 200.
    let token = sign_hs256(
        "integration-secret",
        json!({ "sub": "alice", "iss": "edgeguard-it", "exp": far_future() }),
    );
    assert_eq!(
        send_with_headers(
            proxy,
            "GET",
            "/",
            &[("authorization", &format!("Bearer {token}"))],
            Bytes::new()
        )
        .await
        .status,
        StatusCode::OK
    );

    // Token signed with the wrong secret -> 401.
    let forged = sign_hs256(
        "not-the-secret",
        json!({ "sub": "mallory", "iss": "edgeguard-it", "exp": far_future() }),
    );
    assert_eq!(
        send_with_headers(
            proxy,
            "GET",
            "/",
            &[("authorization", &format!("Bearer {forged}"))],
            Bytes::new()
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn per_route_rate_limit_overrides_global() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth = AuthCfg {
        mode: "none".into(),
        ..Default::default()
    };
    // Generous global limit, strict override on /api/.
    cfg.ratelimit = RateLimitCfg {
        enabled: true,
        rate: "1000/min".into(),
        burst: 1000,
        routes: vec![RouteRateLimit {
            path: "/api/".into(),
            rate: "1/min".into(),
            burst: 1,
        }],
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;

    // /api/ is capped at a burst of 1.
    assert_eq!(
        send(proxy, "GET", "/api/x", None, Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(proxy, "GET", "/api/x", None, Bytes::new())
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // A non-/api/ path uses the generous global limit and still passes.
    assert_eq!(
        send(proxy, "GET", "/public", None, Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn per_key_rate_limit_is_keyed_by_principal() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth = AuthCfg {
        mode: "apikey".into(),
        api_keys: vec!["key-a".into(), "key-b".into()],
        ..Default::default()
    };
    cfg.ratelimit = RateLimitCfg {
        enabled: true,
        rate: "1000/min".into(), // generous per-IP so only the per-key cap trips
        burst: 1000,
        per_key: PerKeyRateLimit {
            enabled: true,
            rate: "1/min".into(),
            burst: 1,
        },
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;

    // key-a: first request OK, second rejected by its own per-key bucket.
    assert_eq!(
        send_with_headers(proxy, "GET", "/", &[("x-api-key", "key-a")], Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send_with_headers(proxy, "GET", "/", &[("x-api-key", "key-a")], Bytes::new())
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // key-b has an independent bucket and is unaffected.
    assert_eq!(
        send_with_headers(proxy, "GET", "/", &[("x-api-key", "key-b")], Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn max_header_bytes_rejects_oversized_headers() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth = AuthCfg {
        mode: "none".into(),
        ..Default::default()
    };
    cfg.validation.max_header_bytes = "256B".into();
    let proxy = spawn_proxy(cfg).await;

    // A minimal request is comfortably under the cap.
    assert_eq!(get(proxy, None).await.status, StatusCode::OK);
    // A single oversized header trips the cap -> 431.
    let big = "a".repeat(400);
    assert_eq!(
        send_with_headers(proxy, "GET", "/", &[("x-pad", big.as_str())], Bytes::new())
            .await
            .status,
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
}

#[tokio::test]
async fn csp_report_only_header_and_report_uri() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.headers = HeadersCfg {
        csp: "default-src 'self'".into(),
        csp_report_only: true,
        csp_report_uri: "/__edgeguard/csp-report".into(),
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;
    let r = get(proxy, Some(&basic("admin", "secret"))).await;
    assert_eq!(r.status, StatusCode::OK);

    // Report-only: the enforcing header is absent, the report-only one present and carries the
    // appended report-uri directive.
    assert!(!r.headers.contains_key("content-security-policy"));
    let cspro = r
        .headers
        .get("content-security-policy-report-only")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cspro.contains("default-src 'self'"), "{cspro}");
    assert!(
        cspro.contains("report-uri /__edgeguard/csp-report"),
        "{cspro}"
    );
}

#[tokio::test]
async fn csp_report_sink_accepts_and_counts_reports() {
    let up = spawn_upstream().await;
    let proxy = spawn_proxy(base_cfg(format!("http://{up}"))).await;

    let report = r#"{"csp-report":{"violated-directive":"script-src","blocked-uri":"https://evil.example"}}"#;
    let r = send(
        proxy,
        "POST",
        "/__edgeguard/csp-report",
        None,
        Bytes::from_static(report.as_bytes()),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    // The metrics endpoint reflects the received report.
    let m = send(proxy, "GET", "/__edgeguard/metrics", None, Bytes::new()).await;
    assert_eq!(m.status, StatusCode::OK);
    assert!(
        m.body.contains("edgeguard_csp_reports_total 1"),
        "{}",
        m.body
    );
}

#[tokio::test]
async fn metrics_endpoint_exposes_request_counters() {
    let up = spawn_upstream().await;
    let proxy = spawn_proxy(base_cfg(format!("http://{up}"))).await;

    // Drive one authorized request through the pipeline.
    assert_eq!(
        get(proxy, Some(&basic("admin", "secret"))).await.status,
        StatusCode::OK
    );

    let m = send(proxy, "GET", "/__edgeguard/metrics", None, Bytes::new()).await;
    assert_eq!(m.status, StatusCode::OK);
    assert!(
        m.headers
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("version=0.0.4"),
        "wrong content-type"
    );
    assert!(
        m.body.contains("edgeguard_requests_total{outcome=\"ok\"}"),
        "{}",
        m.body
    );
    assert!(
        m.body.contains("edgeguard_request_duration_seconds_bucket"),
        "{}",
        m.body
    );
}

#[tokio::test]
async fn unauthorized_without_credentials() {
    let up = spawn_upstream().await;
    let proxy = spawn_proxy(base_cfg(format!("http://{up}"))).await;
    let r = get(proxy, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.headers.contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn ok_with_credentials_and_hardened_response() {
    let up = spawn_upstream().await;
    let proxy = spawn_proxy(base_cfg(format!("http://{up}"))).await;
    let r = get(proxy, Some(&basic("admin", "secret"))).await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, "hello from upstream");

    // injected security headers
    assert_eq!(r.headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(r.headers.get("x-frame-options").unwrap(), "DENY");
    assert!(r.headers.contains_key("content-security-policy"));
    assert!(r.headers.contains_key("strict-transport-security"));
    assert!(r.headers.contains_key("referrer-policy"));
    assert!(r.headers.contains_key("permissions-policy"));

    // leaky upstream headers stripped
    assert!(!r.headers.contains_key("server"));
    assert!(!r.headers.contains_key("x-powered-by"));

    // cookie hardened
    let cookie = r.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(cookie.contains("sid=abc123"), "{cookie}");
    assert!(cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite"), "{cookie}");
}

/// The static-host `_headers` generator (Phase 5) must emit exactly the response-hardening
/// headers the live proxy injects — both go through `proxy::security_headers`. This guards
/// against the generated edge config drifting from runtime behavior.
#[tokio::test]
async fn generated_headers_file_matches_proxy_injected_headers() {
    use edgeguard::generate::{generate, Target};

    // Parse the generated `_headers` body into name(lowercased) -> value. Header lines are
    // indented two spaces ("  Name: Value"); comment lines and the `/*` glob are skipped.
    let cfg = base_cfg(String::new());
    let generated = generate(&cfg, Target::Headers);
    let mut want: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in generated.lines() {
        if let Some(rest) = line.strip_prefix("  ") {
            if let Some((name, value)) = rest.split_once(": ") {
                want.insert(name.to_ascii_lowercase(), value.to_string());
            }
        }
    }
    assert!(
        !want.is_empty(),
        "generator produced no headers:\n{generated}"
    );

    // Compare against what the live proxy actually sets on a real response.
    let up = spawn_upstream().await;
    let proxy = spawn_proxy(base_cfg(format!("http://{up}"))).await;
    let r = get(proxy, Some(&basic("admin", "secret"))).await;
    assert_eq!(r.status, StatusCode::OK);
    for (name, value) in &want {
        let got = r
            .headers
            .get(name)
            .unwrap_or_else(|| panic!("proxy did not set generated header {name}"));
        assert_eq!(got.to_str().unwrap(), value, "value mismatch for {name}");
    }
}

#[tokio::test]
async fn too_many_requests_over_the_limit() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.ratelimit = RateLimitCfg {
        enabled: true,
        rate: "1/min".into(),
        burst: 1,
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;
    let auth = basic("admin", "secret");

    // burst of 1: the first request consumes the only cell, the second is rejected.
    assert_eq!(get(proxy, Some(&auth)).await.status, StatusCode::OK);
    assert_eq!(
        get(proxy, Some(&auth)).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn payload_too_large_over_body_limit() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.validation.max_body = "8B".into();
    let proxy = spawn_proxy(cfg).await;

    let r = send(
        proxy,
        "POST",
        "/",
        Some(&basic("admin", "secret")),
        Bytes::from_static(b"way more than eight bytes"),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn method_not_allowed_when_not_in_allowlist() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.validation.allow_methods = vec!["GET".into()];
    let proxy = spawn_proxy(cfg).await;

    let r = send(
        proxy,
        "DELETE",
        "/",
        Some(&basic("admin", "secret")),
        Bytes::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn bad_gateway_when_upstream_down() {
    let proxy = spawn_proxy(base_cfg(format!("http://{}", dead_addr().await))).await;
    let r = get(proxy, Some(&basic("admin", "secret"))).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn gateway_timeout_when_upstream_stalls() {
    // Upstream sleeps far longer than the configured timeout -> 504, not a hang.
    let up = spawn_slow_upstream(Duration::from_secs(30)).await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.validation.upstream_timeout = "100ms".into();
    let proxy = spawn_proxy(cfg).await;
    let r = get(proxy, Some(&basic("admin", "secret"))).await;
    assert_eq!(r.status, StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn health_is_always_ok() {
    let up = spawn_upstream().await;
    let proxy = spawn_proxy(base_cfg(format!("http://{up}"))).await;
    let r = send(proxy, "GET", "/__edgeguard/health", None, Bytes::new()).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, "ok");
}

#[tokio::test]
async fn readiness_reflects_upstream_reachability() {
    // Up: probe succeeds -> 200.
    let up = spawn_upstream().await;
    let proxy = spawn_proxy(base_cfg(format!("http://{up}"))).await;
    let r = send(proxy, "GET", "/__edgeguard/ready", None, Bytes::new()).await;
    assert_eq!(r.status, StatusCode::OK);

    // Down: probe fails -> 503.
    let proxy_down = spawn_proxy(base_cfg(format!("http://{}", dead_addr().await))).await;
    let r = send(proxy_down, "GET", "/__edgeguard/ready", None, Bytes::new()).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
}

/// Baseline for the WAF tests: no auth (so an attack-shaped request reaches the WAF step),
/// rate limiting off, pointed at `up`.
fn waf_base(up: SocketAddr) -> Config {
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth = AuthCfg {
        mode: "none".into(),
        ..Default::default()
    };
    cfg
}

#[tokio::test]
async fn waf_off_by_default_allows_attack_shaped_requests() {
    let up = spawn_upstream().await;
    // No [waf] config at all -> mode defaults to "off".
    let proxy = spawn_proxy(waf_base(up)).await;

    // A blatant SQLi payload is forwarded untouched while the WAF is off.
    let r = send(
        proxy,
        "GET",
        "/items?q=1%20UNION%20SELECT%20pw%20FROM%20users",
        None,
        Bytes::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, "hello from upstream");
}

#[tokio::test]
async fn waf_block_mode_rejects_sqli_with_403_and_counts_it() {
    let up = spawn_upstream().await;
    let mut cfg = waf_base(up);
    cfg.waf = WafCfg {
        mode: "block".into(),
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;

    // A benign request still passes.
    assert_eq!(
        send(proxy, "GET", "/healthy", None, Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
    // SQLi in the (percent-encoded) query string -> 403.
    let r = send(proxy, "GET", "/items?id=1%20OR%201%3D1", None, Bytes::new()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // The block shows up in both the WAF metric and the request-outcome metric.
    let m = send(proxy, "GET", "/__edgeguard/metrics", None, Bytes::new()).await;
    assert!(
        m.body.contains("edgeguard_waf_hits_total{rule=\"sqli\"} 1"),
        "{}",
        m.body
    );
    assert!(
        m.body
            .contains("edgeguard_requests_total{outcome=\"forbidden\"} 1"),
        "{}",
        m.body
    );
}

#[tokio::test]
async fn waf_report_mode_forwards_but_counts_the_match() {
    let up = spawn_upstream().await;
    let mut cfg = waf_base(up);
    cfg.waf = WafCfg {
        mode: "report".into(),
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;

    // XSS payload: report mode does NOT block — the request is forwarded (200) ...
    let r = send(
        proxy,
        "GET",
        "/p?c=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        None,
        Bytes::new(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, "hello from upstream");

    // ... but the match is counted, and nothing was recorded as forbidden.
    let m = send(proxy, "GET", "/__edgeguard/metrics", None, Bytes::new()).await;
    assert!(
        m.body.contains("edgeguard_waf_hits_total{rule=\"xss\"} 1"),
        "{}",
        m.body
    );
    assert!(
        m.body
            .contains("edgeguard_requests_total{outcome=\"forbidden\"} 0"),
        "{}",
        m.body
    );
}

#[tokio::test]
async fn waf_custom_deny_pattern_blocks() {
    let up = spawn_upstream().await;
    let mut cfg = waf_base(up);
    cfg.waf = WafCfg {
        mode: "block".into(),
        // Disable the built-ins to prove the custom rule is what fires.
        sqli: false,
        xss: false,
        path_traversal: false,
        rules: vec![WafRule {
            id: "no-wp".into(),
            pattern: r"(?i)/wp-(admin|login)".into(),
            target: "path".into(),
        }],
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;

    assert_eq!(
        send(proxy, "GET", "/app/home", None, Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(proxy, "GET", "/wp-admin/setup.php", None, Bytes::new())
            .await
            .status,
        StatusCode::FORBIDDEN
    );

    let m = send(proxy, "GET", "/__edgeguard/metrics", None, Bytes::new()).await;
    assert!(
        m.body
            .contains("edgeguard_waf_hits_total{rule=\"custom\"} 1"),
        "{}",
        m.body
    );
}

#[tokio::test]
async fn waf_inspect_body_blocks_payload_in_post_body() {
    let up = spawn_upstream().await;
    let mut cfg = waf_base(up);
    cfg.waf = WafCfg {
        mode: "block".into(),
        inspect_body: true,
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;

    // A clean body passes; an XSS payload in the body is blocked once body inspection is on.
    assert_eq!(
        send(
            proxy,
            "POST",
            "/submit",
            None,
            Bytes::from_static(b"name=alice")
        )
        .await
        .status,
        StatusCode::OK
    );
    let r = send(
        proxy,
        "POST",
        "/submit",
        None,
        Bytes::from_static(b"bio=<script>steal(document.cookie)</script>"),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

// --- Phase 4: distributed (shared-store) limiter ---

#[tokio::test]
async fn distributed_memory_store_enforces_ip_limit_through_pipeline() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth = AuthCfg {
        mode: "none".into(),
        ..Default::default()
    };
    cfg.ratelimit = RateLimitCfg {
        enabled: true,
        rate: "1/min".into(),
        burst: 1,
        store: "memory".into(), // shared-store path, in-process backend
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;

    // burst of 1 via the shared store: first OK, second 429 — same semantics as the local limiter.
    assert_eq!(
        send(proxy, "GET", "/", None, Bytes::new()).await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(proxy, "GET", "/", None, Bytes::new()).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );

    // The rejection is recorded under the "ip" scope, just like the governor limiter.
    let m = send(proxy, "GET", "/__edgeguard/metrics", None, Bytes::new()).await;
    assert!(
        m.body
            .contains("edgeguard_ratelimit_hits_total{scope=\"ip\"} 1"),
        "{}",
        m.body
    );
}

#[tokio::test]
async fn distributed_memory_store_enforces_per_key_limit_through_pipeline() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth = AuthCfg {
        mode: "apikey".into(),
        api_keys: vec!["key-a".into(), "key-b".into()],
        ..Default::default()
    };
    cfg.ratelimit = RateLimitCfg {
        enabled: true,
        rate: "1000/min".into(), // generous per-IP so only the per-key cap trips
        burst: 1000,
        per_key: PerKeyRateLimit {
            enabled: true,
            rate: "1/min".into(),
            burst: 1,
        },
        store: "memory".into(),
        ..Default::default()
    };
    let proxy = spawn_proxy(cfg).await;

    // key-a: first OK, second rejected by its own shared-store per-key bucket.
    assert_eq!(
        send_with_headers(proxy, "GET", "/", &[("x-api-key", "key-a")], Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send_with_headers(proxy, "GET", "/", &[("x-api-key", "key-a")], Bytes::new())
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // key-b has an independent bucket.
    assert_eq!(
        send_with_headers(proxy, "GET", "/", &[("x-api-key", "key-b")], Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn unknown_ratelimit_store_is_rejected_at_build() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.ratelimit = RateLimitCfg {
        enabled: true,
        store: "dynamodb".into(),
        ..Default::default()
    };
    // A typo'd store must fail fast rather than silently disable rate limiting.
    assert!(build_state(Arc::new(cfg)).is_err());
}

// --- Phase 4: public/private service split ---

/// Spawn the split topology: the public router (proxy + CSP sink) and the admin router
/// (health/ready/metrics) on two separate listeners sharing one `AppState`.
async fn spawn_split(cfg: Config) -> (SocketAddr, SocketAddr) {
    let state = build_state(Arc::new(cfg)).unwrap();
    let public = build_public_router(state.clone());
    let admin = build_admin_router(state);

    let pub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pub_addr = pub_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            pub_listener,
            public.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(admin_listener, admin).await.unwrap();
    });

    (pub_addr, admin_addr)
}

#[tokio::test]
async fn public_private_split_serves_internal_endpoints_only_on_admin() {
    let up = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth = AuthCfg {
        mode: "none".into(),
        ..Default::default()
    };
    let (public, admin) = spawn_split(cfg).await;

    // Public listener: the ops endpoints are NOT exposed ...
    assert_eq!(
        send(public, "GET", "/__edgeguard/metrics", None, Bytes::new())
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(public, "GET", "/__edgeguard/health", None, Bytes::new())
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    // ... but the proxy works, and the browser-facing CSP sink stays public.
    assert_eq!(
        send(public, "GET", "/anything", None, Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(
            public,
            "POST",
            "/__edgeguard/csp-report",
            None,
            Bytes::from_static(b"{}")
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );

    // Admin listener: serves the ops endpoints ...
    assert_eq!(
        send(admin, "GET", "/__edgeguard/health", None, Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(admin, "GET", "/__edgeguard/metrics", None, Bytes::new())
            .await
            .status,
        StatusCode::OK
    );
    // ... and does NOT proxy arbitrary paths (no fallback).
    assert_eq!(
        send(admin, "GET", "/anything", None, Bytes::new())
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

/// Raw-TCP `text/event-stream` upstream: writes one chunk immediately, waits `gap`, then writes
/// a second chunk and ends the chunked body. Lets a test observe whether the proxy forwards the
/// first event before the upstream has finished (streamed) or only after (buffered). Hand-rolled
/// over `TcpStream` so no stream/SSE helper crate is needed.
async fn spawn_sse_upstream(gap: Duration) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn write_chunk(sock: &mut tokio::net::TcpStream, data: &[u8]) {
        sock.write_all(format!("{:x}\r\n", data.len()).as_bytes())
            .await
            .unwrap();
        sock.write_all(data).await.unwrap();
        sock.write_all(b"\r\n").await.unwrap();
        sock.flush().await.unwrap();
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                // Drain the request head (a GET fits in one read); we don't parse it.
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                sock.write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: text/event-stream\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .unwrap();
                write_chunk(&mut sock, b"data: one\n\n").await;
                tokio::time::sleep(gap).await;
                write_chunk(&mut sock, b"data: two\n\n").await;
                sock.write_all(b"0\r\n\r\n").await.unwrap(); // terminating chunk
                sock.flush().await.unwrap();
            });
        }
    });
    addr
}

/// Read a response body frame-by-frame, returning (full text, time-to-first-byte, time-to-last)
/// measured from `start` — which must be taken *before* the request is sent, so a buffered proxy
/// (headers+body delivered together at the end) shows a late first byte rather than an instant one.
async fn read_streamed(
    resp: Response<hyper::body::Incoming>,
    start: std::time::Instant,
) -> (String, Duration, Duration) {
    let mut body = resp.into_body();
    let (mut first, mut last, mut text) = (None, Duration::ZERO, String::new());
    while let Some(frame) = body.frame().await {
        let frame = frame.unwrap();
        if let Some(data) = frame.data_ref() {
            if !data.is_empty() {
                let t = start.elapsed();
                first.get_or_insert(t);
                last = t;
                text.push_str(&String::from_utf8_lossy(data));
            }
        }
    }
    (text, first.unwrap_or(Duration::ZERO), last)
}

/// With `stream_passthrough` on, an SSE response is forwarded frame-by-frame: the first event
/// reaches the client well before the upstream sends the last one (time-to-first-byte preserved).
#[tokio::test]
async fn sse_passthrough_streams_frames_as_they_arrive() {
    let gap = Duration::from_millis(500);
    let up = spawn_sse_upstream(gap).await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth.mode = "none".into();
    cfg.validation.stream_passthrough = true;
    let proxy = spawn_proxy(cfg).await;

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .uri(format!("http://{proxy}/stream"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let start = std::time::Instant::now();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (text, first, last) = read_streamed(resp, start).await;

    assert!(
        text.contains("one") && text.contains("two"),
        "got: {text:?}"
    );
    // The two events are separated by `gap`; streaming means we saw the first long before the last.
    assert!(first < gap, "first byte too late: {first:?}");
    assert!(last >= gap, "last byte too early: {last:?}");
    assert!(
        last - first >= gap / 2,
        "frames not separated (buffered?): first={first:?} last={last:?}"
    );
}

/// With passthrough off (default), the same SSE response is buffered: the client gets nothing
/// until the upstream has finished, so the first byte arrives no earlier than the inter-event gap.
#[tokio::test]
async fn buffered_response_withholds_body_until_complete() {
    let gap = Duration::from_millis(500);
    let up = spawn_sse_upstream(gap).await;
    let mut cfg = base_cfg(format!("http://{up}"));
    cfg.auth.mode = "none".into();
    // stream_passthrough defaults to false.
    let proxy = spawn_proxy(cfg).await;

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .uri(format!("http://{proxy}/stream"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let start = std::time::Instant::now();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (text, first, _last) = read_streamed(resp, start).await;

    assert!(
        text.contains("one") && text.contains("two"),
        "got: {text:?}"
    );
    assert!(
        first >= gap,
        "body was not buffered — first byte at {first:?}, expected >= {gap:?}"
    );
}

/// CORS: a browser preflight (OPTIONS + Origin + Access-Control-Request-Method) is answered by
/// EdgeGuard directly, *before* auth (preflights carry no credentials), with the matching allow
/// headers — and the actual authenticated response is decorated with Access-Control-Allow-Origin
/// + Vary: Origin. A disallowed origin gets no CORS headers, so the browser blocks it.
#[tokio::test]
async fn cors_preflight_and_decoration() {
    let upstream = spawn_upstream().await;
    let mut cfg = base_cfg(format!("http://{upstream}")); // basic auth admin/secret
    cfg.cors = CorsCfg {
        enabled: true,
        allow_origins: vec!["https://app.example.com".into()],
        allow_credentials: true,
        ..Default::default()
    };
    let addr = spawn_proxy(cfg).await;

    // Preflight from an allowed origin: 204, no auth required, ACAO echoes the origin, the
    // requested headers are reflected, and the credentials flag is set.
    let pre = send_with_headers(
        addr,
        "OPTIONS",
        "/api/thing",
        &[
            ("origin", "https://app.example.com"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "content-type"),
        ],
        Bytes::new(),
    )
    .await;
    assert_eq!(pre.status, StatusCode::NO_CONTENT);
    assert_eq!(
        pre.headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example.com"
    );
    assert_eq!(
        pre.headers
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
    assert_eq!(
        pre.headers
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap(),
        "content-type"
    );

    // Preflight from a disallowed origin: still 204, but no CORS headers (browser refuses it).
    let bad = send_with_headers(
        addr,
        "OPTIONS",
        "/api/thing",
        &[
            ("origin", "https://evil.example"),
            ("access-control-request-method", "POST"),
        ],
        Bytes::new(),
    )
    .await;
    assert_eq!(bad.status, StatusCode::NO_CONTENT);
    assert!(bad
        .headers
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());

    // Actual authenticated request: response is decorated with ACAO + Vary: Origin.
    let resp = send_with_headers(
        addr,
        "GET",
        "/",
        &[
            ("origin", "https://app.example.com"),
            ("authorization", &basic("admin", "secret")),
        ],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example.com"
    );
    assert!(resp
        .headers
        .get_all(header::VARY)
        .iter()
        .any(|v| v.to_str().unwrap().eq_ignore_ascii_case("origin")));
}

/// IP access control: `deny` drops a matching client with `403` before auth, and a non-empty
/// `allow` is a whitelist (a client outside it is rejected even with no auth gate).
#[tokio::test]
async fn ip_access_deny_and_allow() {
    let upstream = spawn_upstream().await;

    // Deny loopback -> 403 (the test client connects from 127.0.0.1 / ::1).
    let mut deny_cfg = base_cfg(format!("http://{upstream}"));
    deny_cfg.auth.mode = "none".into();
    deny_cfg.access.deny = vec!["127.0.0.1/32".into(), "::1/128".into()];
    let denied = spawn_proxy(deny_cfg).await;
    assert_eq!(get(denied, None).await.status, StatusCode::FORBIDDEN);

    // Allowlist that excludes loopback -> 403 (whitelist semantics).
    let mut allow_other = base_cfg(format!("http://{upstream}"));
    allow_other.auth.mode = "none".into();
    allow_other.access.allow = vec!["10.0.0.0/8".into()];
    let blocked = spawn_proxy(allow_other).await;
    assert_eq!(get(blocked, None).await.status, StatusCode::FORBIDDEN);

    // Allowlist including loopback -> 200.
    let mut allow_lo = base_cfg(format!("http://{upstream}"));
    allow_lo.auth.mode = "none".into();
    allow_lo.access.allow = vec!["127.0.0.1/32".into(), "::1/128".into()];
    let ok = spawn_proxy(allow_lo).await;
    assert_eq!(get(ok, None).await.status, StatusCode::OK);
}

/// A minimal upstream that performs an HTTP `Upgrade` handshake: it answers `101` (echoing the
/// requested `Upgrade` token) and then echoes every byte on the upgraded connection. Lets the
/// WebSocket-passthrough test assert the proxy splices bytes both ways, without pulling in a full
/// WebSocket framing library — the proxy's job is protocol-agnostic byte tunneling after a `101`.
async fn spawn_ws_echo_upstream() -> SocketAddr {
    async fn handler(req: Request<Body>) -> Response<Body> {
        let proto = req.headers().get(header::UPGRADE).cloned();
        let on_upgrade = hyper::upgrade::on(req);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if let Ok(upgraded) = on_upgrade.await {
                let mut io = hyper_util::rt::TokioIo::new(upgraded);
                let mut buf = vec![0u8; 1024];
                loop {
                    match io.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if io.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        resp.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        if let Some(p) = proto {
            resp.headers_mut().insert(header::UPGRADE, p);
        }
        resp
    }
    let app = Router::new().fallback(any(handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// WebSocket / `Upgrade` passthrough: with `validation.websocket_passthrough` on, an upgrade
/// request is forwarded intact, the upstream's `101` reaches the client, and the connection
/// becomes a raw bidirectional tunnel (bytes written by the client are echoed back through the
/// proxy). Uses a raw TCP client so the test isn't tied to a WebSocket client library.
#[tokio::test]
async fn websocket_passthrough_tunnels_bytes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = spawn_ws_echo_upstream().await;
    let mut cfg = base_cfg(format!("http://{upstream}"));
    cfg.auth.mode = "none".into();
    cfg.validation.websocket_passthrough = true;
    let addr = spawn_proxy(cfg).await;

    // Bound the whole exchange: if the proxy regresses and never returns 101 or stops echoing,
    // fail fast with a clear message instead of hanging until the test harness kills us.
    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: edgeguard\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n",
            )
            .await
            .unwrap();

        // Read the response head (up to the blank line that ends the headers).
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).await.unwrap();
            assert_ne!(n, 0, "connection closed before the 101 head");
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&head);
        assert!(
            head.starts_with("HTTP/1.1 101"),
            "expected 101, got: {head}"
        );

        // The connection is now a raw tunnel — bytes are echoed by the upstream.
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    };
    tokio::time::timeout(Duration::from_secs(5), exchange)
        .await
        .expect("websocket tunnel did not complete within 5s");
}

/// Upstream that reflects the `X-Request-Id` it received into a response header, so the test can
/// assert EdgeGuard both forwards the id upstream and echoes it to the client.
async fn spawn_reflect_upstream() -> SocketAddr {
    async fn handler(req: Request<Body>) -> Response<Body> {
        let seen = req.headers().get("x-request-id").cloned();
        let mut resp = Response::new(Body::from("ok"));
        if let Some(v) = seen {
            resp.headers_mut().insert("x-saw-request-id", v);
        }
        resp
    }
    let app = Router::new().fallback(any(handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A request id is generated when absent, forwarded upstream, and echoed on the response; a
/// well-formed inbound id is reused verbatim end to end (for cross-service log correlation).
#[tokio::test]
async fn request_id_is_generated_echoed_and_forwarded() {
    let upstream = spawn_reflect_upstream().await;
    let mut cfg = base_cfg(format!("http://{upstream}"));
    cfg.auth.mode = "none".into();
    let addr = spawn_proxy(cfg).await;

    // No inbound id -> EdgeGuard generates one, echoes it, and the upstream saw the same value.
    let r = send_with_headers(addr, "GET", "/", &[], Bytes::new()).await;
    let echoed = r
        .headers
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(!echoed.is_empty());
    assert_eq!(r.headers.get("x-saw-request-id").unwrap(), echoed.as_str());

    // Inbound id -> reused verbatim, client-echoed and upstream-forwarded.
    let r = send_with_headers(
        addr,
        "GET",
        "/",
        &[("x-request-id", "trace-abc-123")],
        Bytes::new(),
    )
    .await;
    assert_eq!(r.headers.get("x-request-id").unwrap(), "trace-abc-123");
    assert_eq!(r.headers.get("x-saw-request-id").unwrap(), "trace-abc-123");
}

/// A trivial upstream that always responds with a fixed label, to tell two upstreams apart.
async fn spawn_labeled_upstream(label: &'static str) -> SocketAddr {
    let app = Router::new().fallback(any(move || async move { label }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// `[[upstreams]]`: a path-prefix override routes matching requests to a second upstream, while
/// everything else falls back to the default upstream.
#[tokio::test]
async fn path_based_upstream_routing() {
    let default_up = spawn_labeled_upstream("default-upstream").await;
    let api_up = spawn_labeled_upstream("api-upstream").await;
    let admin_up = spawn_labeled_upstream("admin-upstream").await;
    let mut cfg = base_cfg(format!("http://{default_up}"));
    cfg.auth.mode = "none".into();
    // Overlapping prefixes, declared broad-first, to prove longest-prefix wins (not declaration
    // order).
    cfg.upstreams = vec![
        UpstreamRoute {
            path: "/api/".into(),
            target: format!("http://{api_up}"),
        },
        UpstreamRoute {
            path: "/api/admin/".into(),
            target: format!("http://{admin_up}"),
        },
    ];
    let addr = spawn_proxy(cfg).await;

    assert_eq!(get(addr, None).await.body, "default-upstream");
    assert_eq!(
        send(addr, "GET", "/api/users", None, Bytes::new())
            .await
            .body,
        "api-upstream"
    );
    // The deeper, more specific prefix wins over the broader `/api/` one.
    assert_eq!(
        send(addr, "GET", "/api/admin/users", None, Bytes::new())
            .await
            .body,
        "admin-upstream"
    );
    // A non-matching prefix still goes to the default.
    assert_eq!(
        send(addr, "GET", "/static/app.js", None, Bytes::new())
            .await
            .body,
        "default-upstream"
    );
}

/// An upstream returning a sizable, compressible body (above the compressor's small-response
/// floor) so the gzip path actually engages.
async fn spawn_big_upstream() -> SocketAddr {
    async fn handler() -> Response<Body> {
        Response::new(Body::from("compress me ".repeat(64)))
    }
    let app = Router::new().fallback(any(handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// With `validation.compress_responses` on and a client that advertises `Accept-Encoding: gzip`,
/// a compressible response comes back gzip-encoded.
#[tokio::test]
async fn gzip_compression_when_enabled() {
    let upstream = spawn_big_upstream().await;
    let mut cfg = base_cfg(format!("http://{upstream}"));
    cfg.auth.mode = "none".into();
    cfg.validation.compress_responses = true;
    let addr = spawn_proxy(cfg).await;

    let r = send_with_headers(
        addr,
        "GET",
        "/",
        &[("accept-encoding", "gzip")],
        Bytes::new(),
    )
    .await;
    assert_eq!(
        r.headers
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
}
