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
    AuthCfg, Config, HeadersCfg, JwtCfg, PerKeyRateLimit, RateLimitCfg, RouteRateLimit, ServerCfg,
    WafCfg, WafRule,
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
