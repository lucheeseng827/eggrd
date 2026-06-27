//! Request path: header-size limit -> rate limit (per-IP / per-route) -> auth -> per-key
//! rate limit -> method allowlist -> body-size limit -> WAF input inspection -> forward to
//! upstream.
//! Response path: header injection (incl. CSP / CSP-report-only) -> cookie hardening ->
//! strip leaky headers.
//!
//! All policy lives in [`Runtime`], held behind an [`ArcSwap`] so a config hot-reload swaps
//! it atomically without blocking the request path or dropping in-flight connections. The
//! upstream client and the metric registry sit *outside* the swap so the connection pool and
//! counters survive a reload.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode},
};
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, RateLimiter};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::auth::{AuthEngine, Challenge, Decision};
use crate::config::{Config, HeadersCfg};
use crate::limiter::{Admit, DistributedLimiter};
use crate::metrics::Metrics;
use crate::waf::{WafEngine, WafMode};

pub type KeyedLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;
/// Rate limiter keyed by the authenticated principal (per-key limiting).
pub type StrLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;
pub type UpstreamClient = Client<HttpConnector, Full<Bytes>>;

/// Shared, cheaply-cloned handle the router hands to every request. Only the hot-swappable
/// [`Runtime`] changes on reload; the client and metrics are stable.
#[derive(Clone)]
pub struct AppState {
    pub client: UpstreamClient,
    pub metrics: Arc<Metrics>,
    pub runtime: Arc<ArcSwap<Runtime>>,
    /// Managed-mode control-plane client (`Some` only when `[control_plane]` is enabled). Used to
    /// forward CSP reports; policy pull + usage reporting run as background tasks in `main`.
    pub cp: Option<Arc<crate::cp::CpClient>>,
    /// Shared quota verdict, updated by the managed-mode quota poller and read by the
    /// hard-stop gate below. Lives here (not on the hot-swappable [`Runtime`]) so a policy reload
    /// never resets enforcement. Inert unless `control_plane.enforce_quota` is set.
    pub quota: Arc<crate::cp::QuotaState>,
}

/// A per-route rate-limit override: requests whose path starts with `prefix` use `limiter`.
pub struct RouteLimiter {
    pub prefix: String,
    pub limiter: Arc<KeyedLimiter>,
}

/// All request-handling policy derived from a [`Config`]. Rebuilt from scratch on reload and
/// swapped in atomically.
pub struct Runtime {
    pub cfg: Arc<Config>,
    /// Default upstream base URL (the single `server.upstream`/`app_port`), used when no
    /// `[[upstreams]]` prefix matches.
    pub upstream_base: Arc<String>,
    /// Per-path-prefix upstream overrides as `(prefix, base)`; the longest matching prefix wins.
    /// Empty unless `[[upstreams]]` is configured.
    pub upstream_routes: Vec<(String, Arc<String>)>,
    pub auth: AuthEngine,
    /// WAF-lite input screener. Inert (`evaluate` returns `None`) when `waf.mode = "off"`.
    pub waf: WafEngine,
    /// Compiled CORS policy; `None` when `cors.enabled = false` (the proxy then skips CORS).
    pub cors: Option<crate::cors::CorsPolicy>,
    /// Compiled IP allow/deny policy; `None` when both lists are empty (no IP gating).
    pub access: Option<crate::access::AccessPolicy>,
    /// Shared-store (distributed) limiter, `Some` when `ratelimit.store` is `memory`/`redis`.
    /// When present it replaces the three `governor` limiters below (which are then `None`).
    pub distributed: Option<DistributedLimiter>,
    /// Global per-client-IP limiter (`None` when rate limiting is disabled or distributed).
    pub ip_limiter: Option<Arc<KeyedLimiter>>,
    /// Per-route limiters (also keyed per IP), checked instead of `ip_limiter` on a match.
    pub route_limiters: Vec<RouteLimiter>,
    /// Per-principal limiter (`None` when per-key limiting is disabled or distributed).
    pub key_limiter: Option<Arc<StrLimiter>>,
    pub max_body: usize,
    /// Cap on the buffered upstream response body; `0` means unbounded.
    pub max_response_body: usize,
    /// Cap on total request header bytes; `0` means disabled.
    pub max_header_bytes: usize,
    /// Max time for the upstream request + body read; `None` disables the timeout.
    pub upstream_timeout: Option<Duration>,
    /// Forward `text/event-stream` responses unbuffered (SSE passthrough). See
    /// [`crate::config::ValidationCfg::stream_passthrough`].
    pub stream_passthrough: bool,
    /// Tunnel WebSocket / `Upgrade` connections to the upstream. See
    /// [`crate::config::ValidationCfg::websocket_passthrough`].
    pub websocket_passthrough: bool,
}

impl Runtime {
    /// The upstream base URL to forward `path` to: the longest matching `[[upstreams]]` prefix,
    /// or the default [`Runtime::upstream_base`] when none match.
    pub fn pick_upstream(&self, path: &str) -> &str {
        self.upstream_routes
            .iter()
            .filter(|(prefix, _)| path_prefix_matches(path, prefix))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, base)| base.as_str())
            .unwrap_or_else(|| self.upstream_base.as_str())
    }
}

/// Whether `prefix` matches `path` on a path-segment boundary. `prefix` is a validated upstream
/// route prefix (always starts with `/`); `path` is the request path-and-query. A plain
/// `str::starts_with` would route a sibling like `/apiary` to the `/api` upstream, so the match
/// only succeeds when the prefix is followed by a real boundary: end of path, a `/`, or the query
/// separator `?`. A trailing slash on the prefix is itself a boundary.
fn path_prefix_matches(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => {
            rest.is_empty()
                || prefix.ends_with('/')
                || rest.starts_with('/')
                || rest.starts_with('?')
        }
        None => false,
    }
}

/// Hop-by-hop headers that must not be forwarded (RFC 7230 §6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub async fn handle(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response<Body> {
    // One atomic load pins a consistent policy snapshot for the whole request, even if a reload
    // swaps in a new Runtime mid-flight — routing, auth, *and* the final CORS decoration below all
    // see the same one (loading again here could decorate with a policy the request never used).
    let rt = state.runtime.load_full();
    // Capture the request Origin before the body is consumed, so we can CORS-decorate *every*
    // response — including EdgeGuard-generated 401/403/429 — not just proxied successes. Without
    // this, an allowed browser origin sees a generic CORS failure instead of the real status.
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut resp = handle_inner(&state, &rt, peer, req).await;
    if let Some(origin) = &origin {
        if let Some(cors) = &rt.cors {
            cors.decorate_origin(origin, &mut resp);
        }
    }
    resp
}

async fn handle_inner(
    state: &AppState,
    rt: &Runtime,
    peer: SocketAddr,
    req: Request<Body>,
) -> Response<Body> {
    let started = Instant::now();
    let m = &state.metrics;

    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let ip = client_ip(req.headers(), peer, rt.cfg.server.trust_forwarded_for);
    // Request id for correlation: reuse a well-formed inbound one, else generate. Echoed on the
    // response and the access log by `finish`, and forwarded upstream below.
    let rid = resolve_request_id(req.headers());

    // Reserve the internal namespace: never forward `/__edgeguard/*` upstream. Registered
    // internal routes are matched before this fallback, so anything reaching here under that
    // prefix is an unknown internal path — a `404` from EdgeGuard, not a request leaked to the
    // app. This is also what keeps the ops endpoints (health/ready/metrics) unserved on the
    // public listener in public/private split mode, rather than proxying them to the upstream.
    if req.uri().path().starts_with("/__edgeguard/") {
        return finish(
            m,
            &rid,
            &method,
            &path,
            ip,
            started,
            "not_found",
            text(StatusCode::NOT_FOUND, "Not Found"),
        );
    }

    // 0) IP access control. A coarse network gate (CIDR allow/deny) evaluated before auth and
    //    rate limiting, so a denied/non-allowlisted client is dropped with `403` before consuming
    //    any limiter token or auth work. Keys on the same resolved client IP as rate limiting.
    if let Some(access) = &rt.access {
        if !access.allowed(ip) {
            return finish(
                m,
                &rid,
                &method,
                &path,
                ip,
                started,
                "ip_denied",
                text(StatusCode::FORBIDDEN, "Forbidden"),
            );
        }
    }

    // 0.1) Total request-header-size limit.
    if rt.max_header_bytes > 0 && header_bytes(req.headers()) > rt.max_header_bytes {
        return finish(
            m,
            &rid,
            &method,
            &path,
            ip,
            started,
            "header_too_large",
            text(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Request Header Fields Too Large",
            ),
        );
    }

    // 0.5) Quota hard-stop (managed mode, opt-in). When the control plane reports the
    //      edge over its quota, reject the edge's traffic with `429` and a
    //      month-scale `Retry-After`, until the next successful poll clears it. Off unless
    //      `control_plane.enforce_quota` is set; the `/__edgeguard/*` endpoints are excluded above,
    //      so health/ready/metrics keep serving even while over quota.
    if rt.cfg.control_plane.enforce_quota && state.quota.blocked() {
        let mut resp = text(StatusCode::TOO_MANY_REQUESTS, "Quota Exceeded");
        let reset = state.quota.reset_epoch();
        if reset > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let retry_after = reset.saturating_sub(now).max(0);
            if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        return finish(m, &rid, &method, &path, ip, started, "over_quota", resp);
    }

    // 1) Rate limit. A matching per-route override replaces the global per-IP limit. A shared
    //    store (distributed) limiter, when configured, replaces the in-process limiters; on a
    //    store error it fails closed (`503`) unless `ratelimit.fail_open` is set.
    if rt.cfg.ratelimit.enabled {
        if let Some(d) = &rt.distributed {
            match d.check_ip_route(ip, &path).await {
                Admit::Allowed => {}
                Admit::Limited(scope) => {
                    m.record_ratelimit_hit(scope);
                    return finish(
                        m,
                        &rid,
                        &method,
                        &path,
                        ip,
                        started,
                        "rate_limited",
                        text(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests"),
                    );
                }
                Admit::Error => {
                    return finish(
                        m,
                        &rid,
                        &method,
                        &path,
                        ip,
                        started,
                        "limiter_error",
                        text(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable"),
                    );
                }
            }
        } else {
            let (limiter, scope) = match longest_route(&rt.route_limiters, &path) {
                Some(r) => (Some(r.limiter.as_ref()), "route"),
                None => (rt.ip_limiter.as_deref(), "ip"),
            };
            if let Some(limiter) = limiter {
                if limiter.check_key(&ip).is_err() {
                    m.record_ratelimit_hit(scope);
                    return finish(
                        m,
                        &rid,
                        &method,
                        &path,
                        ip,
                        started,
                        "rate_limited",
                        text(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests"),
                    );
                }
            }
        }
    }

    // 1.5) CORS preflight. Answer a browser preflight (`OPTIONS` + `Origin` +
    //      `Access-Control-Request-Method`) here, *before* auth: a preflight carries no
    //      credentials, so gating it behind the auth check would make every cross-origin call
    //      fail. Only a real preflight is short-circuited; a plain `OPTIONS` falls through.
    if method == Method::OPTIONS {
        if let Some(cors) = &rt.cors {
            if let Some(resp) = cors.preflight_response(req.headers()) {
                return finish(m, &rid, &method, &path, ip, started, "cors_preflight", resp);
            }
        }
    }

    // 2) Authentication. On success we learn the principal for per-key limiting.
    let principal = match rt.auth.authorize(&rt.cfg.auth, req.headers()).await {
        Decision::Allow(principal) => principal,
        Decision::Deny(challenge) => {
            let mut resp = text(StatusCode::UNAUTHORIZED, "Unauthorized");
            let challenge_value = match challenge {
                Challenge::Basic(c) => Some(c),
                Challenge::Bearer => Some("Bearer".to_string()),
                Challenge::None => None,
            };
            if let Some(c) = challenge_value {
                if let Ok(v) = HeaderValue::from_str(&c) {
                    resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
                }
            }
            return finish(m, &rid, &method, &path, ip, started, "unauthorized", resp);
        }
    };

    // 3) Per-key rate limit (only for authenticated principals). Routed to the distributed
    //    limiter when configured, else the in-process per-key limiter.
    if let Some(principal) = &principal {
        let key_admit = if let Some(d) = &rt.distributed {
            Some(d.check_key(principal).await)
        } else {
            rt.key_limiter.as_ref().map(|limiter| {
                if limiter.check_key(principal).is_err() {
                    Admit::Limited("key")
                } else {
                    Admit::Allowed
                }
            })
        };
        match key_admit {
            Some(Admit::Limited(scope)) => {
                m.record_ratelimit_hit(scope);
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "rate_limited",
                    text(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests"),
                );
            }
            Some(Admit::Error) => {
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "limiter_error",
                    text(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable"),
                );
            }
            Some(Admit::Allowed) | None => {}
        }
    }

    // 4) Method allowlist.
    let allow = &rt.cfg.validation.allow_methods;
    if !allow.is_empty()
        && !allow
            .iter()
            .any(|x| x.eq_ignore_ascii_case(method.as_str()))
    {
        return finish(
            m,
            &rid,
            &method,
            &path,
            ip,
            started,
            "method_not_allowed",
            text(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed"),
        );
    }

    // 4.5) WebSocket / `Upgrade` passthrough (opt-in). An upgrade request can't go through the
    //      buffer-and-forward path below — it needs a raw bidirectional tunnel. When enabled, hand
    //      off to `proxy_upgrade`, which forwards the request *with* its upgrade headers (the
    //      normal path strips them) and splices the connections on a `101`. The request is already
    //      authenticated and rate-limited at this point. When disabled (default), fall through and
    //      the upgrade headers are stripped like any other hop-by-hop header.
    if rt.websocket_passthrough && is_upgrade_request(req.headers()) {
        return proxy_upgrade(state, rt, req, &rid, &method, &path, ip, started).await;
    }

    // 5) Buffer the body up to the configured limit.
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, rt.max_body).await {
        Ok(b) => b,
        Err(_) => {
            return finish(
                m,
                &rid,
                &method,
                &path,
                ip,
                started,
                "payload_too_large",
                text(StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large"),
            )
        }
    };
    // Request (ingress) size for managed-mode usage, captured before the body is forwarded upstream.
    let ingress_bytes = header_bytes(&parts.headers).saturating_add(body_bytes.len());

    // 6) WAF-lite input inspection. A no-op unless `waf.mode` is report/block. The body is
    //    already buffered above, so inspecting it adds no extra read. On a match: `block` mode
    //    returns 403; `report` mode logs + counts and forwards. Both record the hit so a
    //    report-only rollout shows up in `edgeguard_waf_hits_total`.
    if let Some(hit) = rt.waf.evaluate(&path, &parts.headers, &body_bytes) {
        m.record_waf_hit(hit.class);
        match rt.waf.mode() {
            WafMode::Block => {
                warn!(
                    rule = %hit.rule_id,
                    class = hit.class,
                    location = hit.location,
                    client_ip = %ip,
                    path = %path,
                    "WAF blocked request"
                );
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "forbidden",
                    text(StatusCode::FORBIDDEN, "Forbidden"),
                );
            }
            WafMode::Report => warn!(
                rule = %hit.rule_id,
                class = hit.class,
                location = hit.location,
                client_ip = %ip,
                path = %path,
                "WAF rule matched (report-only)"
            ),
            // `evaluate` returns `None` when off, so this arm is unreachable; kept for
            // exhaustiveness.
            WafMode::Off => {}
        }
    }

    // 7) Build the upstream request (the per-path upstream override, or the default).
    let uri = format!("{}{}", rt.pick_upstream(&path), path);
    let mut up = Request::builder().method(parts.method.clone()).uri(&uri);
    {
        let headers = up.headers_mut().expect("builder headers");
        // Drop hop-by-hop headers (the fixed set plus any named by `Connection`) before
        // forwarding, so they don't leak across the proxy boundary.
        let mut forwarded = parts.headers.clone();
        strip_hop_by_hop(&mut forwarded);
        for (name, value) in forwarded.iter() {
            if name == header::HOST {
                continue; // let the client set Host for the upstream
            }
            headers.insert(name.clone(), value.clone());
        }
        // Standard forwarding headers.
        if let Ok(v) = HeaderValue::from_str(&ip.to_string()) {
            headers.insert(HeaderName::from_static("x-forwarded-for"), v);
        }
        headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static(forwarded_proto(&rt.cfg, &parts.headers)),
        );
        // Forward the (resolved/generated) request id so the upstream logs the same correlation id.
        if let Ok(v) = HeaderValue::from_str(&rid) {
            headers.insert(HeaderName::from_static(REQUEST_ID_HEADER), v);
        }
    }

    let upstream_req = match up.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "failed to build upstream request");
            return finish(
                m,
                &rid,
                &method,
                &path,
                ip,
                started,
                "bad_gateway",
                text(StatusCode::BAD_GATEWAY, "Bad Gateway"),
            );
        }
    };

    // 8) Forward and collect the response under a single deadline, so a stalled upstream
    //    can't pin this task. `None` => no timeout (validation.upstream_timeout = "0").
    let deadline = rt.upstream_timeout.map(|d| tokio::time::Instant::now() + d);
    let timed_out = || {
        warn!(upstream = %uri, "upstream timed out");
        text(StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout")
    };

    let upstream_resp = match within(deadline, state.client.request(upstream_req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            warn!(error = %e, upstream = %uri, "upstream unreachable");
            return finish(
                m,
                &rid,
                &method,
                &path,
                ip,
                started,
                "upstream_error",
                text(StatusCode::BAD_GATEWAY, "Bad Gateway"),
            );
        }
        Err(_) => {
            return finish(
                m,
                &rid,
                &method,
                &path,
                ip,
                started,
                "upstream_timeout",
                timed_out(),
            )
        }
    };

    let (mut resp_parts, resp_body) = upstream_resp.into_parts();

    // 8a) SSE passthrough: forward a `text/event-stream` response frame-by-frame instead of
    //     buffering the whole body, so the client sees events as they arrive (time-to-first-byte
    //     is preserved). The buffering path below would hold the entire stream until the upstream
    //     finished, which defeats SSE. On a streamed body the `max_response_body` cap and the
    //     body-read deadline don't apply — the connect/first-byte `upstream_timeout` already
    //     bounded time-to-headers — and egress bytes are tallied by `CountingBody` as frames flow.
    //     Response hardening is headers-only, so it stays correct on a streaming body.
    if rt.stream_passthrough && is_event_stream(&resp_parts.headers) {
        strip_hop_by_hop(&mut resp_parts.headers);
        resp_parts.headers.remove(header::CONTENT_LENGTH);
        let header_egress = header_bytes(&resp_parts.headers);
        let body = Body::new(CountingBody::new(
            resp_body,
            Arc::clone(m),
            ingress_bytes,
            header_egress,
        ));
        let mut response = Response::from_parts(resp_parts, body);
        harden_response(&rt.cfg, &mut response);
        // CORS decoration happens centrally in `handle` (covers this and every error path).
        return finish(m, &rid, &method, &path, ip, started, "ok", response);
    }

    // Buffer the upstream body, optionally capped so a huge response can't OOM the proxy.
    let resp_bytes = if rt.max_response_body > 0 {
        match within(
            deadline,
            Limited::new(resp_body, rt.max_response_body).collect(),
        )
        .await
        {
            Ok(Ok(c)) => c.to_bytes(),
            Ok(Err(_)) => {
                warn!(
                    limit = rt.max_response_body,
                    "upstream response exceeded max_response_body"
                );
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "upstream_body_too_large",
                    text(StatusCode::BAD_GATEWAY, "Bad Gateway"),
                );
            }
            Err(_) => {
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "upstream_timeout",
                    timed_out(),
                )
            }
        }
    } else {
        match within(deadline, resp_body.collect()).await {
            Ok(Ok(c)) => c.to_bytes(),
            Ok(Err(e)) => {
                warn!(error = %e, "failed reading upstream body");
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "upstream_body_error",
                    text(StatusCode::BAD_GATEWAY, "Bad Gateway"),
                );
            }
            Err(_) => {
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "upstream_timeout",
                    timed_out(),
                )
            }
        }
    };

    // The body was rebuffered, so let the server recompute framing; strip hop-by-hop headers
    // (incl. any named by `Connection`) so they don't leak downstream.
    strip_hop_by_hop(&mut resp_parts.headers);
    resp_parts.headers.remove(header::CONTENT_LENGTH);

    // Managed-mode usage: this is the proxied path, where both bodies are buffered, so the byte
    // counts are exact. (`add_usage_request` is recorded for every request in `finish`.)
    m.add_usage_bytes(
        ingress_bytes,
        header_bytes(&resp_parts.headers).saturating_add(resp_bytes.len()),
    );

    let mut response = Response::from_parts(resp_parts, Body::from(resp_bytes));
    harden_response(&rt.cfg, &mut response);
    // CORS decoration happens centrally in `handle` (covers this and every error path).

    finish(m, &rid, &method, &path, ip, started, "ok", response)
}

/// Readiness probe. Returns `200` only if the upstream accepts a TCP connection, so a
/// platform's readiness check reflects whether EdgeGuard can actually serve traffic — not
/// merely that the process booted. `503` while the upstream is unreachable. (Liveness, i.e.
/// "is EdgeGuard itself up", is the separate unconditional `/__edgeguard/health`.)
pub async fn ready(State(state): State<AppState>) -> StatusCode {
    let rt = state.runtime.load();
    let Some((host, port)) = rt.cfg.upstream_probe_addr() else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    match tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(_)) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Prometheus scrape endpoint (`GET /__edgeguard/metrics`). Like health/ready, it is a
/// dedicated route outside the proxy fallback, so it is not subject to auth or rate limits —
/// restrict access to `/__edgeguard/*` at the network layer if that matters in your setup.
pub async fn metrics_handler(State(state): State<AppState>) -> Response<Body> {
    let body = state.metrics.render();
    let mut resp = Response::new(Body::from(body));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    resp
}

/// CSP violation report sink (`POST /__edgeguard/csp-report`). Browsers POST a JSON report
/// here when `headers.csp_report_uri` points at it; we count and log it, then `204`.
pub async fn csp_report(State(state): State<AppState>, body: Bytes) -> StatusCode {
    state.metrics.record_csp_report();
    // Managed mode: forward the raw report to the control plane (fire-and-forget, so the browser's
    // 204 is never delayed by an outbound call). Only when a control plane is configured and
    // `forward_csp` is on.
    if let Some(cp) = &state.cp {
        if state.runtime.load().cfg.control_plane.forward_csp {
            let cp = cp.clone();
            let raw = body.clone();
            tokio::spawn(async move { cp.forward_csp(&raw).await });
        }
    }
    // This endpoint is unauthenticated and a report can carry the full document URL,
    // referrer, and query strings — logging the whole blob at `info` is both a privacy leak
    // and a log-flood vector. Record only the directive that fired, at `debug`.
    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(report) => {
            let directive = report
                .get("csp-report")
                .and_then(|r| {
                    r.get("violated-directive")
                        .or_else(|| r.get("effective-directive"))
                })
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            debug!(target: "edgeguard::csp", directive, "CSP violation report");
        }
        Err(_) => warn!(
            bytes = body.len(),
            "CSP violation report with an unparseable body"
        ),
    }
    StatusCode::NO_CONTENT
}

/// Header EdgeGuard reads an inbound request id from and echoes on every response. A
/// `&'static str` (rather than a `HeaderName` const, which isn't a const fn) — `HeaderMap`'s
/// `get`/`insert` accept it directly.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Resolve the request id for log correlation: reuse a well-formed inbound `X-Request-Id` (one a
/// CDN/LB already set), else mint a UUID v4. The inbound value is trusted only when it's a short,
/// printable-ASCII token, so a hostile client can't inject newlines/control characters into the
/// access log or the echoed response header.
fn resolve_request_id(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get(REQUEST_ID_HEADER).and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        if !v.is_empty() && v.len() <= 128 && v.bytes().all(|b| b.is_ascii_graphic()) {
            return v.to_string();
        }
    }
    uuid::Uuid::new_v4().to_string()
}

/// Resolve the client IP. The peer socket address is authoritative; `X-Forwarded-For`
/// (first hop) is honored only when `trust_forwarded` is set, because a directly
/// reachable client can otherwise spoof it to forge their identity.
fn client_ip(headers: &HeaderMap, peer: SocketAddr, trust_forwarded: bool) -> IpAddr {
    if trust_forwarded {
        if let Some(xff) = headers.get("x-forwarded-for") {
            if let Ok(s) = xff.to_str() {
                if let Some(first) = s.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }
    }
    peer.ip()
}

/// Total size of the request headers (sum of name + value bytes), used for the header-size
/// policy limit. This is an application-layer approximation of the on-wire header size.
fn header_bytes(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum()
}

/// True if the response is a Server-Sent Events stream (`Content-Type: text/event-stream`,
/// ignoring any `; charset=…` parameter and leading whitespace). The signal we use to forward a
/// response unbuffered when `validation.stream_passthrough` is on.
fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .map(str::trim)
                .map(|ct| ct.eq_ignore_ascii_case("text/event-stream"))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// True when the request asks to upgrade the protocol — a `Connection: upgrade` token plus an
/// `Upgrade` header (e.g. a WebSocket handshake). The signal for [`proxy_upgrade`].
fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let conn_has_upgrade = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    conn_has_upgrade && headers.contains_key(header::UPGRADE)
}

/// Tunnel a WebSocket / `Upgrade` request to the upstream. Unlike the normal path (which strips
/// the hop-by-hop `Upgrade`/`Connection` headers), this forwards the handshake intact; on the
/// upstream's `101 Switching Protocols` it splices the client and upstream connections into a raw
/// bidirectional byte tunnel for the lifetime of the socket. Any other upstream status is passed
/// back to the client unchanged, so a rejected handshake surfaces normally.
// Mirrors the `handle` forward path's parameters (state/runtime/request + the access-log tuple);
// see the note on `finish`.
#[allow(clippy::too_many_arguments)]
async fn proxy_upgrade(
    state: &AppState,
    rt: &Runtime,
    mut req: Request<Body>,
    request_id: &str,
    method: &Method,
    path: &str,
    ip: IpAddr,
    started: Instant,
) -> Response<Body> {
    let m = &state.metrics;

    // The client-side upgrade future: once we return a `101`, the server completes it and yields
    // the raw client connection. Take it (removing the extension from `req`) before forwarding.
    let client_upgrade = hyper::upgrade::on(&mut req);

    // Build the upstream request: copy end-to-end headers AND the upgrade/connection headers
    // (the handshake needs them), add the forwarding headers, send an empty body.
    let uri = format!("{}{}", rt.pick_upstream(path), path);
    let mut up = Request::builder().method(req.method().clone()).uri(&uri);
    {
        let headers = up.headers_mut().expect("builder headers");
        // Strip hop-by-hop headers (the fixed set + any named by `Connection`) before forwarding,
        // so a client can't smuggle connection-scoped headers upstream — then re-add the handshake
        // headers the upgrade itself needs (`Connection: upgrade` + the requested `Upgrade`).
        let upgrade = req.headers().get(header::UPGRADE).cloned();
        let mut forwarded = req.headers().clone();
        strip_hop_by_hop(&mut forwarded);
        for (name, value) in forwarded.iter() {
            if name == header::HOST {
                continue;
            }
            headers.insert(name.clone(), value.clone());
        }
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        if let Some(v) = upgrade {
            headers.insert(header::UPGRADE, v);
        }
        if let Ok(v) = HeaderValue::from_str(&ip.to_string()) {
            headers.insert(HeaderName::from_static("x-forwarded-for"), v);
        }
        headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static(forwarded_proto(&rt.cfg, req.headers())),
        );
        if let Ok(v) = HeaderValue::from_str(request_id) {
            headers.insert(HeaderName::from_static(REQUEST_ID_HEADER), v);
        }
    }
    let upstream_req = match up.body(Full::new(Bytes::new())) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "failed to build upstream upgrade request");
            return finish(
                m,
                request_id,
                method,
                path,
                ip,
                started,
                "bad_gateway",
                text(StatusCode::BAD_GATEWAY, "Bad Gateway"),
            );
        }
    };

    // Bound the handshake by the same `upstream_timeout` as the buffered path, so a stalled
    // upstream can't pin this task (a `None` deadline means no timeout).
    let deadline = rt.upstream_timeout.map(|d| tokio::time::Instant::now() + d);
    let timed_out = || {
        warn!(upstream = %uri, "upstream timed out (upgrade)");
        finish(
            m,
            request_id,
            method,
            path,
            ip,
            started,
            "upstream_timeout",
            text(StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout"),
        )
    };

    let mut up_resp = match within(deadline, state.client.request(upstream_req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            warn!(error = %e, upstream = %uri, "upstream unreachable (upgrade)");
            return finish(
                m,
                request_id,
                method,
                path,
                ip,
                started,
                "upstream_error",
                text(StatusCode::BAD_GATEWAY, "Bad Gateway"),
            );
        }
        Err(_) => return timed_out(),
    };

    // Upstream declined to upgrade: forward its response as-is (the client sees the rejection),
    // but under the same deadline and `max_response_body` cap as the normal buffered path so a
    // rejected handshake can't hang or buffer an unbounded body.
    if up_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (mut parts, body) = up_resp.into_parts();
        // Collect the rejection body, capped by `max_response_body` when set. Both arms normalize
        // any read/limit error to `()` — the distinction doesn't change the `502` we return.
        let body_fut = async {
            if rt.max_response_body > 0 {
                Limited::new(body, rt.max_response_body)
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .map_err(|_| ())
            } else {
                body.collect().await.map(|c| c.to_bytes()).map_err(|_| ())
            }
        };
        let bytes = match within(deadline, body_fut).await {
            Ok(Ok(b)) => b,
            Ok(Err(())) => {
                warn!("upstream upgrade-rejection body failed or exceeded max_response_body");
                return finish(
                    m,
                    request_id,
                    method,
                    path,
                    ip,
                    started,
                    "bad_gateway",
                    text(StatusCode::BAD_GATEWAY, "Bad Gateway"),
                );
            }
            Err(_) => return timed_out(),
        };
        strip_hop_by_hop(&mut parts.headers);
        parts.headers.remove(header::CONTENT_LENGTH);
        let mut response = Response::from_parts(parts, Body::from(bytes));
        harden_response(&rt.cfg, &mut response);
        return finish(m, request_id, method, path, ip, started, "ok", response);
    }

    // `101`: wire up the upstream-side upgrade and splice the two connections once both complete.
    let upstream_upgrade = hyper::upgrade::on(&mut up_resp);
    tokio::spawn(async move {
        match tokio::join!(client_upgrade, upstream_upgrade) {
            (Ok(client_io), Ok(up_io)) => {
                let mut client_io = TokioIo::new(client_io);
                let mut up_io = TokioIo::new(up_io);
                if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut up_io).await {
                    debug!(error = %e, "websocket tunnel closed");
                }
            }
            (c, u) => warn!(
                client_ok = c.is_ok(),
                upstream_ok = u.is_ok(),
                "websocket upgrade did not complete"
            ),
        }
    });

    // Return the upstream's `101` — its headers carry `Sec-WebSocket-Accept` etc., and returning a
    // `101` is what makes the server upgrade the client side (completing `client_upgrade` above).
    // Strip hop-by-hop headers (the fixed set + any named by `Connection`) so the upstream can't
    // leak connection-scoped headers downstream, then re-add the handshake headers the upgrade
    // itself needs (`Connection: upgrade` + the negotiated `Upgrade`).
    let (mut parts, _body) = up_resp.into_parts();
    let upgrade = parts.headers.get(header::UPGRADE).cloned();
    strip_hop_by_hop(&mut parts.headers);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts
        .headers
        .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    if let Some(v) = upgrade {
        parts.headers.insert(header::UPGRADE, v);
    }
    let response = Response::from_parts(parts, Body::empty());
    finish(
        m,
        request_id,
        method,
        path,
        ip,
        started,
        "ws_upgrade",
        response,
    )
}

/// Wraps a streaming upstream body to tally egress bytes (response headers + each data frame)
/// and report them to managed-mode usage when the body is dropped — i.e. after the final frame
/// is sent, or earlier if the client disconnects mid-stream (we count what actually went out).
/// Used for SSE passthrough: the body isn't buffered, so the exact byte count the buffered path
/// takes up front can only be accumulated as frames flow.
struct CountingBody<B> {
    inner: B,
    metrics: Arc<Metrics>,
    ingress: usize,
    /// Running egress total: response header bytes, then each data frame as it passes.
    egress: usize,
}

impl<B> CountingBody<B> {
    fn new(inner: B, metrics: Arc<Metrics>, ingress: usize, header_egress: usize) -> Self {
        Self {
            inner,
            metrics,
            ingress,
            egress: header_egress,
        }
    }
}

impl<B> HttpBody for CountingBody<B>
where
    B: HttpBody<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled {
            if let Some(data) = frame.data_ref() {
                this.egress = this.egress.saturating_add(data.len());
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for CountingBody<B> {
    fn drop(&mut self) {
        self.metrics.add_usage_bytes(self.ingress, self.egress);
    }
}

/// Remove hop-by-hop headers so they don't leak across the proxy boundary (RFC 7230 §6.1):
/// the fixed [`HOP_BY_HOP`] set plus any header *named* in a `Connection` header. Applied in
/// both directions (request to upstream, response to client).
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // Header names listed in any `Connection` header are connection-specific; collect them
    // before mutating (the borrow of `headers` must end before we remove).
    let connection_named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    for name in connection_named {
        headers.remove(name);
    }
}

/// Decide the `X-Forwarded-Proto` to send upstream. If EdgeGuard terminates TLS, the client
/// hop is HTTPS. Otherwise, behind a trusted edge (`trust_forwarded_for`) we preserve the
/// proto the edge reported (falling back to `http`); an untrusted client's `X-Forwarded-Proto`
/// is never honored, mirroring the client-IP trust model. Returns a `'static` token so the
/// caller can build a `HeaderValue` without fallible parsing.
fn forwarded_proto(cfg: &Config, headers: &HeaderMap) -> &'static str {
    if cfg.tls.enabled {
        return "https";
    }
    if cfg.server.trust_forwarded_for {
        if let Some(value) = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
        {
            match value.split(',').next().map(str::trim) {
                Some(p) if p.eq_ignore_ascii_case("https") => return "https",
                Some(p) if p.eq_ignore_ascii_case("http") => return "http",
                _ => {}
            }
        }
    }
    "http"
}

/// Pick the most specific (longest-prefix) per-route limiter matching `path`, if any.
fn longest_route<'a>(routes: &'a [RouteLimiter], path: &str) -> Option<&'a RouteLimiter> {
    routes
        .iter()
        .filter(|r| path.starts_with(&r.prefix))
        .max_by_key(|r| r.prefix.len())
}

/// The HSTS header value EdgeGuard emits when `headers.hsts` is on: a two-year `max-age`
/// including subdomains. A named constant so the live proxy and the static-host config
/// generator ([`crate::generate`]) can't drift on it.
pub const HSTS_VALUE: &str = "max-age=63072000; includeSubDomains";

/// The constant security response headers EdgeGuard injects, derived from the `[headers]`
/// policy. This is the **single source of truth** shared by the live response-hardening path
/// ([`harden_response`]) and the static-host config generator ([`crate::generate`]), so a
/// generated `_headers` file / edge-middleware snippet matches exactly what the proxy would add
/// at runtime. Returns `(name, value)` pairs with canonically-cased names (for readable
/// generated output); the proxy normalizes the case when it inserts them.
///
/// Cookie hardening and leaky-header *stripping* are deliberately **not** here: both rewrite the
/// upstream's actual response (`Set-Cookie`, `Server`/`X-Powered-By`), which a static file that
/// can only "always add this header" cannot express. The generator documents that gap; the
/// WASM worker, which sees the real response, applies them too.
pub fn security_headers(cfg: &HeadersCfg) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::with_capacity(6);
    out.push(("X-Content-Type-Options", "nosniff".to_string()));
    if !cfg.frame_options.is_empty() {
        out.push(("X-Frame-Options", cfg.frame_options.clone()));
    }
    if !cfg.referrer_policy.is_empty() {
        out.push(("Referrer-Policy", cfg.referrer_policy.clone()));
    }
    if !cfg.permissions_policy.is_empty() {
        out.push(("Permissions-Policy", cfg.permissions_policy.clone()));
    }
    if !cfg.csp.is_empty() {
        // Append a report-uri directive if configured, and choose enforce vs. report-only.
        let mut value = cfg.csp.clone();
        if !cfg.csp_report_uri.is_empty() {
            value.push_str("; report-uri ");
            value.push_str(&cfg.csp_report_uri);
        }
        let name = if cfg.csp_report_only {
            "Content-Security-Policy-Report-Only"
        } else {
            "Content-Security-Policy"
        };
        out.push((name, value));
    }
    if cfg.hsts {
        out.push(("Strict-Transport-Security", HSTS_VALUE.to_string()));
    }
    out
}

/// Inject security headers, harden Set-Cookie, and strip leaky headers.
fn harden_response(cfg: &Config, resp: &mut Response<Body>) {
    let h = resp.headers_mut();

    // Inject the constant security headers (shared with the static-host generator via
    // `security_headers`, so the two never diverge). `from_bytes` normalizes the canonical
    // casing to lowercase; these names/values are all valid, so the inserts don't fail.
    for (name, value) in security_headers(&cfg.headers) {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            h.insert(n, v);
        }
    }

    // Strip leaky headers.
    for name in &cfg.headers.strip {
        if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
            h.remove(hn);
        }
    }

    // Harden cookies: ensure Secure, HttpOnly, and a SameSite default.
    if cfg.headers.force_secure_cookies {
        let cookies: Vec<HeaderValue> = h.get_all(header::SET_COOKIE).iter().cloned().collect();
        if !cookies.is_empty() {
            h.remove(header::SET_COOKIE);
            for c in cookies {
                if let Ok(s) = c.to_str() {
                    let hardened = harden_cookie(s);
                    if let Ok(v) = HeaderValue::from_str(&hardened) {
                        h.append(header::SET_COOKIE, v);
                    }
                } else {
                    h.append(header::SET_COOKIE, c);
                }
            }
        }
    }
}

fn harden_cookie(cookie: &str) -> String {
    // Inspect attribute *names* (the tokens after the first `name=value` pair), not the
    // whole string — otherwise a value like `session=securetoken` would look like it
    // already carries `Secure` and we'd skip hardening it.
    let attrs: std::collections::HashSet<String> = cookie
        .split(';')
        .skip(1)
        .filter_map(|p| p.trim().split('=').next())
        .map(|k| k.trim().to_ascii_lowercase())
        .collect();

    let mut out = cookie.trim_end_matches(';').to_string();
    if !attrs.contains("secure") {
        out.push_str("; Secure");
    }
    if !attrs.contains("httponly") {
        out.push_str("; HttpOnly");
    }
    if !attrs.contains("samesite") {
        out.push_str("; SameSite=Lax");
    }
    out
}

/// Run `fut` bounded by an optional deadline. `None` means no timeout. On success returns
/// the future's own output; `Err(Elapsed)` if the deadline passed first.
async fn within<F: Future>(
    deadline: Option<tokio::time::Instant>,
    fut: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    match deadline {
        Some(dl) => tokio::time::timeout_at(dl, fut).await,
        None => Ok(fut.await),
    }
}

fn text(status: StatusCode, msg: &str) -> Response<Body> {
    let mut resp = Response::new(Body::from(msg.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

/// Emit a structured access-log line, record metrics, stamp the response with `X-Request-Id`,
/// and return it.
// All args are part of the access-log/identity tuple for one request; bundling them in a struct
// would just move the same fields behind another name at every (already terse) call site.
#[allow(clippy::too_many_arguments)]
fn finish(
    metrics: &Metrics,
    request_id: &str,
    method: &Method,
    path: &str,
    ip: IpAddr,
    started: Instant,
    outcome: &str,
    mut resp: Response<Body>,
) -> Response<Body> {
    // Echo the request id on every response (including error responses) so a client / upstream /
    // log can be correlated. `resolve_request_id` guarantees it's a valid header value.
    if let Ok(v) = HeaderValue::from_str(request_id) {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    let elapsed = started.elapsed();
    info!(
        request_id,
        %method,
        path = %path,
        client_ip = %ip,
        status = resp.status().as_u16(),
        outcome,
        latency_ms = elapsed.as_millis() as u64,
        "request"
    );
    metrics.record_request(outcome);
    metrics.observe_latency(elapsed);
    // Managed mode: count every finished request (proxied or rejected) toward the usage delta.
    // Cheap (two relaxed atomic adds) and inert unless a control plane drains it for reporting.
    metrics.add_usage_request();
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(name: &'static str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn path_prefix_matches_on_segment_boundary_only() {
        // Exact, sub-path, and query-boundary matches.
        assert!(path_prefix_matches("/api", "/api"));
        assert!(path_prefix_matches("/api/users", "/api"));
        assert!(path_prefix_matches("/api?x=1", "/api"));
        // A trailing-slash prefix matches its sub-paths.
        assert!(path_prefix_matches("/api/users", "/api/"));
        // Sibling paths sharing a textual prefix must NOT match.
        assert!(!path_prefix_matches("/apiary", "/api"));
        assert!(!path_prefix_matches("/apiary/honey", "/api"));
        // `/` matches everything.
        assert!(path_prefix_matches("/anything", "/"));
    }

    #[test]
    fn client_ip_ignores_xff_when_untrusted() {
        let peer: SocketAddr = "203.0.113.9:55000".parse().unwrap();
        let h = headers_with("x-forwarded-for", "1.2.3.4");
        // Untrusted: a directly reachable client must not be able to spoof its IP.
        assert_eq!(client_ip(&h, peer, false), peer.ip());
    }

    #[test]
    fn client_ip_uses_first_xff_hop_when_trusted() {
        let peer: SocketAddr = "203.0.113.9:55000".parse().unwrap();
        let h = headers_with("x-forwarded-for", "1.2.3.4, 5.6.7.8");
        assert_eq!(client_ip(&h, peer, true).to_string(), "1.2.3.4");
    }

    #[test]
    fn client_ip_falls_back_to_peer_on_missing_or_garbage_xff() {
        let peer: SocketAddr = "203.0.113.9:55000".parse().unwrap();
        assert_eq!(client_ip(&HeaderMap::new(), peer, true), peer.ip());
        let garbage = headers_with("x-forwarded-for", "not-an-ip");
        assert_eq!(client_ip(&garbage, peer, true), peer.ip());
    }

    #[test]
    fn header_bytes_sums_names_and_values() {
        let mut h = HeaderMap::new();
        h.insert("a", HeaderValue::from_static("bb")); // 1 + 2
        h.insert("ccc", HeaderValue::from_static("dddd")); // 3 + 4
        assert_eq!(header_bytes(&h), 1 + 2 + 3 + 4);
    }

    #[test]
    fn strip_hop_by_hop_removes_fixed_and_connection_named() {
        let mut h = HeaderMap::new();
        h.insert(
            "connection",
            HeaderValue::from_static("keep-alive, X-Custom-Hop"),
        );
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("x-custom-hop", HeaderValue::from_static("secret"));
        h.insert("content-type", HeaderValue::from_static("text/plain"));
        strip_hop_by_hop(&mut h);
        assert!(!h.contains_key("connection"));
        assert!(!h.contains_key("keep-alive"));
        // A header named by Connection is connection-specific and must be dropped.
        assert!(!h.contains_key("x-custom-hop"));
        // An end-to-end header is preserved.
        assert!(h.contains_key("content-type"));
    }

    #[test]
    fn forwarded_proto_reflects_tls_and_trust() {
        let mut cfg = Config::default();

        // We terminate TLS -> always https, regardless of any incoming header.
        cfg.tls.enabled = true;
        assert_eq!(
            forwarded_proto(&cfg, &headers_with("x-forwarded-proto", "http")),
            "https"
        );

        // Plain HTTP, untrusted: http, and an incoming XFP is NOT trusted.
        cfg.tls.enabled = false;
        cfg.server.trust_forwarded_for = false;
        assert_eq!(
            forwarded_proto(&cfg, &headers_with("x-forwarded-proto", "https")),
            "http"
        );

        // Plain HTTP behind a trusted edge: preserve the edge's reported proto.
        cfg.server.trust_forwarded_for = true;
        assert_eq!(
            forwarded_proto(&cfg, &headers_with("x-forwarded-proto", "https")),
            "https"
        );
        assert_eq!(
            forwarded_proto(&cfg, &headers_with("x-forwarded-proto", "http, https")),
            "http"
        );
        // Missing or unrecognized -> http.
        assert_eq!(forwarded_proto(&cfg, &HeaderMap::new()), "http");
        assert_eq!(
            forwarded_proto(&cfg, &headers_with("x-forwarded-proto", "garbage")),
            "http"
        );
    }

    #[test]
    fn longest_route_picks_most_specific_prefix() {
        let mk = |p: &str| RouteLimiter {
            prefix: p.to_string(),
            limiter: Arc::new(RateLimiter::keyed(governor::Quota::per_second(
                std::num::NonZeroU32::new(1).unwrap(),
            ))),
        };
        let routes = vec![mk("/api/"), mk("/api/admin/")];
        assert_eq!(
            longest_route(&routes, "/api/admin/users").map(|r| r.prefix.as_str()),
            Some("/api/admin/")
        );
        assert_eq!(
            longest_route(&routes, "/api/things").map(|r| r.prefix.as_str()),
            Some("/api/")
        );
        assert!(longest_route(&routes, "/public").is_none());
    }

    #[test]
    fn path_prefix_matches_on_segment_boundaries() {
        // A prefix without a trailing slash must not match a sibling path.
        assert!(path_prefix_matches("/api", "/api")); // exact
        assert!(path_prefix_matches("/api/users", "/api")); // segment boundary
        assert!(path_prefix_matches("/api?q=1", "/api")); // query boundary
        assert!(!path_prefix_matches("/apiary", "/api")); // sibling — must NOT match
                                                          // A trailing-slash prefix is a clean boundary by construction.
        assert!(path_prefix_matches("/api/users", "/api/"));
        assert!(!path_prefix_matches("/apiary", "/api/"));
        // "/" matches everything.
        assert!(path_prefix_matches("/anything", "/"));
    }

    #[test]
    fn harden_cookie_adds_missing_flags() {
        let out = harden_cookie("sid=abc");
        assert!(out.contains("; Secure"), "{out}");
        assert!(out.contains("; HttpOnly"), "{out}");
        assert!(out.contains("; SameSite=Lax"), "{out}");
    }

    #[test]
    fn harden_cookie_preserves_existing_attributes() {
        let out = harden_cookie("sid=abc; HttpOnly; SameSite=Strict");
        assert!(out.contains("; Secure"), "{out}");
        assert!(out.contains("SameSite=Strict"), "{out}");
        // existing SameSite isn't overridden, HttpOnly isn't duplicated
        assert!(!out.contains("SameSite=Lax"), "{out}");
        assert_eq!(out.matches("HttpOnly").count(), 1, "{out}");
    }

    #[test]
    fn harden_cookie_value_resembling_an_attr_is_not_skipped() {
        // The value contains the substring "secure" but there is no Secure *attribute*;
        // it must still be added (regression guard for the token-vs-substring fix).
        let out = harden_cookie("session=securetoken");
        assert!(out.contains("; Secure"), "{out}");
    }

    #[test]
    fn security_headers_reflects_config_toggles() {
        // Defaults: every header present, CSP enforced (not report-only).
        let cfg = HeadersCfg::default();
        let got = security_headers(&cfg);
        let names: Vec<&str> = got.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"X-Content-Type-Options"));
        assert!(names.contains(&"X-Frame-Options"));
        assert!(names.contains(&"Referrer-Policy"));
        assert!(names.contains(&"Permissions-Policy"));
        assert!(names.contains(&"Content-Security-Policy"));
        assert!(names.contains(&"Strict-Transport-Security"));
        assert!(!names.contains(&"Content-Security-Policy-Report-Only"));

        // Disabling HSTS and clearing frame_options drops exactly those; report-only flips the
        // CSP header name and report_uri is appended to the value.
        let cfg = HeadersCfg {
            hsts: false,
            frame_options: String::new(),
            csp: "default-src 'self'".into(),
            csp_report_only: true,
            csp_report_uri: "/__edgeguard/csp-report".into(),
            ..HeadersCfg::default()
        };
        let got = security_headers(&cfg);
        let map: std::collections::HashMap<&str, String> =
            got.iter().map(|(n, v)| (*n, v.clone())).collect();
        assert!(!map.contains_key("Strict-Transport-Security"));
        assert!(!map.contains_key("X-Frame-Options"));
        assert!(!map.contains_key("Content-Security-Policy"));
        assert_eq!(
            map.get("Content-Security-Policy-Report-Only")
                .map(|s| s.as_str()),
            Some("default-src 'self'; report-uri /__edgeguard/csp-report")
        );
    }
}
