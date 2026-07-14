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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// Compiled LLM token-metering runtime (price book + on/off). Inert when `[llm]` is disabled.
    pub llm: Arc<crate::llm::LlmRuntime>,
    /// Compiled LLM hard-budget engine (gateway L1). `None` when no `[[llm.budgets]]` are configured.
    pub budgets: Option<Arc<crate::budget::BudgetEngine>>,
    /// Compiled BYO-key vault (gateway L2). `None` when no `[[llm.keys]]` are configured; when set,
    /// every proxied request must present a known virtual key.
    pub keyvault: Option<Arc<crate::keyvault::KeyVault>>,
    /// Compiled edge-DLP engine (gateway L3). `None` when `[llm.dlp].mode = "off"`.
    pub dlp: Option<Arc<crate::dlp::DlpEngine>>,
    /// Compiled OTLP span emitter (gateway L4). Inert when `[llm.telemetry].enabled = false` or no
    /// endpoint is set; emits one OpenInference span per metered LLM request, fire-and-forget.
    pub telemetry: Arc<crate::telemetry::TelemetryRuntime>,
    /// Compiled outbound alerter (gateway L4). Inert when `[alerts].enabled = false` or no webhook is
    /// set; fires a Slack-compatible alert when a hard budget crosses its threshold, fire-and-forget.
    pub alerts: Arc<crate::alert::AlertRuntime>,
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
        // Vault check for upgrade connections: validate the virtual key and swap it for the
        // provider key before tunnelling. WebSocket frames don't carry a parseable JSON body, so
        // model egress can't be enforced; any key with a non-empty allowlist is denied
        // (fail-closed — the tunnel could reach any model on the upstream).
        let mut req = req;
        if let Some(vault) = rt.keyvault.as_ref() {
            let presented = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(str::trim);
            match presented.and_then(|k| vault.lookup(k)) {
                Some(entry) => {
                    if !entry.model_allowed(None) {
                        m.record_keyvault("denied_model");
                        warn!(key = %entry.label(), client_ip = %ip, "WebSocket upgrade denied: key has a model allowlist (model cannot be verified on upgrade connections)");
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
                    match HeaderValue::from_str(&format!("Bearer {}", entry.provider_key())) {
                        Ok(v) => {
                            m.record_keyvault("swapped");
                            req.headers_mut().insert(header::AUTHORIZATION, v);
                        }
                        Err(e) => {
                            warn!(key = %entry.label(), error = %e, "provider key is not a valid Authorization header value");
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
                    }
                }
                None => {
                    m.record_keyvault("denied_key");
                    return finish(
                        m,
                        &rid,
                        &method,
                        &path,
                        ip,
                        started,
                        "unauthorized",
                        text(StatusCode::UNAUTHORIZED, "Unauthorized"),
                    );
                }
            }
        }
        return proxy_upgrade(state, rt, req, &rid, &method, &path, ip, started).await;
    }

    // 5) Buffer the body up to the configured limit.
    let (parts, body) = req.into_parts();
    // Capture an inbound W3C `traceparent` (if any) so an emitted LLM span stitches under the
    // caller's trace. Cheap header read; only used when `[llm.telemetry]` is enabled.
    let traceparent = parts
        .headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // Team/tag for per-team token/cost metrics (chargeback/showback), from `[llm].team_header`
    // (default `x-edgeguard-team`; absent → the shared `_none` bucket). Owned so the streamed-path
    // meter can carry it past the request borrow. Matches the per-team budget scope's keying.
    let llm_team: Option<String> = parts
        .headers
        .get(rt.cfg.llm.team_header.as_str())
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let mut body_bytes = match axum::body::to_bytes(body, rt.max_body).await {
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

    // Reversible mask map (gateway L3): populated when inbound redaction runs in reversible mode, so
    // the response can be unmasked back to the caller's own values (see the response paths below).
    // Empty unless reversible masking actually replaces a span.
    let mut mask_map = crate::dlp::MaskMap::default();

    // LLM edge DLP (gateway L3) — inbound prompt. Scan the request body for PII/secrets and apply
    // the configured mode before forwarding: `block` rejects 403 (the secret never leaves), `redact`
    // rewrites the forwarded body, `report` logs + counts and passes through unchanged.
    if let Some(dlp) = rt.dlp.as_ref() {
        if dlp.scan_request() {
            let body_text = String::from_utf8_lossy(&body_bytes);
            let findings = dlp.scan(&body_text);
            if !findings.is_empty() {
                for f in &findings {
                    m.record_dlp_finding(f.category);
                }
                match dlp.mode() {
                    crate::dlp::DlpMode::Block => {
                        m.record_dlp_blocked();
                        warn!(findings = findings.len(), client_ip = %ip, "LLM request blocked by DLP (inbound PII/secret)");
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
                    crate::dlp::DlpMode::Redact => {
                        // Reversible mode masks to placeholders (recorded in `mask_map`) so the
                        // response can restore them; plain redact rewrites irreversibly.
                        let redacted = if dlp.reversible() {
                            dlp.redact_reversible(&body_text, &findings, &mut mask_map)
                        } else {
                            dlp.redact(&body_text, &findings)
                        };
                        warn!(
                            findings = findings.len(),
                            reversible = dlp.reversible(),
                            "DLP redacted inbound request"
                        );
                        body_bytes = Bytes::from(redacted);
                    }
                    crate::dlp::DlpMode::Report => {
                        warn!(
                            findings = findings.len(),
                            "DLP findings in inbound request (report-only)"
                        )
                    }
                    crate::dlp::DlpMode::Off => {}
                }
            }
        }
    }

    // LLM token metering (gateway L0): if enabled, note the request's `model` *before* the body is
    // forwarded (it's moved into the upstream request below). `None` for non-JSON / non-LLM bodies,
    // in which case the request is simply not metered as LLM traffic. Metering is observe-only.
    // Also parse when the vault is active: the model is needed for egress-allowlist enforcement and
    // a missing model must be treated as denied for any key that has a non-empty allowlist.
    let llm_model = if rt.llm.enabled || rt.keyvault.is_some() || rt.budgets.is_some() {
        crate::llm::parse_request_model(&body_bytes)
    } else {
        None
    };

    // LLM key vault + egress governance (gateway L2): when configured, every proxied request must
    // present a known virtual key. We resolve it to the mapped provider key (injected upstream
    // below, so the provider secret never reaches the client) and enforce the key's model egress
    // allowlist. Runs before the budget reserve so an unknown key / disallowed model never consumes
    // budget. `upstream_auth`, when set, replaces the outbound `Authorization` header.
    let mut upstream_auth: Option<HeaderValue> = None;
    if let Some(vault) = rt.keyvault.as_ref() {
        let presented = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::trim);
        match presented.and_then(|k| vault.lookup(k)) {
            Some(entry) => {
                // Fail closed: a request whose model is absent or unparseable is denied when the
                // key has a non-empty allowlist — same as an explicitly off-list model.
                if !entry.model_allowed(llm_model.as_deref()) {
                    let model = llm_model.as_deref().unwrap_or("<missing>");
                    m.record_keyvault("denied_model");
                    warn!(key = %entry.label(), model = %model, client_ip = %ip, "LLM request denied: model off the key's egress allowlist");
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
                // Convert to a HeaderValue now so a malformed provider key is caught here and
                // fails with 502 rather than silently leaving the client's virtual key in place.
                match HeaderValue::from_str(&format!("Bearer {}", entry.provider_key())) {
                    Ok(v) => {
                        m.record_keyvault("swapped");
                        upstream_auth = Some(v);
                    }
                    Err(e) => {
                        warn!(key = %entry.label(), error = %e, "provider key is not a valid Authorization header value");
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
                }
            }
            None => {
                m.record_keyvault("denied_key");
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "unauthorized",
                    text(StatusCode::UNAUTHORIZED, "Unauthorized"),
                );
            }
        }
    }

    // LLM unpriced-model policy (gateway L0): when `on_unpriced_model = "block"` and a price book is
    // configured, a request for a model absent from that book is rejected `402` *before* it reaches
    // the upstream — an unpriced model is never served at a silent $0 (the LiteLLM `#24770` failure,
    // designed out). Metering-only deployments (empty `[llm.models]`) never trip this. Runs after the
    // vault (an unknown key is still `401` first) and before the budget reserve (no budget consumed).
    if let Some(model) = llm_model.as_ref() {
        if rt.llm.reject_unpriced(model) {
            warn!(model = %model, client_ip = %ip, "LLM request denied: model not in price book (on_unpriced_model=block)");
            return finish(
                m,
                &rid,
                &method,
                &path,
                ip,
                started,
                "unpriced_model",
                text(
                    StatusCode::PAYMENT_REQUIRED,
                    "Payment Required: model not in price book",
                ),
            );
        }
    }

    // LLM hard budgets (gateway L1): reserve an estimate against every applicable budget *before*
    // forwarding, so an over-budget request is denied 429 and never reaches the upstream. The
    // returned guard reconciles to actual usage on success and auto-releases on any early return
    // (upstream error / timeout) via its Drop. Only runs when budgets are configured and this is an
    // LLM request with a known model.
    let mut budget_guard: Option<ReservationGuard> = None;
    if let (Some(engine), Some(model)) = (rt.budgets.as_ref(), llm_model.as_ref()) {
        let est_prompt = crate::llm::estimate_prompt_tokens(body_bytes.len());
        let est_completion = crate::llm::parse_request_max_tokens(&body_bytes)
            .unwrap_or(rt.cfg.llm.default_max_tokens);
        let estimate = crate::budget::Spend {
            tokens: est_prompt.saturating_add(est_completion),
            cost_micros: rt
                .llm
                .cost_micros(
                    model,
                    &crate::llm::Usage {
                        prompt_tokens: est_prompt,
                        completion_tokens: est_completion,
                        ..Default::default()
                    },
                )
                .unwrap_or(0),
        };
        // Team/tag for the per-team scope + chargeback, from the configured header (default
        // `x-edgeguard-team`). Absent → the shared `_none` bucket.
        let team = parts
            .headers
            .get(rt.cfg.llm.team_header.as_str())
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let dims = crate::budget::Dims {
            principal: principal.as_deref(),
            // Normalize a provider-prefixed model ("openai/gpt-4o") to the bare name for budget
            // attribution, so a prefixed request can't silently escape a bare-named per-model budget.
            model: crate::llm::canonical_model(model),
            team,
        };
        match engine.reserve(dims, estimate).await {
            crate::budget::Reserved::Ok(reservation) => {
                // Feed the near-limit gauge with each admitted budget's post-reserve consumption,
                // and fire an alert (edge-triggered, fire-and-forget) when one crosses the threshold.
                for obs in reservation.observations() {
                    m.record_budget_consumed(&obs.name, obs.consumed_ratio);
                    rt.alerts.fire_budget_alert(&obs.name, obs.consumed_ratio);
                }
                // Only non-zero on the fail-open path: a store error rolled back an earlier partial
                // reservation before admitting anyway. Same drift signal as a failed reconcile/release.
                m.record_budget_reconcile_failures(reservation.rollback_failures());
                budget_guard = Some(ReservationGuard {
                    engine: Arc::clone(engine),
                    reservation: Some(reservation),
                    metrics: Arc::clone(m),
                });
            }
            crate::budget::Reserved::Denied(denial) => {
                m.record_budget_blocked(denial.scope.label());
                m.record_budget_reconcile_failures(denial.rollback_failures);
                warn!(budget = %denial.name, scope = %denial.scope.label(), model = %model, client_ip = %ip, "LLM request denied: budget exhausted");
                // A cost cap answers 402 (Payment Required — the spend, not the rate, is the limit);
                // a token cap answers 429 (Too Many Requests). Both carry the `over_budget` outcome.
                let (status, body) = match denial.unit {
                    crate::budget::BudgetUnit::UsdMicros => (
                        StatusCode::PAYMENT_REQUIRED,
                        "Payment Required: budget exhausted",
                    ),
                    crate::budget::BudgetUnit::Tokens => {
                        (StatusCode::TOO_MANY_REQUESTS, "Too Many Requests")
                    }
                };
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "over_budget",
                    text(status, body),
                );
            }
            crate::budget::Reserved::Error { rollback_failures } => {
                m.record_budget_reconcile_failures(rollback_failures);
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
        // The body is re-sent from a sized `Full`, so the client's Content-Length may be stale (it
        // is once DLP redaction rewrote the body). Drop it and let the upstream client recompute the
        // correct length from the body, rather than forwarding a mismatched header.
        forwarded.remove(header::CONTENT_LENGTH);
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
        // L2 key vault: replace the client's `Authorization` (which carried the virtual key) with the
        // mapped provider key. The provider secret only ever travels edge→upstream — never back to
        // the client — and the client's virtual key never reaches the upstream. The value was
        // already validated as a legal HeaderValue when upstream_auth was set above.
        if let Some(v) = upstream_auth {
            headers.insert(header::AUTHORIZATION, v);
        }
    }

    // Content capture (gateway L4): grab the request body for the emitted span *before* it is
    // forwarded and consumed. `body_bytes` is already the DLP-redacted/masked form at this point;
    // `capture_for_span` additionally scans+redacts so capture is safe under any DLP mode. Only when
    // telemetry + content capture are both on; `None` otherwise (no cost when off).
    let telem_input: Option<String> = (rt.telemetry.enabled && rt.telemetry.capture_content)
        .then(|| capture_for_span(rt.dlp.as_ref(), &body_bytes, rt.telemetry.max_content_bytes));

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
    //
    //     Carve-out: when outbound DLP is in `block` mode, streaming can't fail closed — frames would
    //     reach the client before the body could be judged, and a stream can't be un-sent. So skip
    //     passthrough and fall through to the buffered path (bounded by `max_response_body`), which
    //     applies the same block enforcement to `text/event-stream` bodies as to any other response.
    //     Block-mode operators trade incremental delivery for the fail-closed contract they configured;
    //     `report`/`redact` still stream (redaction rewrites frames inline as they flow).
    let dlp_blocks_response = rt
        .dlp
        .as_ref()
        .is_some_and(|d| d.scan_response() && matches!(d.mode(), crate::dlp::DlpMode::Block));
    if rt.stream_passthrough && is_event_stream(&resp_parts.headers) && !dlp_blocks_response {
        strip_hop_by_hop(&mut resp_parts.headers);
        resp_parts.headers.remove(header::CONTENT_LENGTH);
        let header_egress = header_bytes(&resp_parts.headers);
        // LLM metering on the streamed path: capture the stream tail so the terminal `usage` frame
        // can be parsed when the body finishes (see `CountingBody`'s `Drop`). The L1 budget
        // reservation rides along — moved out of the guard so the guard's Drop won't release it; the
        // body's Drop reconciles it to the streamed usage (or releases on no usage) instead.
        let llm_meter = llm_model.as_ref().map(|model| {
            let (engine, reservation) = match budget_guard.take() {
                Some(mut g) => (Some(g.engine.clone()), g.reservation.take()),
                None => (None, None),
            };
            // Telemetry span context: built only when emission is on (avoids a per-request UUID
            // otherwise). Carries an inbound `traceparent` so the gateway span stitches under the app.
            let (telemetry, ctx) = if rt.telemetry.enabled {
                (
                    Some(Arc::clone(&rt.telemetry)),
                    crate::telemetry::TraceContext::from_traceparent(traceparent.as_deref()),
                )
            } else {
                (None, crate::telemetry::TraceContext::from_traceparent(None))
            };
            LlmStreamMeter {
                model: model.clone(),
                llm: Arc::clone(&rt.llm),
                tail: Vec::new(),
                engine,
                reservation,
                started,
                first_at: None,
                last_at: None,
                telemetry,
                ctx,
                input: telem_input.clone(),
                team: llm_team.clone(),
                key: principal.clone(),
            }
        });
        // Reversible unmasking (gateway L3): when active, the stream is *unmasked* back to the caller's
        // own values from the inbound mask map — the provider only ever saw placeholders. This
        // replaces the outbound DLP scan on the streamed path (restore, not re-detect).
        let reversible_stream = rt.dlp.as_ref().is_some_and(|d| d.reversible());
        // Edge-DLP scan over the streamed response. Counts findings (report); additionally rewrites
        // frames when `redact` + `stream_redact` are on (deterministic spans only, NER stays off the
        // stream). Built when DLP is on and response scanning is enabled — but not in reversible mode,
        // where the unmasker below takes over the stream.
        let dlp_scanner = if reversible_stream {
            None
        } else {
            rt.dlp
                .as_ref()
                .filter(|d| d.scan_response())
                .map(|d| DlpStreamScanner {
                    engine: Arc::clone(d),
                    metrics: Arc::clone(m),
                    redact: d.stream_redact(),
                    carry: Vec::new(),
                })
        };
        let unmasker = reversible_stream.then(|| UnmaskStreamState {
            map: std::mem::take(&mut mask_map),
            carry: Vec::new(),
        });
        let body = Body::new(CountingBody::new(
            resp_body,
            Arc::clone(m),
            ingress_bytes,
            header_egress,
            llm_meter,
            dlp_scanner,
            unmasker,
        ));
        let mut response = Response::from_parts(resp_parts, body);
        harden_response(&rt.cfg, &mut response);
        // CORS decoration happens centrally in `handle` (covers this and every error path).
        return finish(m, &rid, &method, &path, ip, started, "ok", response);
    }

    // Buffer the upstream body, optionally capped so a huge response can't OOM the proxy.
    let mut resp_bytes = if rt.max_response_body > 0 {
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

    // LLM token metering on the buffered (non-streaming) path: read the upstream's own `usage`
    // object. Priced model -> tokens + cost; unmapped model -> tokens only; no usage -> just count
    // the request. Best-effort and observe-only — never affects the response.
    if let Some(model) = &llm_model {
        let usage = if is_event_stream(&resp_parts.headers) {
            crate::llm::parse_sse_usage(&resp_bytes)
        } else {
            crate::llm::parse_response_usage(&resp_bytes)
        };
        let actual = match usage {
            Some(usage) => {
                let cost = rt.llm.cost_micros(model, &usage);
                let sample = crate::metrics::LlmSample {
                    tokens_in: usage.prompt_tokens,
                    tokens_out: usage.completion_tokens,
                    cached_tokens: usage.cached_tokens,
                    reasoning_tokens: usage.reasoning_tokens,
                    cost_micros: cost,
                };
                m.record_llm_usage(model, sample);
                m.record_llm_team_usage(llm_team.as_deref().unwrap_or("_none"), &sample);
                m.record_llm_key_usage(principal.as_deref().unwrap_or("_anon"), &sample);
                // Emit an OpenInference span for this (buffered) request — gateway L4,
                // fire-and-forget. No TTFT/TPOT on the non-streaming path. When content capture is on,
                // attach the redacted request (captured pre-forward) + redacted response body. At this
                // point `resp_bytes` is pre-unmask/pre-outbound-redaction, so `capture_for_span` does
                // the redaction so no PII/secret is stored regardless of DLP mode.
                if rt.telemetry.enabled {
                    let (start_nanos, end_nanos) = wall_clock_span(started);
                    let output = rt.telemetry.capture_content.then(|| {
                        capture_for_span(
                            rt.dlp.as_ref(),
                            &resp_bytes,
                            rt.telemetry.max_content_bytes,
                        )
                    });
                    rt.telemetry.emit(crate::telemetry::SpanRecord {
                        ctx: crate::telemetry::TraceContext::from_traceparent(
                            traceparent.as_deref(),
                        ),
                        name: "llm.chat".into(),
                        model: model.clone(),
                        provider: None,
                        prompt_tokens: usage.prompt_tokens,
                        completion_tokens: usage.completion_tokens,
                        cached_tokens: usage.cached_tokens,
                        reasoning_tokens: usage.reasoning_tokens,
                        cost_micros: cost,
                        start_unix_nano: start_nanos,
                        end_unix_nano: end_nanos,
                        ttft: None,
                        tpot: None,
                        status_ok: resp_parts.status.is_success(),
                        input: telem_input.clone(),
                        output,
                        session_id: None,
                    });
                }
                crate::budget::Spend {
                    tokens: usage.total_tokens(),
                    cost_micros: cost.unwrap_or(0),
                }
            }
            None => {
                m.record_llm_no_usage();
                crate::budget::Spend::default()
            }
        };
        // Reconcile the L1 budget reservation to actual spend (releases the over-estimate, or charges
        // a low one). `commit` consumes the guard so its Drop won't also release.
        if let Some(guard) = budget_guard.take() {
            guard.commit(actual).await;
        }
    }

    // Reversible unmasking (gateway L3): when reversible masking is active, the response is *restored*
    // to the caller's own values from the inbound mask map — the provider only ever saw placeholders.
    // This replaces the outbound scan/redact (the goal is restoration, not re-detection), so it runs
    // instead of the block below.
    let reversible_active = rt.dlp.as_ref().is_some_and(|d| d.reversible());
    if reversible_active {
        if !mask_map.is_empty() {
            let restored = mask_map.unmask(&String::from_utf8_lossy(&resp_bytes));
            resp_bytes = Bytes::from(restored);
        }
    } else if let Some(dlp) = rt.dlp.as_ref() {
        // LLM edge DLP (gateway L3) — outbound completion (buffered path only; the streamed path scans
        // frame-by-frame in `CountingBody`). `block` withholds the body, `redact` rewrites it, `report`
        // logs + counts. Runs after usage metering so token accounting reads the original `usage`.
        if dlp.scan_response() {
            let body_text = String::from_utf8_lossy(&resp_bytes);
            let findings = dlp.scan(&body_text);
            if !findings.is_empty() {
                for f in &findings {
                    m.record_dlp_finding(f.category);
                }
                match dlp.mode() {
                    crate::dlp::DlpMode::Block => {
                        m.record_dlp_blocked();
                        warn!(
                            findings = findings.len(),
                            "DLP withheld response body (outbound PII/secret)"
                        );
                        resp_parts.status = StatusCode::FORBIDDEN;
                        resp_bytes =
                            Bytes::from_static(b"{\"error\":\"response withheld by DLP policy\"}");
                        resp_parts.headers.remove(header::CONTENT_TYPE);
                        resp_parts.headers.insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/json"),
                        );
                    }
                    crate::dlp::DlpMode::Redact => {
                        warn!(findings = findings.len(), "DLP redacted response body");
                        resp_bytes = Bytes::from(dlp.redact(&body_text, &findings));
                    }
                    crate::dlp::DlpMode::Report => {
                        warn!(
                            findings = findings.len(),
                            "DLP findings in response (report-only)"
                        )
                    }
                    crate::dlp::DlpMode::Off => {}
                }
            }
        }
    }

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
    /// LLM token metering for a streamed response, when `[llm]` is on and this is an LLM request.
    llm: Option<LlmStreamMeter>,
    /// Edge-DLP scanner for the streamed response (gateway L3): counts findings, and in
    /// `redact` + `stream_redact` mode rewrites the emitted bytes (deterministic spans only).
    dlp: Option<DlpStreamScanner>,
    /// Reversible unmask over the streamed response (gateway L3): restores placeholders to the
    /// caller's own values, carrying a boundary tail so a placeholder split across frames unmasks
    /// whole. Present only when reversible masking is active; mutually exclusive with `dlp` redaction.
    unmask: Option<UnmaskStreamState>,
    /// A non-data (trailers) frame held back so the redaction flush is emitted *before* it, then
    /// returned on the next poll. Keeps trailers last even when a buffered redaction tail remains.
    pending: Option<Frame<Bytes>>,
}

/// Streaming reversible-unmask state: the per-request mask map + the held-back boundary tail.
struct UnmaskStreamState {
    map: crate::dlp::MaskMap,
    carry: Vec<u8>,
}

/// Carry-buffer size for streaming DLP: the last bytes of each frame are kept and prepended to the
/// next, so a secret/PII token split across two SSE frames is still detected. Sized above the
/// longest signature (private-key header, provider keys).
const DLP_STREAM_CARRY: usize = 256;

/// Scans a streamed response frame-by-frame for DLP findings, carrying a tail across frame
/// boundaries so a split token is still caught. Uses the engine's **deterministic** scan only
/// (`scan_stream`): the ML NER family never runs on the stream. In `report` mode it counts findings;
/// in `redact` mode (when `[llm.dlp].stream_redact` is on) it rewrites the emitted bytes, holding back
/// the boundary tail so a span straddling a frame is redacted whole on the next frame / final flush.
struct DlpStreamScanner {
    engine: Arc<crate::dlp::DlpEngine>,
    metrics: Arc<Metrics>,
    /// True when the stream should be rewritten (redact mode + stream_redact), not merely counted.
    redact: bool,
    /// Report mode: trailing bytes of the previous frame, prepended to the next scan (split-token
    /// detection). Redact mode: the un-emitted tail held back so a boundary-straddling span waits.
    carry: Vec<u8>,
}

impl DlpStreamScanner {
    /// Report mode: scan one frame (prepended with the carry), counting only findings that touch the
    /// new data (so a span already counted from the carry isn't double-counted), then refresh the carry.
    fn record_only(&mut self, data: &[u8]) {
        let carry_len = self.carry.len();
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(data);
        let text = String::from_utf8_lossy(&buf);
        for f in self.engine.scan_stream(&text) {
            // Count a finding once, when its span reaches into the newly-arrived bytes.
            if f.end > carry_len {
                self.metrics.record_dlp_finding(f.category);
            }
        }
        // Keep the last DLP_STREAM_CARRY bytes for the next frame's boundary check.
        let keep = buf.len().min(DLP_STREAM_CARRY);
        self.carry = buf.split_off(buf.len() - keep);
    }

    /// Redact mode: append `data` to the held-back carry, redact every deterministic span that ends
    /// before the boundary tail, and return the bytes to emit now (the rest waits in `carry`). A span
    /// straddling the boundary pulls the emit point back to its start so it is never split.
    fn redact_frame(&mut self, data: &[u8]) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(data);
        let text = String::from_utf8_lossy(&buf).into_owned();
        let findings = self.engine.scan_stream(&text);
        // Hold back the last DLP_STREAM_CARRY bytes; never emit past a span that crosses the boundary.
        let mut emit_to = text.len().saturating_sub(DLP_STREAM_CARRY);
        for f in &findings {
            if f.start < emit_to && f.end > emit_to {
                emit_to = f.start;
            }
        }
        while emit_to > 0 && !text.is_char_boundary(emit_to) {
            emit_to -= 1;
        }
        let emit: Vec<crate::dlp::Finding> =
            findings.into_iter().filter(|f| f.end <= emit_to).collect();
        for f in &emit {
            self.metrics.record_dlp_finding(f.category);
        }
        let out = self.engine.redact(&text[..emit_to], &emit).into_bytes();
        self.carry = text.as_bytes()[emit_to..].to_vec();
        out
    }

    /// Redact mode: at end-of-stream, redact and return whatever remains in the held-back tail.
    fn flush(&mut self) -> Vec<u8> {
        if self.carry.is_empty() {
            return Vec::new();
        }
        let buf = std::mem::take(&mut self.carry);
        let text = String::from_utf8_lossy(&buf).into_owned();
        let findings = self.engine.scan_stream(&text);
        for f in &findings {
            self.metrics.record_dlp_finding(f.category);
        }
        self.engine.redact(&text, &findings).into_bytes()
    }
}

/// Cap on the rolling tail buffer kept for SSE token metering. The OpenAI terminal `usage` frame is
/// small and arrives just before `[DONE]`, so the last 16 KiB always contains it; bounding the
/// buffer keeps streaming memory flat regardless of stream length.
const LLM_SSE_TAIL_CAP: usize = 16 * 1024;

/// Accumulates the tail of an SSE stream so the terminal `usage` frame can be parsed when the body
/// finishes. Holds the model + price book; records to metrics and reconciles the L1 budget on drop.
struct LlmStreamMeter {
    model: String,
    llm: Arc<crate::llm::LlmRuntime>,
    tail: Vec<u8>,
    /// L1 budget engine + the held reservation, when budgets are configured. Reconciled to the
    /// streamed usage on drop (or released on no usage).
    engine: Option<Arc<crate::budget::BudgetEngine>>,
    reservation: Option<crate::budget::Reservation>,
    /// Request-receipt instant, the TTFT clock's zero. TTFT = first streamed frame − `started`.
    started: Instant,
    /// When the first / most-recent data frame was emitted to the client. TPOT is derived from the
    /// span between them and the terminal `usage` output-token count. `None` until the first frame.
    first_at: Option<Instant>,
    last_at: Option<Instant>,
    /// OTLP span emission for the streamed request (gateway L4), when `[llm.telemetry]` is on. On
    /// drop, the finalized usage + TTFT/TPOT are emitted as one OpenInference span. `None` when off.
    telemetry: Option<Arc<crate::telemetry::TelemetryRuntime>>,
    /// The trace context for the emitted span (carries an inbound `traceparent` when present).
    ctx: crate::telemetry::TraceContext,
    /// Captured (DLP-redacted) request body for the span's `input.value`, when content capture is on.
    /// The streamed *output* isn't buffered (SSE is forwarded frame-by-frame), so only input is set.
    input: Option<String>,
    /// Team/tag for the per-team token/cost metric on drop (absent → `_none`).
    team: Option<String>,
    /// Authenticated principal for the per-key token/cost metric on drop (absent → `_anon`).
    key: Option<String>,
}

/// Holds an LLM budget reservation for the buffered/non-streaming path. `commit` reconciles it to
/// the actual spend; if the guard is dropped without committing (any early return on an upstream
/// error / timeout), its `Drop` releases the reservation in full, so a failed request never
/// permanently consumes budget.
struct ReservationGuard {
    engine: Arc<crate::budget::BudgetEngine>,
    reservation: Option<crate::budget::Reservation>,
    /// For recording reconcile/release failures (counter drift) to Prometheus.
    metrics: Arc<Metrics>,
}

impl ReservationGuard {
    /// Reconcile the held reservation to `actual` spend (consuming the guard so `Drop` is a no-op).
    async fn commit(mut self, actual: crate::budget::Spend) {
        if let Some(reservation) = self.reservation.take() {
            let failed = self.engine.reconcile(&reservation, actual).await;
            self.metrics.record_budget_reconcile_failures(failed);
        }
    }
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        // Not committed (an error path bailed before reconcile): release the whole hold. `release`
        // is async, so spawn it onto the current runtime (we're always inside the request task).
        if let Some(reservation) = self.reservation.take() {
            let engine = Arc::clone(&self.engine);
            let metrics = Arc::clone(&self.metrics);
            tokio::spawn(async move {
                let failed = engine.release(&reservation).await;
                metrics.record_budget_reconcile_failures(failed);
            });
        }
    }
}

impl<B> CountingBody<B> {
    fn new(
        inner: B,
        metrics: Arc<Metrics>,
        ingress: usize,
        header_egress: usize,
        llm: Option<LlmStreamMeter>,
        dlp: Option<DlpStreamScanner>,
        unmask: Option<UnmaskStreamState>,
    ) -> Self {
        Self {
            inner,
            metrics,
            ingress,
            egress: header_egress,
            llm,
            dlp,
            unmask,
            pending: None,
        }
    }

    /// Append the bytes the client will actually receive to the bounded LLM tail buffer (keeping only
    /// the last [`LLM_SSE_TAIL_CAP`] bytes), so the terminal `usage` frame is available to parse on drop.
    fn push_meter_tail(&mut self, data: &[u8]) {
        if let Some(meter) = self.llm.as_mut() {
            // Stamp first/last emitted-frame time for TTFT/TPOT (this runs on the bytes the client
            // actually receives, so it measures server-side time-to-first-token with no client clock).
            if !data.is_empty() {
                let now = Instant::now();
                meter.first_at.get_or_insert(now);
                meter.last_at = Some(now);
            }
            meter.tail.extend_from_slice(data);
            if meter.tail.len() > LLM_SSE_TAIL_CAP {
                let drop_n = meter.tail.len() - LLM_SSE_TAIL_CAP;
                meter.tail.drain(..drop_n);
            }
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
        // A trailers frame held back during a redaction flush is emitted now, before anything else.
        if let Some(frame) = this.pending.take() {
            return Poll::Ready(Some(Ok(frame)));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // Only data frames are scanned/redacted; trailers and the like pass through — but in
                // redact mode any buffered tail must be flushed *before* the trailers go out.
                let data = match frame.into_data() {
                    Ok(data) => data,
                    Err(non_data) => {
                        if let Some(scanner) = this.dlp.as_mut() {
                            if scanner.redact {
                                let out = scanner.flush();
                                if !out.is_empty() {
                                    let out = Bytes::from(out);
                                    this.egress = this.egress.saturating_add(out.len());
                                    this.push_meter_tail(&out);
                                    this.pending = Some(non_data); // emit trailers on the next poll
                                    return Poll::Ready(Some(Ok(Frame::data(out))));
                                }
                            }
                        }
                        // Reversible unmask: flush the held-back tail before the trailers go out.
                        if let Some(u) = this.unmask.as_mut() {
                            let out = u.map.flush_unmask(&mut u.carry);
                            if !out.is_empty() {
                                let out = Bytes::from(out);
                                this.egress = this.egress.saturating_add(out.len());
                                this.push_meter_tail(&out);
                                this.pending = Some(non_data);
                                return Poll::Ready(Some(Ok(Frame::data(out))));
                            }
                        }
                        return Poll::Ready(Some(Ok(non_data)));
                    }
                };
                // Reversible unmask (gateway L3): restore placeholders to the caller's own values,
                // holding a boundary tail so a placeholder split across frames unmasks whole.
                if let Some(u) = this.unmask.as_mut() {
                    let out = Bytes::from(u.map.unmask_stream(&mut u.carry, &data));
                    this.egress = this.egress.saturating_add(out.len());
                    this.push_meter_tail(&out);
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                if this.dlp.as_ref().is_some_and(|s| s.redact) {
                    // Redact mode: rewrite the emitted bytes (deterministic spans only). The emitted
                    // length may differ from the input frame; account for the bytes the client gets.
                    let out = Bytes::from(this.dlp.as_mut().unwrap().redact_frame(&data));
                    this.egress = this.egress.saturating_add(out.len());
                    this.push_meter_tail(&out);
                    Poll::Ready(Some(Ok(Frame::data(out))))
                } else {
                    this.egress = this.egress.saturating_add(data.len());
                    this.push_meter_tail(&data);
                    // Report mode (or no redaction): count findings, pass the frame through unchanged.
                    if let Some(scanner) = this.dlp.as_mut() {
                        scanner.record_only(&data);
                    }
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
            }
            Poll::Ready(None) => {
                // Upstream ended. In redact mode, flush the held-back tail as one final data frame
                // (the next poll sees inner-end again and returns None).
                if let Some(scanner) = this.dlp.as_mut() {
                    if scanner.redact {
                        let out = scanner.flush();
                        if !out.is_empty() {
                            let out = Bytes::from(out);
                            this.egress = this.egress.saturating_add(out.len());
                            this.push_meter_tail(&out);
                            return Poll::Ready(Some(Ok(Frame::data(out))));
                        }
                    }
                }
                // Reversible unmask: flush the held-back tail as one final data frame.
                if let Some(u) = this.unmask.as_mut() {
                    let out = u.map.flush_unmask(&mut u.carry);
                    if !out.is_empty() {
                        let out = Bytes::from(out);
                        this.egress = this.egress.saturating_add(out.len());
                        this.push_meter_tail(&out);
                        return Poll::Ready(Some(Ok(Frame::data(out))));
                    }
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        // Not done while a held-back trailers frame, or a buffered redaction tail, still has to flow.
        if self.pending.is_some() {
            return false;
        }
        if let Some(scanner) = self.dlp.as_ref() {
            if scanner.redact && !scanner.carry.is_empty() {
                return false;
            }
        }
        if let Some(u) = self.unmask.as_ref() {
            if !u.carry.is_empty() {
                return false;
            }
        }
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for CountingBody<B> {
    fn drop(&mut self) {
        self.metrics.add_usage_bytes(self.ingress, self.egress);
        // LLM metering for the streamed body: parse the terminal `usage` frame from the tail. The
        // client gets usage only if it sent `stream_options.include_usage`; otherwise `no_usage`.
        if let Some(meter) = self.llm.as_mut() {
            let actual = match crate::llm::parse_sse_usage(&meter.tail) {
                Some(usage) => {
                    let cost = meter.llm.cost_micros(&meter.model, &usage);
                    let sample = crate::metrics::LlmSample {
                        tokens_in: usage.prompt_tokens,
                        tokens_out: usage.completion_tokens,
                        cached_tokens: usage.cached_tokens,
                        reasoning_tokens: usage.reasoning_tokens,
                        cost_micros: cost,
                    };
                    self.metrics.record_llm_usage(&meter.model, sample);
                    self.metrics
                        .record_llm_team_usage(meter.team.as_deref().unwrap_or("_none"), &sample);
                    self.metrics
                        .record_llm_key_usage(meter.key.as_deref().unwrap_or("_anon"), &sample);
                    // Server-side TTFT/TPOT from the emitted-frame timestamps. TPOT (inter-token
                    // latency) is only defined for >1 output token; a single-token response records
                    // TTFT alone; an empty stream records neither.
                    let (ttft, tpot) = match meter.first_at {
                        Some(first) => {
                            let ttft = first.saturating_duration_since(meter.started);
                            let tpot = match meter.last_at {
                                Some(last) if usage.completion_tokens > 1 => {
                                    let denom =
                                        (usage.completion_tokens - 1).min(u32::MAX as u64) as u32;
                                    Some(last.saturating_duration_since(first) / denom)
                                }
                                _ => None,
                            };
                            (Some(ttft), tpot)
                        }
                        None => (None, None),
                    };
                    if let Some(ttft) = ttft {
                        self.metrics.record_llm_latency(ttft, tpot);
                    }
                    // Emit an OpenInference span for the streamed request (gateway L4, fire-and-forget).
                    if let Some(telemetry) = meter.telemetry.as_ref() {
                        let (start_nanos, end_nanos) = wall_clock_span(meter.started);
                        telemetry.emit(crate::telemetry::SpanRecord {
                            ctx: meter.ctx,
                            name: "llm.chat".into(),
                            model: meter.model.clone(),
                            provider: None,
                            prompt_tokens: usage.prompt_tokens,
                            completion_tokens: usage.completion_tokens,
                            cached_tokens: usage.cached_tokens,
                            reasoning_tokens: usage.reasoning_tokens,
                            cost_micros: cost,
                            start_unix_nano: start_nanos,
                            end_unix_nano: end_nanos,
                            ttft,
                            tpot,
                            status_ok: true, // a streamed body means the upstream 2xx already began
                            input: meter.input.take(),
                            output: None, // streamed output isn't buffered (forwarded frame-by-frame)
                            session_id: None,
                        });
                    }
                    crate::budget::Spend {
                        tokens: usage.total_tokens(),
                        cost_micros: cost.unwrap_or(0),
                    }
                }
                None => {
                    self.metrics.record_llm_no_usage();
                    crate::budget::Spend::default()
                }
            };
            // Reconcile the L1 budget reservation to the streamed actual spend. Async, so spawn it
            // (we're inside the request task's runtime when the body is dropped). Record any settle
            // failure as counter drift.
            if let (Some(engine), Some(reservation)) =
                (meter.engine.take(), meter.reservation.take())
            {
                let metrics = Arc::clone(&self.metrics);
                tokio::spawn(async move {
                    let failed = engine.reconcile(&reservation, actual).await;
                    metrics.record_budget_reconcile_failures(failed);
                });
            }
        }
    }
}

/// Prepare captured LLM content (`input.value` / `output.value`) for a telemetry span: truncate to
/// the cap, and when a DLP engine is configured, scan+redact so PII/secrets never leave the box —
/// **regardless of the DLP `mode`**, so content capture is safe even under `report`/`block` (which
/// don't rewrite the body). Without a DLP engine the content is captured as-is (an explicit
/// `capture_content` opt-in). Returns `None` only when capture is off (handled by the caller).
fn capture_for_span(dlp: Option<&Arc<crate::dlp::DlpEngine>>, bytes: &[u8], max: usize) -> String {
    let text = crate::telemetry::prepare_content(bytes, max);
    match dlp {
        Some(dlp) => {
            let findings = dlp.scan(&text);
            if findings.is_empty() {
                text
            } else {
                dlp.redact(&text, &findings)
            }
        }
        None => text,
    }
}

/// Derive wall-clock (unix-nanos) span bounds from a monotonic request-start `Instant`. An `Instant`
/// can't be converted to a unix time directly, so we anchor the end at `SystemTime::now()` and
/// subtract the measured elapsed duration for the start. Used to timestamp emitted OTLP spans.
fn wall_clock_span(started: Instant) -> (u64, u64) {
    let end = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let start = end.saturating_sub(started.elapsed().as_nanos() as u64);
    (start, end)
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
                    // HttpOnly is added unless globally disabled or this cookie's name is
                    // exempt — the latter keeps a double-submit CSRF cookie JS-readable.
                    let add_httponly = cfg.headers.httponly_cookies
                        && !cookie_name_exempt(s, &cfg.headers.httponly_cookie_exempt);
                    let hardened = harden_cookie(s, add_httponly);
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

/// The cookie's NAME — the token before the first `=` of the `name=value` pair. Cookies are
/// case-sensitive, so this is returned as-is (trimmed) for an exact exemption match.
fn cookie_name(cookie: &str) -> &str {
    cookie
        .split(';')
        .next()
        .unwrap_or("")
        .split('=')
        .next()
        .unwrap_or("")
        .trim()
}

/// True when this cookie's name is on the `httponly_cookie_exempt` allowlist.
fn cookie_name_exempt(cookie: &str, exempt: &[String]) -> bool {
    let name = cookie_name(cookie);
    exempt.iter().any(|e| e == name)
}

/// Harden one `Set-Cookie` value: ensure `Secure` and a `SameSite` default, and add
/// `HttpOnly` when `add_httponly` is set (the caller clears it for exempt cookies).
fn harden_cookie(cookie: &str, add_httponly: bool) -> String {
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
    if add_httponly && !attrs.contains("httponly") {
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
    // Managed mode: count every finished request (proxied or rejected) toward the usage delta, and
    // — when the edge denied it — the drainable `blocked` figure. Cheap (relaxed atomic adds) and
    // inert unless a control plane drains it for reporting.
    metrics.add_usage_request(outcome);
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
    fn capture_for_span_redacts_content_when_dlp_is_configured() {
        // With a DLP engine, captured content is redacted before it can be emitted — even in
        // `report` mode, which does not rewrite the forwarded body. This is the safety guarantee for
        // gateway content capture (top-20 #14): PII/secrets never leave the box via a span.
        let dlp = crate::dlp::DlpEngine::build(&crate::config::DlpCfg {
            mode: "report".into(),
            detect_email: true,
            ..Default::default()
        })
        .unwrap()
        .map(Arc::new);
        assert!(dlp.is_some(), "report mode should build a DLP engine");
        let body = b"please email alice@example.com about the invoice";

        let redacted = capture_for_span(dlp.as_ref(), body, 4096);
        assert!(
            !redacted.contains("alice@example.com"),
            "email must be redacted before capture: {redacted}"
        );

        // Without a DLP engine, capture is verbatim (an explicit `capture_content` opt-in).
        let raw = capture_for_span(None, body, 4096);
        assert!(raw.contains("alice@example.com"));

        // The size cap still applies to the captured content.
        assert!(capture_for_span(None, body, 8).len() < body.len());
    }

    /// Drive a sequence of byte frames through a redact-mode `DlpStreamScanner` and return the
    /// concatenated emitted output (frames + final flush) as a string.
    fn run_stream_redact(frames: &[&[u8]]) -> String {
        let engine = crate::dlp::DlpEngine::build(&crate::config::DlpCfg {
            mode: "redact".into(),
            stream_redact: true,
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        let mut scanner = DlpStreamScanner {
            engine: Arc::new(engine),
            metrics: Arc::new(Metrics::new()),
            redact: true,
            carry: Vec::new(),
        };
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&scanner.redact_frame(f));
        }
        out.extend_from_slice(&scanner.flush());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn stream_redaction_redacts_pii_split_across_frames() {
        // An email split across two SSE frames is still redacted whole (carry holds the boundary).
        let out = run_stream_redact(&[b"hello jane.d", b"oe@example.com bye"]);
        assert_eq!(out, "hello [REDACTED:email] bye");
    }

    #[test]
    fn stream_redaction_passes_clean_text_unchanged() {
        let out = run_stream_redact(&[b"the quick brown ", b"fox jumps over the lazy dog"]);
        assert_eq!(out, "the quick brown fox jumps over the lazy dog");
    }

    #[test]
    fn stream_redaction_handles_pii_at_end_via_flush() {
        // PII entirely within the final held-back tail is redacted by the end-of-stream flush.
        let out = run_stream_redact(&[b"ssn 123-45-6789"]);
        assert_eq!(out, "ssn [REDACTED:ssn]");
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
        let out = harden_cookie("sid=abc", true);
        assert!(out.contains("; Secure"), "{out}");
        assert!(out.contains("; HttpOnly"), "{out}");
        assert!(out.contains("; SameSite=Lax"), "{out}");
    }

    #[test]
    fn harden_cookie_preserves_existing_attributes() {
        let out = harden_cookie("sid=abc; HttpOnly; SameSite=Strict", true);
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
        let out = harden_cookie("session=securetoken", true);
        assert!(out.contains("; Secure"), "{out}");
    }

    #[test]
    fn harden_cookie_skips_httponly_when_disabled() {
        // add_httponly=false → Secure + SameSite still added, but NOT HttpOnly. This is the
        // path for a JS-readable double-submit CSRF cookie (e.g. doneyet_csrf).
        let out = harden_cookie("doneyet_csrf=tok", false);
        assert!(out.contains("; Secure"), "{out}");
        assert!(out.contains("; SameSite=Lax"), "{out}");
        assert!(!out.to_ascii_lowercase().contains("httponly"), "{out}");
    }

    #[test]
    fn cookie_name_exempt_matches_by_name_only() {
        let exempt = vec!["doneyet_csrf".to_string()];
        assert!(cookie_name_exempt(
            "doneyet_csrf=abc; Path=/; Secure",
            &exempt
        ));
        // a different cookie is not exempt; the value never triggers a match
        assert!(!cookie_name_exempt(
            "doneyet_auth=doneyet_csrf; Path=/",
            &exempt
        ));
        assert!(!cookie_name_exempt("sid=x", &exempt));
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
