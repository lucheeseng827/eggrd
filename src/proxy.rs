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
use http_body_util::{BodyExt, Limited};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::auth::{AuthEngine, Challenge, Decision};
use crate::config::{Config, HeadersCfg};
use crate::limiter::{Admit, DistributedLimiter};
use crate::metrics::Metrics;
use crate::upstream::UpstreamResult;
use crate::waf::{WafEngine, WafMode};

pub type KeyedLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;
/// Rate limiter keyed by the authenticated principal (per-key limiting).
pub type StrLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;
/// The upstream client. Its body type is axum's boxed [`Body`], so one client carries both a
/// buffered request (`Body::from(bytes)`) and a streamed one ([`StreamedRequestBody`]). Its
/// connector speaks TLS to `https://` upstreams ([`crate::upstream`]).
pub type UpstreamClient = Client<crate::upstream::UpstreamConnector, Body>;

/// Shared, cheaply-cloned handle the router hands to every request. Only the hot-swappable
/// [`Runtime`] changes on reload; the client and metrics are stable.
#[derive(Clone)]
pub struct AppState {
    pub client: UpstreamClient,
    /// The connector `client` was built on, for the health checks that need it with other TLS
    /// settings (see [`crate::upstream::UpstreamConnector::with_tls_of`]).
    pub connector: crate::upstream::UpstreamConnector,
    /// The TLS settings the client's connector uses, held here too so the client certificates in
    /// them can be watched for changes on disk.
    pub upstream_tls: Arc<crate::upstream::UpstreamTls>,
    pub metrics: Arc<Metrics>,
    pub runtime: Arc<ArcSwap<Runtime>>,
    /// Managed-mode control-plane client (`Some` only when `[control_plane]` is enabled). Used to
    /// forward CSP reports; policy pull + usage reporting run as background tasks in `main`.
    pub cp: Option<Arc<crate::cp::CpClient>>,
    /// Shared quota verdict, updated by the managed-mode quota poller and read by the
    /// hard-stop gate below. Lives here (not on the hot-swappable [`Runtime`]) so a policy reload
    /// never resets enforcement. Inert unless `control_plane.enforce_quota` is set.
    pub quota: Arc<crate::cp::QuotaState>,
    /// Set when shutdown begins. `/__edgeguard/ready` answers `503` from then on, so a load
    /// balancer stops sending new traffic while the listeners drain.
    pub draining: Arc<std::sync::atomic::AtomicBool>,
    /// Set while `control_plane.boot_without_policy = "refuse"` and no control-plane policy has
    /// been applied: proxied requests and readiness get `503`. Cleared by
    /// [`crate::policy::Policy`] when one is.
    pub policy_pending: Arc<std::sync::atomic::AtomicBool>,
    /// `[trusted_client_cert_header]`: client certificates a load balancer forwards. Read at
    /// startup and fixed for the process, like `upstream_tls`.
    pub client_cert_header: Option<Arc<crate::client_cert_header::TrustedHeader>>,
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
    /// The default upstream (the single `server.upstream`/`app_port`), used when no
    /// `[[upstreams]]` prefix matches.
    pub default_upstream: crate::pool::Pool,
    /// Per-path-prefix upstreams as `(prefix, pool)`; the longest matching prefix wins. Empty
    /// unless `[[upstreams]]` is configured.
    pub upstream_routes: Vec<(String, crate::pool::Pool)>,
    /// The `route` label of the per-route metrics, as `(prefix, label)`: every `[[upstreams]]` and
    /// `[[ratelimit.routes]]` prefix, labelled by its `name` or the prefix itself. The longest
    /// matching prefix wins; nothing matching is [`crate::metrics::DEFAULT_ROUTE`]. Labels come
    /// only from config, so a request cannot add one.
    pub route_labels: Vec<(String, String)>,
    pub auth: AuthEngine,
    /// WAF-lite input screener. Inert (`evaluate` returns `None`) when `waf.mode = "off"`.
    pub waf: Arc<WafEngine>,
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
    /// Stream responses of any type when nothing needs the whole body. See
    /// [`crate::config::ValidationCfg::stream_responses`] and [`streams_any_response`].
    pub stream_responses: bool,
    /// Stream request bodies when nothing needs the whole body. See
    /// [`crate::config::ValidationCfg::stream_requests`] and [`streams_request`].
    pub stream_requests: bool,
    /// Routes whose streamed request body is inspected on a bounded window. See
    /// [`crate::config::ValidationCfg::stream_inspect`] and [`crate::stream_inspect`].
    pub stream_inspect: Vec<crate::stream_inspect::InspectWindow>,
    /// Tunnel WebSocket / `Upgrade` connections to the upstream. See
    /// [`crate::config::ValidationCfg::websocket_passthrough`].
    pub websocket_passthrough: bool,
    /// What happens to `X-Forwarded-Client-Cert` on the way upstream (`[tls.client_auth]`).
    pub client_cert_header: crate::client_auth::ForwardPolicy,
    /// Whom `X-Forwarded-For` and `X-Forwarded-Proto` are believed from, and which entry is the
    /// client (`server.trust_forwarded_for`, `forwarded_hops`, `trusted_forwarders`).
    pub forwarders: Forwarders,
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
    /// The per-route metrics label for `path` (see [`Runtime::route_labels`]).
    pub fn route_label(&self, path: &str) -> &str {
        self.route_labels
            .iter()
            .filter(|(prefix, _)| path_prefix_matches(path, prefix))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, label)| label.as_str())
            .unwrap_or(crate::metrics::DEFAULT_ROUTE)
    }

    /// The upstreams to forward `path` to: the longest matching `[[upstreams]]` prefix, or the
    /// default [`Runtime::default_upstream`] when none match.
    pub fn pick_upstream(&self, path: &str) -> &crate::pool::Pool {
        self.upstream_routes
            .iter()
            .filter(|(prefix, _)| path_prefix_matches(path, prefix))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, pool)| pool)
            .unwrap_or(&self.default_upstream)
    }

    /// Every route's upstreams, the default first.
    pub fn pools(&self) -> impl Iterator<Item = &crate::pool::Pool> + Clone {
        std::iter::once(&self.default_upstream).chain(self.upstream_routes.iter().map(|(_, p)| p))
    }

    /// Keep the health of the pool targets `old` already tracked: same route prefix, same URL.
    /// Called on every rebuild, so a reload does not put a dead target back in rotation.
    pub fn carry_health_from(&mut self, old: &Runtime) {
        for (prefix, pool) in &mut self.upstream_routes {
            if let Some((_, previous)) = old.upstream_routes.iter().find(|(p, _)| p == prefix) {
                pool.carry_health_from(previous);
            }
        }
    }
}

/// Whether `prefix` matches `path` on a path-segment boundary. `prefix` is a validated upstream
/// route prefix (always starts with `/`); `path` is the request path-and-query. A plain
/// `str::starts_with` would route a sibling like `/apiary` to the `/api` upstream, so the match
/// only succeeds when the prefix is followed by a real boundary: end of path, a `/`, or the query
/// separator `?`. A trailing slash on the prefix is itself a boundary.
pub(crate) fn path_prefix_matches(path: &str, prefix: &str) -> bool {
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
    // Read before the runtime, which is stored before this is cleared: a request that sees no
    // policy pending is sure to load the policy's runtime, never the local-only one it replaced.
    // Read after, a request could load the local runtime, then see the first policy arrive, and
    // be served on the very config `boot_without_policy = "refuse"` says not to serve on.
    let policy_pending = state
        .policy_pending
        .load(std::sync::atomic::Ordering::Acquire);
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
    // Request-tracing inputs, captured before `handle_inner` consumes the request. Only gathered
    // when a shipper actually exists: with tracing off this is one Option check, not a trace-id mint
    // and a pile of header reads on every request.
    let mut req = req;
    // The client, resolved once: the span, rate limits, `[access]`, routing, the log and the
    // upstream's forwarding headers all use this one address.
    // `trusted_forwarders` is matched against the TCP peer: the hop that wrote the headers, not a
    // client a PROXY protocol header named. Every listener of ours attaches `TcpPeer` where a PROXY
    // header becomes `ConnectInfo` (`serve::serve_connection`), so the fallback only serves a
    // router run some other way (tests, an embedder's `axum::serve`), whose `ConnectInfo` is the
    // TCP peer.
    let hop = req
        .extensions()
        .get::<crate::serve::TcpPeer>()
        .map_or(peer, |p| p.0)
        .ip();
    let (ip, forwarded_for) = rt.forwarders.resolve(req.headers(), peer, hop);
    if let Some(result) = forwarded_for {
        state.metrics.record_forwarded_for(result);
    }
    if rt.forwarders.believes(hop) {
        req.extensions_mut().insert(ForwardingTrusted);
    }
    // The request's host, decided once ([`request_host`]): the span names it, `handle_inner`
    // refuses the request when it is ambiguous or missing, and the forward path sends it as
    // `X-Forwarded-Host`.
    let host_check = request_host(req.headers(), req.uri(), req.version());
    let span_pre = state
        .metrics
        .span_shipper()
        .is_some()
        .then(|| ServerSpanPre::capture(&req, &rt, ip, host_check.clone().ok().flatten()));
    // Hand the context to the forward path so it can rewrite `traceparent` for the upstream. Only
    // when recording: an unsampled request forwards the client's headers untouched.
    if let Some(pre) = &span_pre {
        if pre.sampled {
            req.extensions_mut().insert(pre.ctx);
        }
    }

    // Per-route and per-consumer metrics, and the access line. The route is decided from config
    // before the pipeline runs; the rest is learned on the way through, into `ctx`.
    let started = Instant::now();
    let method = req.method().clone();
    let route_label = rt.route_label(req.uri().path()).to_string();
    let route = state.metrics.route_stats(&route_label);
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .map(|v| crate::accesslog::user_agent(v.as_bytes()));
    let tls_version = req
        .extensions()
        .get::<crate::serve::TlsVersion>()
        .map(|v| v.0);
    // A certificate the load balancer forwards, from a trusted peer, becomes the request's client
    // certificate before anything reads it; the balancer's own handshake certificate, if any, was
    // the hop's. The header is gone from the request either way. Trust is the TCP peer's: the hop
    // that wrote the header, not a client a PROXY protocol header named.
    if let Some(header) = &state.client_cert_header {
        let hop = req
            .extensions()
            .get::<crate::serve::TcpPeer>()
            .map_or(peer, |p| p.0);
        if let Some(result) = header.apply(hop.ip(), &mut req) {
            state.metrics.record_client_cert_header(result);
        }
    }
    let client_cert = req
        .extensions()
        .get::<Arc<crate::client_auth::ClientCert>>()
        .cloned();
    let ctx = Arc::new(RequestCtx::default());

    let mut resp = handle_inner(&state, &rt, policy_pending, ip, host_check, req, &ctx).await;
    if let Some(origin) = &origin {
        if let Some(cors) = &rt.cors {
            cors.decorate_origin(origin, &mut resp);
        }
    }

    // Every response counts, the edge's own `401`/`429`/`403` included: a request refused before
    // authentication is the unauthenticated consumer's.
    let status = resp.status().as_u16();
    let elapsed = started.elapsed();
    route.record(method.as_str(), status, elapsed);
    if let Some(busy) = ctx.upstream_busy.get() {
        state
            .metrics
            .observe_edge_overhead(elapsed.saturating_sub(*busy));
    }
    if let Some(stats) = ctx
        .consumer
        .get()
        .cloned()
        .or_else(|| state.metrics.consumer_stats(None))
    {
        stats.record(status);
    }

    // The access line. A streamed response's body writes it when it ends, so its bytes and
    // duration are the real ones; every other response's is written now.
    if let Some(info) = resp.extensions().get::<FinishInfo>() {
        let names = rt.cfg.log.principal;
        let (bytes_in, bytes_out) = match ctx.bytes.get() {
            Some((i, o)) => (Some(*i), Some(*o)),
            None => (None, None),
        };
        let line = AccessLine {
            started,
            record: crate::logship::AccessRecord {
                schema: crate::logship::ACCESS_RECORD_SCHEMA,
                ts: String::new(),
                request_id: info.request_id.clone(),
                method: method.to_string(),
                target: info.target.clone(),
                client_ip: info.client_ip.to_string(),
                status,
                outcome: info.outcome.clone(),
                latency_ms: info.elapsed.as_millis() as u64,
                duration_ms: 0,
                edge_id: String::new(),
                route: route_label,
                principal: ctx.principal.get().and_then(|p| names.apply(p)),
                user_agent,
                upstream: ctx.upstream.get().cloned(),
                upstream_ms: ctx.upstream_ms.get().copied(),
                bytes_in,
                bytes_out,
                tls_version: tls_version.map(str::to_string),
                client_cert: client_cert.and_then(|c| {
                    let name = c
                        .identities()
                        .next()
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("sha256:{}", c.sha256));
                    names.apply(&name)
                }),
            },
        };
        if ctx.streamed.load(std::sync::atomic::Ordering::Acquire) {
            *ctx.pending.lock().expect("request ctx mutex poisoned") = Some(line);
        } else {
            write_access_line(&state.metrics, line);
        }
    }

    // Emit the span AFTER CORS decoration, so what is recorded is the response the client receives.
    if let Some(pre) = span_pre {
        // The sampling verdict was fixed from the trace id before any work, so a trace is wholly
        // recorded or wholly not — a half-recorded trace reads in a backend as a missing service.
        if pre.sampled {
            if let (Some(shipper), Some(info)) = (
                state.metrics.span_shipper(),
                resp.extensions().get::<FinishInfo>().cloned(),
            ) {
                shipper.record(pre.finish(&info));
            }
        }
    }
    resp
}

/// Everything a server span needs from the request, taken before the body is consumed.
///
/// Sampling is decided here, once, from the trace id — so the decision is fixed before any work and
/// a trace is wholly recorded or wholly not.
struct ServerSpanPre {
    ctx: crate::telemetry::TraceContext,
    method: String,
    method_original: Option<String>,
    url_path: String,
    url_query: Option<String>,
    url_scheme: String,
    client_address: Option<String>,
    server_address: Option<String>,
    user_agent: Option<String>,
    protocol_version: Option<String>,
    start_unix_nano: u128,
    sampled: bool,
}

impl ServerSpanPre {
    fn capture(
        req: &Request<Body>,
        rt: &Runtime,
        client: IpAddr,
        host: Option<String>,
    ) -> ServerSpanPre {
        let inbound = req
            .headers()
            .get("traceparent")
            .and_then(|v| v.to_str().ok());
        // One context for the whole request: an inbound traceparent makes this span a child of the
        // caller's, otherwise a fresh root trace.
        let ctx = crate::telemetry::TraceContext::from_traceparent(inbound);
        let sampled = crate::telemetry::trace_sampled(rt.cfg.tracing.sample_rate, &ctx.trace_id);

        let (method, method_original) =
            crate::telemetry::ServerSpan::normalize_method(req.method().as_str());

        let (path, query) = match req.uri().path_and_query() {
            Some(pq) => (pq.path().to_string(), pq.query().map(str::to_owned)),
            None => (req.uri().path().to_string(), None),
        };
        // The query is sanitised with the SAME policy as the access log. A span goes to the same
        // class of destination, so leaving credentials in it would reintroduce in traces exactly the
        // leak the access log exists to prevent.
        let url_query = query.map(|q| {
            crate::accesslog::sanitize_target(
                &format!("/?{q}"),
                rt.cfg.log.query,
                &rt.cfg.log.redact_params,
            )
            .split_once('?')
            .map(|(_, v)| v.to_string())
            .unwrap_or_default()
        });

        ServerSpanPre {
            ctx,
            method,
            method_original,
            url_path: path,
            url_query,
            url_scheme: if rt.cfg.tls.enabled { "https" } else { "http" }.to_string(),
            // The same client the request is limited, logged and routed as.
            client_address: Some(client.to_string()),
            // The host the WAF checks: `:authority` over HTTP/2, which sends no `Host`.
            server_address: host,
            user_agent: req
                .headers()
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            protocol_version: match req.version() {
                hyper::Version::HTTP_10 => Some("1.0".into()),
                hyper::Version::HTTP_11 => Some("1.1".into()),
                hyper::Version::HTTP_2 => Some("2".into()),
                hyper::Version::HTTP_3 => Some("3".into()),
                _ => None,
            },
            start_unix_nano: unix_nanos(),
            sampled,
        }
    }

    fn finish(self, info: &FinishInfo) -> crate::telemetry::ServerSpan {
        crate::telemetry::ServerSpan {
            ctx: self.ctx,
            method: self.method,
            method_original: self.method_original,
            url_path: self.url_path,
            url_query: self.url_query,
            url_scheme: self.url_scheme,
            status_code: info.status,
            client_address: self.client_address,
            server_address: self.server_address,
            user_agent: self.user_agent,
            protocol_version: self.protocol_version,
            outcome: info.outcome.clone(),
            request_id: info.request_id.clone(),
            start_unix_nano: self.start_unix_nano,
            end_unix_nano: self.start_unix_nano + info.elapsed.as_nanos(),
        }
    }
}

/// Wall-clock nanoseconds since the Unix epoch, for span timestamps.
fn unix_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

async fn handle_inner(
    state: &AppState,
    rt: &Runtime,
    policy_pending: bool,
    // The client, resolved once in `handle` ([`client_ip`]).
    ip: IpAddr,
    // The request's host, decided once in `handle` ([`request_host`]).
    host_check: Result<Option<String>, &'static str>,
    mut req: Request<Body>,
    ctx: &Arc<RequestCtx>,
) -> Response<Body> {
    let started = Instant::now();
    let m = &state.metrics;

    let method = req.method().clone();
    // Two forms of the request target, and the distinction is load-bearing.
    //
    // `raw_path` is what the request actually asked for: it routes, it picks the upstream, it is
    // what the WAF inspects, and it is forwarded verbatim. Redacting any of that would break
    // routing and blind the security pipeline.
    //
    // `path` is the form that reaches a log line, with credential-shaped query values removed. The
    // query string is where password-reset links, OAuth `?code=`, presigned URLs and `?api_key=`
    // live, and an access log is the most-copied artifact this proxy produces. See `accesslog`.
    let raw_path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let path =
        crate::accesslog::sanitize_target(&raw_path, rt.cfg.log.query, &rt.cfg.log.redact_params);

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

    // The host the request is for, one answer for every protocol: an HTTP/2 request's
    // `:authority` or an HTTP/1.1 absolute-form target, else the `Host` header. The WAF, the
    // upstream's `X-Forwarded-Host` and the span all use it. Two that disagree, or two `Host`
    // headers, are refused: the edge would check one host and the app might use the other.
    // No host at all: HTTP/1.1 and HTTP/2 require one (RFC 9112 §3.2, RFC 9113 §8.3.1), so the
    // request is refused like an ambiguous one, and the WAF never sees a hostless request. An
    // HTTP/1.0 request may lawfully omit it (old health checkers do): it goes on hostless, and a
    // Host allow-list rule sees an empty `host:` line and refuses it.
    let host = match host_check {
        Ok(host) => host,
        Err(why) => {
            debug!(client_ip = %ip, why, "request refused: bad host");
            return finish(
                m,
                &rid,
                &method,
                &path,
                ip,
                started,
                "bad_request",
                text(StatusCode::BAD_REQUEST, "Bad Request"),
            );
        }
    };
    // For the forward paths' `X-Forwarded-Host`.
    req.extensions_mut().insert(EffectiveHost(host.clone()));

    // Managed mode with `boot_without_policy = "refuse"`, before any policy has arrived: the
    // runtime is the local config file alone, which this edge was told not to serve on. Before
    // every other step, since every other step is policy. Read in `handle`, before `rt`.
    if policy_pending {
        let mut resp = text(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable");
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return finish(m, &rid, &method, &path, ip, started, "no_policy", resp);
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
            match d.check_ip_route(ip, &raw_path).await {
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
            let (limiter, scope) = match longest_route(&rt.route_limiters, &raw_path) {
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

    // 2) Authentication. On success we learn the principal for per-key limiting, and, for a
    //    verified JWT, its claims, which may choose a vault entry and key a budget. The client
    //    certificate, when the TLS listener verified one, is what `auth.mode = "mtls"` reads.
    let client_cert = req
        .extensions()
        .get::<Arc<crate::client_auth::ClientCert>>()
        .cloned();
    let (principal, claims) = match rt
        .auth
        .authorize_with_cert(&rt.cfg.auth, req.headers(), client_cert.as_deref())
        .await
    {
        Decision::Allow(principal) => (principal, None),
        Decision::AllowJwt(principal, claims) => (principal, Some(claims)),
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
    // From here on the request is this principal's (or the anonymous consumer's, with no auth).
    if let Some(stats) = m.consumer_stats(principal.as_deref()) {
        let _ = ctx.consumer.set(stats);
    }
    if let Some(p) = &principal {
        let _ = ctx.principal.set(p.clone());
    }

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
        // The WAF on the handshake's path and headers (a tunnel has no body to read): an upgrade
        // must not be a way around a path or Host rule.
        if let WafVerdict::Block = screen(
            &rt.waf,
            m,
            &raw_path,
            req.headers(),
            host.as_deref(),
            b"",
            ip,
            &path,
        ) {
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
            // A virtual key, or else the verified claims of the request's JWT.
            match presented
                .and_then(|k| vault.lookup(k))
                .or_else(|| claims.as_deref().and_then(|c| vault.lookup_claims(c)))
            {
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
        return proxy_upgrade(
            state, rt, req, &rid, &method, &raw_path, &path, ip, started, ctx,
        )
        .await;
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
    // 5a) Stream the body instead, when nothing below reads it (see `streams_request`). It is then
    //     forwarded as it arrives, still capped at `max_body`; `body_bytes` stays empty, so the
    //     inspection steps below see no body — which is exactly the set of steps that need none.
    let stream_request = streams_request(
        rt.stream_requests,
        rt.waf.needs_body(),
        rt.dlp.as_ref().is_some_and(|d| d.scan_request()),
        rt.llm.enabled || rt.keyvault.is_some() || rt.budgets.is_some(),
    );
    let too_large = || {
        finish(
            m,
            &rid,
            &method,
            &path,
            ip,
            started,
            "payload_too_large",
            text(StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large"),
        )
    };
    // Request (ingress) size for managed-mode usage. Shared, because a streamed body is only
    // counted as it flows — after this function has moved on.
    let ingress = Arc::new(std::sync::atomic::AtomicUsize::new(header_bytes(
        &parts.headers,
    )));
    // 5b) A route under `[[validation.stream_inspect]]` streams even though the WAF or inbound DLP
    //     reads the body: they inspect the first `window` bytes below, as if that were the body,
    //     and a `TailInspector` scans the rest as it is forwarded (see `crate::stream_inspect`).
    let window = if stream_request {
        None
    } else {
        crate::stream_inspect::InspectWindow::for_path(&rt.stream_inspect, &raw_path).filter(|_| {
            crate::stream_inspect::inspects_window(
                rt.stream_requests,
                true,
                rt.waf.needs_body(),
                rt.dlp.as_ref().is_some_and(|d| d.scan_request()),
                rt.dlp
                    .as_ref()
                    .is_some_and(|d| d.mode() == crate::dlp::DlpMode::Redact),
                rt.llm.enabled || rt.keyvault.is_some() || rt.budgets.is_some(),
            )
        })
    };
    let mut streamed_body: Option<StreamedRequestBody> = None;
    // The window's inspection happens in the ordinary steps below; the tail inspector is built
    // after them, so it knows whether the WAF already reported this request.
    let mut window_rest: Option<(Body, usize)> = None;
    let mut body_bytes = if let Some(w) = window {
        let declared = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        if declared.is_some_and(|n| n > rt.max_body as u64) {
            return too_large();
        }
        let mut body = body;
        let mut head = bytes::BytesMut::new();
        let mut ended = false;
        while head.len() < w.window {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(d) = frame.data_ref() {
                        head.extend_from_slice(d);
                    }
                }
                Some(Err(_)) => return too_large(),
                None => {
                    ended = true;
                    break;
                }
            }
            if head.len() > rt.max_body {
                return too_large();
            }
        }
        let head = head.freeze();
        ingress.fetch_add(head.len(), std::sync::atomic::Ordering::Relaxed);
        if !ended && body.is_end_stream() {
            ended = true;
        }
        if !ended {
            window_rest = Some((body, w.overlap));
        }
        // A body that ended inside the window was read whole: it is inspected and forwarded like
        // any buffered body.
        head
    } else if stream_request {
        // A declared length over the cap is refused before a byte goes upstream.
        let declared = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        if declared.is_some_and(|n| n > rt.max_body as u64) {
            return too_large();
        }
        streamed_body = Some(StreamedRequestBody::new(
            body,
            rt.max_body,
            Arc::clone(&ingress),
        ));
        Bytes::new()
    } else {
        match axum::body::to_bytes(body, rt.max_body).await {
            Ok(b) => {
                ingress.fetch_add(b.len(), std::sync::atomic::Ordering::Relaxed);
                b
            }
            Err(_) => return too_large(),
        }
    };

    // 6) WAF-lite input inspection. A no-op unless `waf.mode` is report/block. The body is
    //    already buffered above, so inspecting it adds no extra read. On a match: `block` mode
    //    returns 403; `report` mode logs + counts and forwards. Both record the hit so a
    //    report-only rollout shows up in `edgeguard_waf_hits_total`.
    let waf_reported = match screen(
        &rt.waf,
        m,
        &raw_path,
        &parts.headers,
        host.as_deref(),
        &body_bytes,
        ip,
        &path,
    ) {
        WafVerdict::Block => {
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
        WafVerdict::Reported => true,
        WafVerdict::Pass => false,
    };

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

    // The window passed: forward it, then the rest of the body through the tail inspector.
    if let Some((rest, overlap)) = window_rest.take() {
        let tail = crate::stream_inspect::TailInspector::new(
            rt.waf.needs_body().then(|| Arc::clone(&rt.waf)),
            rt.dlp.as_ref().filter(|d| d.scan_request()).cloned(),
            Arc::clone(m),
            overlap,
            &body_bytes,
            waf_reported,
        );
        streamed_body = Some(StreamedRequestBody::windowed(
            std::mem::take(&mut body_bytes),
            rest,
            rt.max_body,
            Arc::clone(&ingress),
            tail,
        ));
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
        // A virtual key, or else the verified claims of the request's JWT.
        match presented
            .and_then(|k| vault.lookup(k))
            .or_else(|| claims.as_deref().and_then(|c| vault.lookup_claims(c)))
        {
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
    // the upstream — an unpriced model is never served at a silent $0. Metering-only deployments (empty `[llm.models]`) never trip this. Runs after the
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
            claims: claims.as_deref(),
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

    // 7) Build the upstream request (the per-path upstream override, or the default), for the
    // first of the route's targets to try.
    // Two forms again, and for the same reason as `raw_path`/`path` above: `uri` is forwarded and
    // must carry the client's query verbatim, `log_uri` (below) is what a timeout or a connection
    // error writes to the log. Redacting the access log and then printing the same `?api_key=` in a
    // `warn!` on the failure path would leak exactly the credentials this is meant to keep out — and
    // on the path an operator is most likely to be reading.
    let pool = rt.pick_upstream(&raw_path);
    let affinity = pool.affinity(&parts.headers, &parts.uri, ip);
    let tries = pool.order_for(&affinity);
    let uri = format!("{}{raw_path}", tries[0].base);
    let mut up = Request::builder().method(parts.method.clone()).uri(&uri);
    {
        let headers = up.headers_mut().expect("builder headers");
        // Drop hop-by-hop headers (the fixed set plus any named by `Connection`) before
        // forwarding, so they don't leak across the proxy boundary.
        let mut forwarded = parts.headers.clone();
        strip_hop_by_hop(&mut forwarded);
        pool.strip_sticky_cookie(&mut forwarded);
        // The body is re-sent from a sized `Full`, so the client's Content-Length may be stale (it
        // is once DLP redaction rewrote the body). Drop it and let the upstream client recompute the
        // correct length from the body, rather than forwarding a mismatched header.
        forwarded.remove(header::CONTENT_LENGTH);
        forward_headers(&forwarded, headers);
        set_client_cert_header(headers, rt.client_cert_header, client_cert.as_deref());
        // Standard forwarding headers, every client-address one the edge's own.
        set_forwarding_headers(
            headers,
            ip,
            forwarded_proto(
                &rt.cfg,
                parts.extensions.get::<ForwardingTrusted>().is_some(),
                &parts.headers,
            ),
            parts
                .extensions
                .get::<EffectiveHost>()
                .and_then(|h| h.0.as_deref()),
        );
        // Forward the (resolved/generated) request id so the upstream logs the same correlation id.
        if let Ok(v) = HeaderValue::from_str(&rid) {
            headers.insert(HeaderName::from_static(REQUEST_ID_HEADER), v);
        }
        // W3C trace context, outbound. Without this the app behind the proxy starts its own trace
        // and the edge's span is an orphan — the request appears twice in the backend with nothing
        // connecting them, which is the failure that makes proxy tracing worth less than none.
        //
        // The flags are `01` (sampled), because this is only reached when we are recording; that is
        // what stops the app's own sampler dropping the other half of the trace.
        if let Some(ctx) = parts
            .extensions
            .get::<crate::telemetry::TraceContext>()
            .copied()
        {
            if let Ok(v) = HeaderValue::from_str(&crate::telemetry::traceparent_header(&ctx)) {
                headers.insert(HeaderName::from_static("traceparent"), v);
            }
            // `tracestate` belongs to the caller's traceparent. Having replaced that, a forwarded
            // tracestate refers to a span id no longer in the header and is worse than absent.
            headers.remove("tracestate");
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

    // Watch the streamed body's cap: past it the upload is cut mid-request, and the client is owed a
    // 413, not the 502 a cut request would otherwise read as.
    let request_cut = streamed_body.as_ref().map(StreamedRequestBody::cut_flag);
    let request_blocked = streamed_body
        .as_ref()
        .map(StreamedRequestBody::blocked_flag);
    // The body again, for the next target should the first refuse the connection. Only a buffered
    // one: a streamed body is read as it is sent, once.
    let replay = (tries.len() > 1 && streamed_body.is_none()).then(|| body_bytes.clone());
    let upstream_body = match streamed_body {
        Some(b) => Body::new(b),
        None => Body::from(body_bytes),
    };
    let upstream_req = match up.body(upstream_body) {
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
    //    can't pin this task. `None` => no timeout (validation.upstream_timeout = "0"). The
    //    deadline covers every target tried.
    let deadline = rt.upstream_timeout.map(|d| tokio::time::Instant::now() + d);
    let template = (tries.len() > 1).then(|| {
        (
            upstream_req.method().clone(),
            upstream_req.headers().clone(),
        )
    });
    let again = |target: &crate::pool::Target| {
        let (method, headers) = template.as_ref()?;
        let mut req = Request::builder()
            .method(method.clone())
            .uri(format!("{}{raw_path}", target.base))
            .body(Body::from(replay.clone()?))
            .ok()?;
        *req.headers_mut() = headers.clone();
        Some(req)
    };

    // The wait, from the first send to the answer, for the access log's `upstream_ms`; the target
    // that answered gets its own attempt's in its histogram. An exchange the edge itself cut short
    // (the request body over its cap, or blocked by inspection) says nothing about the upstream
    // and is not counted against it.
    let sent = Instant::now();
    let attempt = send_to_pool(state, pool, &tries, upstream_req, again, deadline, &path).await;
    let waited = sent.elapsed();
    let target = attempt.target;
    // In flight until `ctx` goes: when this returns, or a streamed body (which holds it) ends.
    if let Some(in_flight) = attempt.in_flight {
        let _ = ctx.in_flight.set(in_flight);
    }
    let up_stats = m.upstream_stats(&target.label);
    let _ = ctx.upstream.set(target.label.clone());
    // Credentials in a configured upstream URL never reach a log line: `target.base` is built
    // without them (`pool::target`), and only it is redacted again, never the client's path,
    // whose `@` (an email address) would otherwise hide the upstream host.
    let log_uri = format!("{}{path}", crate::redact::userinfo(&target.base));
    let timed_out = || {
        warn!(upstream = %log_uri, "upstream timed out");
        text(StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout")
    };
    let _ = ctx.upstream_ms.set(waited.as_millis() as u64);
    let upstream_resp = match attempt.result {
        Ok(Ok(r)) => {
            up_stats.observe_headers(attempt.waited);
            r
        }
        Ok(Err(_))
            if request_cut
                .as_ref()
                .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) =>
        {
            warn!(
                limit = rt.max_body,
                "streamed request body exceeded max_body; upload cut"
            );
            return too_large();
        }
        Ok(Err(_))
            if request_blocked
                .as_ref()
                .is_some_and(|b| b.load(std::sync::atomic::Ordering::Relaxed)) =>
        {
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
        Ok(Err(e)) => {
            up_stats.record(UpstreamResult::classify(&e));
            warn!(
                error = crate::upstream::error_chain(&e),
                upstream = %log_uri,
                "upstream unreachable"
            );
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
            up_stats.record(UpstreamResult::Timeout);
            return finish(
                m,
                &rid,
                &method,
                &path,
                ip,
                started,
                "upstream_timeout",
                timed_out(),
            );
        }
    };

    let (mut resp_parts, resp_body) = upstream_resp.into_parts();
    // Before hardening, which treats it as it does the upstream's own cookies.
    if let Some(cookie) = pool.sticky_cookie(&affinity, target) {
        resp_parts.headers.append(header::SET_COOKIE, cookie);
    }
    // How the exchange ended once the upstream has answered: by its status, unless reading a
    // buffered body fails below.
    let answered = UpstreamResult::from_status(resp_parts.status.as_u16());

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
    let sse_stream =
        rt.stream_passthrough && is_event_stream(&resp_parts.headers) && !dlp_blocks_response;
    // 8b) Any other response streams too when `stream_responses` is on and nothing below needs the
    //     whole body (see `streams_any_response`). Unlike SSE, `max_response_body` still holds —
    //     enforced as the bytes flow — and the body passes through unmodified, so the upstream's
    //     `Content-Length` stays (a download keeps its progress bar; a cut body is visibly short).
    let whole_stream = !sse_stream
        && streams_any_response(
            rt.stream_responses,
            llm_model.is_some(),
            rt.dlp.as_ref().is_some_and(|d| d.reversible()),
            rt.dlp.as_ref().is_some_and(|d| d.scan_response()),
        );
    if sse_stream || whole_stream {
        // A streamed body is not waited for: the exchange is counted on its headers.
        up_stats.record(answered);
        let _ = ctx.upstream_busy.set(waited);
        strip_hop_by_hop(&mut resp_parts.headers);
        if sse_stream {
            resp_parts.headers.remove(header::CONTENT_LENGTH);
        }
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
                usage: crate::llm::StreamUsage::default(),
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
        let body = if whole_stream && rt.max_response_body > 0 {
            // Over the cap, `Limited` errors the stream and the connection is cut: the headers are
            // already out, so a short body is the only signal left to give.
            Body::new(
                CountingBody::new(
                    Limited::new(resp_body, rt.max_response_body),
                    Arc::clone(m),
                    Arc::clone(&ingress),
                    header_egress,
                    llm_meter,
                    dlp_scanner,
                    unmasker,
                )
                .with_ctx(Arc::clone(ctx)),
            )
        } else {
            Body::new(
                CountingBody::new(
                    resp_body,
                    Arc::clone(m),
                    Arc::clone(&ingress),
                    header_egress,
                    llm_meter,
                    dlp_scanner,
                    unmasker,
                )
                .with_ctx(Arc::clone(ctx)),
            )
        };
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
            Ok(Ok(c)) => {
                up_stats.record(answered);
                c.to_bytes()
            }
            Ok(Err(e)) => {
                // Over the cap is the edge's limit, not an upstream failure; a broken body is.
                up_stats.record(if e.is::<http_body_util::LengthLimitError>() {
                    answered
                } else {
                    UpstreamResult::classify(&*e)
                });
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
                up_stats.record(UpstreamResult::Timeout);
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "upstream_timeout",
                    timed_out(),
                );
            }
        }
    } else {
        match within(deadline, resp_body.collect()).await {
            Ok(Ok(c)) => {
                up_stats.record(answered);
                c.to_bytes()
            }
            Ok(Err(e)) => {
                up_stats.record(UpstreamResult::classify(&e));
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
                up_stats.record(UpstreamResult::Timeout);
                return finish(
                    m,
                    &rid,
                    &method,
                    &path,
                    ip,
                    started,
                    "upstream_timeout",
                    timed_out(),
                );
            }
        }
    };

    // Waiting on the upstream ends here; what follows (inspection, rewriting) is the edge's.
    let _ = ctx.upstream_busy.set(sent.elapsed());

    // The body was rebuffered, so let the server recompute framing; strip hop-by-hop headers
    // (incl. any named by `Connection`) so they don't leak downstream.
    strip_hop_by_hop(&mut resp_parts.headers);
    resp_parts.headers.remove(header::CONTENT_LENGTH);

    // Managed-mode usage: this is the proxied path, where both bodies are buffered, so the byte
    // counts are exact. (`add_usage_request` is recorded for every request in `finish`.)
    let (bytes_in, bytes_out) = (
        ingress.load(std::sync::atomic::Ordering::Relaxed),
        header_bytes(&resp_parts.headers).saturating_add(resp_bytes.len()),
    );
    m.add_usage_bytes(bytes_in, bytes_out);
    if let Some(stats) = ctx.consumer.get() {
        stats.add_bytes(bytes_in, bytes_out);
    }
    let _ = ctx.bytes.set((bytes_in as u64, bytes_out as u64));

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

/// Whether a request body may stream to the upstream when `validation.stream_requests` is on: only
/// when nothing reads the whole body before it is forwarded. One argument per reader, as in
/// [`streams_any_response`]:
///
/// * `waf_reads_body` — a WAF rule targets the body ([`WafEngine::needs_body`]);
/// * `dlp_scans_request` — inbound DLP judges and may rewrite the body;
/// * `llm_reads_body` — `[llm]` metering, the virtual-key vault and budgets parse the model (and
///   `max_tokens`) out of the body before forwarding.
pub(crate) fn streams_request(
    enabled: bool,
    waf_reads_body: bool,
    dlp_scans_request: bool,
    llm_reads_body: bool,
) -> bool {
    enabled && !waf_reads_body && !dlp_scans_request && !llm_reads_body
}

/// A request body forwarded as it arrives: capped at `max_body` (via [`Limited`]), counted into the
/// shared ingress total, and flagging when the cap cut it so the caller can answer 413. A windowed
/// body (`[[validation.stream_inspect]]`) first sends its already-inspected window, then runs every
/// later frame through a [`TailInspector`](crate::stream_inspect::TailInspector) and cuts the
/// upload on a block, flagging it so the caller answers 403.
struct StreamedRequestBody {
    inner: Limited<Body>,
    ingress: Arc<std::sync::atomic::AtomicUsize>,
    cut: Arc<std::sync::atomic::AtomicBool>,
    head: Option<Bytes>,
    tail: Option<crate::stream_inspect::TailInspector>,
    blocked: Arc<std::sync::atomic::AtomicBool>,
}

/// The error a windowed body ends with when its tail inspector blocks it.
#[derive(Debug)]
struct InspectionBlocked;

impl std::fmt::Display for InspectionBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body blocked by inspection")
    }
}

impl std::error::Error for InspectionBlocked {}

impl StreamedRequestBody {
    fn new(inner: Body, max: usize, ingress: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        Self {
            inner: Limited::new(inner, max),
            ingress,
            cut: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            head: None,
            tail: None,
            blocked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// `head` was read, counted and inspected already; the cap on `rest` is what `max` leaves.
    fn windowed(
        head: Bytes,
        rest: Body,
        max: usize,
        ingress: Arc<std::sync::atomic::AtomicUsize>,
        tail: crate::stream_inspect::TailInspector,
    ) -> Self {
        let mut body = Self::new(rest, max.saturating_sub(head.len()), ingress);
        body.head = Some(head);
        body.tail = Some(tail);
        body
    }

    /// Set once the body went past its cap.
    fn cut_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.cut)
    }

    /// Set once the tail inspector blocked the body.
    fn blocked_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.blocked)
    }
}

impl HttpBody for StreamedRequestBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if let Some(head) = this.head.take() {
            return Poll::Ready(Some(Ok(Frame::data(head))));
        }
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.ingress
                        .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
                    if let Some(tail) = this.tail.as_mut() {
                        if tail.check(data) == crate::stream_inspect::Verdict::Block {
                            this.blocked
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            this.tail = None;
                            return Poll::Ready(Some(Err(Box::new(InspectionBlocked))));
                        }
                    }
                }
            }
            Poll::Ready(Some(Err(e))) if e.is::<http_body_util::LengthLimitError>() => {
                this.cut.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.head.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.inner.size_hint();
        if let Some(head) = &self.head {
            // Upper first: `set_lower` asserts lower <= upper.
            let n = head.len() as u64;
            if let Some(upper) = hint.upper() {
                hint.set_upper(upper + n);
            }
            hint.set_lower(hint.lower() + n);
        }
        hint
    }
}

/// Whether a response may stream when `validation.stream_responses` is on: only when nothing on
/// the request needs the *whole* body. Each feature that reads the full response is one argument
/// here, so adding such a feature means adding it to this list — and to its test — rather than
/// silently reading half a body.
///
/// * `llm_route` — buffered LLM metering parses the upstream's `usage` object out of the full JSON;
/// * `reversible_dlp` — unmasking restores placeholders across the whole body;
/// * `dlp_scans_response` — outbound DLP judges (and may withhold or rewrite) the whole body.
pub(crate) fn streams_any_response(
    enabled: bool,
    llm_route: bool,
    reversible_dlp: bool,
    dlp_scans_response: bool,
) -> bool {
    enabled && !llm_route && !reversible_dlp && !dlp_scans_response
}

/// `X-Forwarded-Client-Cert` on the way upstream. While client authentication is on the client's
/// own is always dropped — EdgeGuard terminated the client's TLS, so no one in front of it could
/// have written one the app should believe — and with `forward_client_cert = "xfcc"` it is
/// replaced by one describing the certificate the listener verified.
fn set_client_cert_header(
    headers: &mut HeaderMap,
    policy: crate::client_auth::ForwardPolicy,
    cert: Option<&crate::client_auth::ClientCert>,
) {
    if policy.strip_inbound {
        headers.remove(crate::client_auth::XFCC_HEADER);
    }
    if let (true, Some(cert)) = (policy.forward, cert) {
        if let Ok(v) = HeaderValue::from_str(&cert.xfcc()) {
            headers.insert(HeaderName::from_static(crate::client_auth::XFCC_HEADER), v);
        }
    }
}

/// Readiness probe. Returns `200` only if the upstream accepts a TCP connection, so a
/// platform's readiness check reflects whether EdgeGuard can actually serve traffic — not
/// merely that the process booted. `503` while the upstream is unreachable, while a `refuse` edge
/// waits for its first control-plane policy, and from the moment shutdown begins, so traffic
/// moves elsewhere before the listeners drain. (Liveness, i.e. "is
/// EdgeGuard itself up", is the separate unconditional `/__edgeguard/health`, which stays `200`
/// through the drain so the process is not killed early.)
pub async fn ready(State(state): State<AppState>) -> StatusCode {
    if state.draining.load(std::sync::atomic::Ordering::Acquire)
        || state
            .policy_pending
            .load(std::sync::atomic::Ordering::Acquire)
    {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let rt = state.runtime.load();
    // A pool that serves everything is ready while any of its targets is in rotation: its checks
    // already say what a connection here would.
    let root = rt.pick_upstream("/");
    if root.is_pool() {
        return if root.any_in_rotation() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
    }
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

/// Every route's upstreams (`GET /__edgeguard/upstreams`), the default first: where each prefix
/// goes and, for a pool, whether each target takes requests and why not (its health check, an
/// ejection after failed connections), with each target's request counts. Reading it changes
/// nothing, round-robin's turn included. An ops endpoint, so in split mode it is admin-port only.
pub async fn upstreams_status(State(state): State<AppState>) -> Response<Body> {
    let rt = state.runtime.load();
    let requests = |label: &str| {
        let counts = state.metrics.upstream_results(label);
        serde_json::Value::Object(
            UpstreamResult::ALL
                .iter()
                .zip(counts)
                .map(|(r, n)| (r.label().to_string(), serde_json::json!(n)))
                .collect(),
        )
    };
    let routes: Vec<serde_json::Value> =
        std::iter::once(rt.default_upstream.status_json(None, requests))
            .chain(
                rt.upstream_routes
                    .iter()
                    .map(|(prefix, pool)| pool.status_json(Some(prefix), requests)),
            )
            .collect();
    let mut resp = Response::new(Body::from(
        serde_json::json!({ "routes": routes }).to_string(),
    ));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// The edge's certificates (`GET /__edgeguard/tls`). For the served certificate, at the top level
/// as in 0.5.0: source, serial, validity, days left, whether renewal is due, and the last renewal
/// attempt. Then `sni` (the `[[tls.certs]]` pairs), `client_certs` (each client certificate the
/// edge presents, and what presents it) and `client_auth` (the CAs and CRLs client certificates are
/// checked against), each present only when there is one. `404` when there is no certificate at
/// all. Lives with the other ops endpoints, so in split mode it is admin-port only.
pub async fn tls_status(State(state): State<AppState>) -> Response<Body> {
    let mut status = match state.metrics.cert_store() {
        Some(store) => {
            let mut status = store.status_json();
            // Absent (not an empty list) when there are none, so a single-certificate edge reads as
            // it did in 0.5.0.
            let sni = state.metrics.sni_certs();
            if !sni.is_empty() {
                status["sni"] = serde_json::Value::Array(
                    sni.iter()
                        .map(|c| {
                            let mut j = c.store.status_json();
                            j["hosts"] = serde_json::json!(c.hosts);
                            j
                        })
                        .collect(),
                );
            }
            status
        }
        None => serde_json::json!({}),
    };
    let clients = state.metrics.client_certs();
    if !clients.is_empty() {
        status["client_certs"] = serde_json::Value::Array(
            clients
                .iter()
                .map(|c| {
                    let mut j = c.store.validity_json();
                    j["used_by"] = serde_json::json!(c.used_by);
                    j
                })
                .collect(),
        );
    }
    if let Some(auth) = state.metrics.client_auth() {
        let mut j = trust_json(auth);
        j["mode"] = serde_json::json!(auth.mode().label());
        status["client_auth"] = j;
    }
    if let Some(header) = state.metrics.trusted_header() {
        let mut j = header.verifier().map(trust_json).unwrap_or_default();
        j["name"] = serde_json::json!(header.name().as_str());
        j["format"] = serde_json::json!(format!("{:?}", header.format()).to_ascii_lowercase());
        j["trusted_proxies"] = serde_json::json!(header.trusted_proxies());
        j["trusted_proxy_names"] = serde_json::json!(header.trusted_proxy_names());
        status["trusted_client_cert_header"] = j;
    }
    if status.as_object().is_some_and(|o| o.is_empty()) {
        let mut resp = Response::new(Body::from("TLS is not enabled on this listener\n"));
        *resp.status_mut() = StatusCode::NOT_FOUND;
        return resp;
    }
    let mut resp = Response::new(Body::from(status.to_string()));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// A client-certificate verifier's CA bundle and CRLs, for `GET /__edgeguard/tls`.
fn trust_json(auth: &Arc<crate::client_auth::ClientAuth>) -> serde_json::Value {
    let now = crate::certstore::now_unix();
    let trust = auth.trust();
    serde_json::json!({
        "ca_path": auth.ca_path(),
        "cas": trust.cas.iter().map(|ca| serde_json::json!({
            "name": ca.name,
            "serial": ca.info.serial,
            "not_before": ca.info.not_before,
            "not_after": ca.info.not_after,
            "days_left": ca.info.days_left(now),
        })).collect::<Vec<_>>(),
        "crls": trust.crls.iter().map(|crl| serde_json::json!({
            "name": crl.name,
            "this_update": crl.info.this_update,
            "next_update": crl.info.next_update,
            "stale": crl.info.stale(now),
        })).collect::<Vec<_>>(),
    })
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

/// The most trusted proxies `server.forwarded_hops` may name.
pub const MAX_FORWARDED_HOPS: usize = 10;

/// How a request's `X-Forwarded-For` was read, with `trust_forwarded_for` on:
/// `edgeguard_forwarded_for_total{result}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardedFor {
    /// The entry `forwarded_hops` from the right is the client.
    Used,
    /// No header: the TCP peer is the client.
    Absent,
    /// Fewer entries than `forwarded_hops`: the TCP peer is the client.
    Short,
    /// The chosen entry is not an IP address (or not text): the TCP peer.
    Invalid,
    /// A header from a TCP peer outside `server.trusted_forwarders`: ignored, the peer.
    UntrustedPeer,
}

impl ForwardedFor {
    /// Every result, in the order the metric renders them.
    pub const ALL: [ForwardedFor; 5] = [
        ForwardedFor::Used,
        ForwardedFor::Absent,
        ForwardedFor::Short,
        ForwardedFor::Invalid,
        ForwardedFor::UntrustedPeer,
    ];

    /// The `result` label value.
    pub fn label(self) -> &'static str {
        match self {
            ForwardedFor::Used => "used",
            ForwardedFor::Absent => "absent",
            ForwardedFor::Short => "short",
            ForwardedFor::Invalid => "invalid",
            ForwardedFor::UntrustedPeer => "untrusted_peer",
        }
    }
}

/// How far `forwarded_hops = "auto"` walks from the right before giving up: no real chain of
/// trusted proxies is this long, and a client must not make the edge walk thousands.
pub const MAX_FORWARDED_WALK: usize = 32;

/// Set on a request whose forwarding headers come from a trusted hop, so its
/// `X-Forwarded-Proto` may be believed too.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ForwardingTrusted;

/// `server.trust_forwarded_for`, `server.forwarded_hops` and `server.trusted_forwarders`,
/// compiled: whom the forwarding headers are believed from, and which entry is the client.
#[derive(Debug, Clone, Default)]
pub struct Forwarders {
    trust: bool,
    hops: crate::config::ForwardedHops,
    list: Vec<crate::access::Cidr>,
}

impl Forwarders {
    /// Compile the settings. A hop count out of range, a list entry that is not an IP or CIDR, a
    /// `/0` (any peer, the 0.7 behaviour in disguise), a list without `trust_forwarded_for`
    /// (which would do nothing), and `"auto"` without a list fail.
    pub fn from_cfg(cfg: &crate::config::ServerCfg) -> anyhow::Result<Forwarders> {
        use crate::config::ForwardedHops;
        use anyhow::Context as _;
        if let ForwardedHops::Count(n) = cfg.forwarded_hops {
            anyhow::ensure!(
                (1..=MAX_FORWARDED_HOPS).contains(&n),
                "server.forwarded_hops = {n}: it counts the trusted proxies in front of EdgeGuard \
                 that each append an X-Forwarded-For entry, from 1 to {MAX_FORWARDED_HOPS}, or \
                 \"auto\" with server.trusted_forwarders"
            );
        }
        let list = cfg
            .trusted_forwarders
            .iter()
            .map(|t| crate::access::Cidr::parse(t).context("server.trusted_forwarders"))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if let Some((text, _)) = cfg
            .trusted_forwarders
            .iter()
            .zip(&list)
            .find(|(_, c)| c.is_everything())
        {
            anyhow::bail!(
                "server.trusted_forwarders contains {text:?}, every address: any peer could write \
                 X-Forwarded-For and choose its client address. List the proxies' addresses"
            );
        }
        anyhow::ensure!(
            list.is_empty() || cfg.trust_forwarded_for,
            "server.trusted_forwarders is set but server.trust_forwarded_for is off, so \
             X-Forwarded-For is never read: set trust_forwarded_for = true, or remove the list"
        );
        anyhow::ensure!(
            cfg.forwarded_hops != ForwardedHops::Auto || !list.is_empty(),
            "server.forwarded_hops = \"auto\" walks past the entries of server.trusted_forwarders, \
             which is empty: list the proxies, or give forwarded_hops a count"
        );
        Ok(Forwarders {
            trust: cfg.trust_forwarded_for,
            hops: cfg.forwarded_hops,
            list,
        })
    }

    /// Whether the forwarding headers are believed from any peer: `trust_forwarded_for` with no
    /// `trusted_forwarders`, the 0.7 behaviour.
    /// Logged at startup and after a reload while [`Forwarders::trusts_any_peer`].
    pub const TRUSTS_ANY_PEER: &'static str = "server.trust_forwarded_for is on without server.trusted_forwarders: X-Forwarded-For is believed on every connection, so anything that reaches this port directly chooses its client address; list the proxies (this fails startup from 0.9)";

    pub fn trusts_any_peer(&self) -> bool {
        self.trust && self.list.is_empty()
    }

    fn listed(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.list.iter().any(|c| c.contains(ip))
    }

    /// Whether a connection whose TCP peer is `hop` may set the forwarding headers.
    pub(crate) fn believes(&self, hop: IpAddr) -> bool {
        self.trust && (self.list.is_empty() || self.listed(hop))
    }

    /// The client a request is served as. `peer` is the connection's client (its TCP peer, or the
    /// client a trusted PROXY header named); `hop` its TCP peer, which the list is matched against.
    pub(crate) fn resolve(
        &self,
        headers: &HeaderMap,
        peer: SocketAddr,
        hop: IpAddr,
    ) -> (IpAddr, Option<ForwardedFor>) {
        if !self.trust {
            return client_ip(headers, peer, false, 1);
        }
        if !self.believes(hop) {
            let result = if headers.contains_key("x-forwarded-for") {
                ForwardedFor::UntrustedPeer
            } else {
                ForwardedFor::Absent
            };
            return (peer.ip().to_canonical(), Some(result));
        }
        match self.hops {
            crate::config::ForwardedHops::Count(n) => client_ip(headers, peer, true, n),
            crate::config::ForwardedHops::Auto => self.walk(headers, peer),
        }
    }

    /// `forwarded_hops = "auto"`: from the right, past the entries inside the list, to the first
    /// that is not. Only the entries walked over and the chosen one are parsed: those further left
    /// are the client's and never matter, so client-written garbage there cannot force the
    /// fallback. Every entry trusted: the leftmost. More than [`MAX_FORWARDED_WALK`] trusted
    /// entries: `invalid`.
    fn walk(&self, headers: &HeaderMap, peer: SocketAddr) -> (IpAddr, Option<ForwardedFor>) {
        let peer_ip = peer.ip().to_canonical();
        let mut lines = headers.get_all("x-forwarded-for").iter().rev().peekable();
        if lines.peek().is_none() {
            return (peer_ip, Some(ForwardedFor::Absent));
        }
        let mut leftmost = None;
        for (walked, entry) in lines
            .flat_map(|line| line.as_bytes().rsplit(|b| *b == b','))
            .map(<[u8]>::trim_ascii)
            .filter(|e| !e.is_empty())
            .enumerate()
        {
            if walked == MAX_FORWARDED_WALK {
                return (peer_ip, Some(ForwardedFor::Invalid));
            }
            let Some(ip) = std::str::from_utf8(entry).ok().and_then(parse_forwarded_ip) else {
                return (peer_ip, Some(ForwardedFor::Invalid));
            };
            if !self.listed(ip) {
                return (ip, Some(ForwardedFor::Used));
            }
            leftmost = Some(ip);
        }
        match leftmost {
            Some(ip) => (ip, Some(ForwardedFor::Used)),
            None => (peer_ip, Some(ForwardedFor::Short)),
        }
    }
}

/// Resolve the client IP: the one function every consumer of the client address goes through
/// (rate limits, `[access]`, pool hashing on `client_ip`, the access log and shipped records,
/// spans and the `X-Forwarded-For` sent upstream).
///
/// The connection's peer is authoritative (with PROXY protocol, the client the header named).
/// `X-Forwarded-For` is read only with `trust_forwarded_for`, and then from the RIGHT: each proxy
/// appends the address it accepted the connection from, so the entries a client sends itself are
/// on the left and must never be believed. With `hops` trusted proxies in front, each appending
/// one entry, the client is the entry `hops` from the right. Several header lines are one list,
/// in order (RFC 9110 §5.3). Anything short of that falls back to the peer, and says why.
pub(crate) fn client_ip(
    headers: &HeaderMap,
    peer: SocketAddr,
    trust_forwarded: bool,
    hops: usize,
) -> (IpAddr, Option<ForwardedFor>) {
    // A dual-stack socket reports an IPv4 client as `::ffff:a.b.c.d`; key it as the IPv4 it is.
    let peer_ip = peer.ip().to_canonical();
    if !trust_forwarded {
        return (peer_ip, None);
    }
    let mut lines = headers.get_all("x-forwarded-for").iter().rev().peekable();
    if lines.peek().is_none() {
        return (peer_ip, Some(ForwardedFor::Absent));
    }
    // Walked from the right, as bytes, never further than the chosen entry (at most
    // MAX_FORWARDED_HOPS): the entries left of it are the client's, and whatever a client puts
    // there (bytes that are not text, thousands of entries) must not matter, or a client could
    // make itself the balancer, for rate limits and `[access]`. Only the chosen entry has to be
    // text, and an address.
    let hops = hops.clamp(1, MAX_FORWARDED_HOPS);
    let chosen = lines
        .flat_map(|line| line.as_bytes().rsplit(|b| *b == b','))
        .map(<[u8]>::trim_ascii)
        .filter(|e| !e.is_empty())
        .nth(hops - 1);
    let Some(chosen) = chosen else {
        return (peer_ip, Some(ForwardedFor::Short));
    };
    match std::str::from_utf8(chosen)
        .ok()
        .and_then(parse_forwarded_ip)
    {
        Some(ip) => (ip, Some(ForwardedFor::Used)),
        None => (peer_ip, Some(ForwardedFor::Invalid)),
    }
}

/// One `X-Forwarded-For` entry as an address: `1.2.3.4`, `1.2.3.4:5678`, `2001:db8::1`,
/// `[2001:db8::1]` or `[2001:db8::1]:5678`. An IPv4-mapped IPv6 address is the IPv4 one.
fn parse_forwarded_ip(entry: &str) -> Option<IpAddr> {
    let ip = if let Ok(ip) = entry.parse::<IpAddr>() {
        ip
    } else if let Ok(sock) = entry.parse::<SocketAddr>() {
        sock.ip()
    } else {
        entry
            .strip_prefix('[')
            .and_then(|e| e.strip_suffix(']'))?
            .parse::<IpAddr>()
            .ok()?
    };
    Some(ip.to_canonical())
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
    // `raw_path` routes and is forwarded verbatim; `path` is the redacted form that reaches a log
    // line. See the note where they are derived in `handle_inner`.
    raw_path: &str,
    path: &str,
    ip: IpAddr,
    started: Instant,
    ctx: &Arc<RequestCtx>,
) -> Response<Body> {
    let m = &state.metrics;

    // The client-side upgrade future: once we return a `101`, the server completes it and yields
    // the raw client connection. Take it (removing the extension from `req`) before forwarding.
    let client_upgrade = hyper::upgrade::on(&mut req);

    // Build the upstream request: copy end-to-end headers AND the upgrade/connection headers
    // (the handshake needs them), add the forwarding headers, send an empty body.
    // A sticky cookie is followed here but not set: a `101` is not hardened like other answers,
    // and the page that opened the socket has set it already.
    let pool = rt.pick_upstream(raw_path);
    let affinity = pool.affinity(req.headers(), req.uri(), ip);
    let tries = pool.order_for(&affinity);
    let uri = format!("{}{raw_path}", tries[0].base);
    let mut up = Request::builder().method(req.method().clone()).uri(&uri);
    {
        let headers = up.headers_mut().expect("builder headers");
        // Strip hop-by-hop headers (the fixed set + any named by `Connection`) before forwarding,
        // so a client can't smuggle connection-scoped headers upstream — then re-add the handshake
        // headers the upgrade itself needs (`Connection: upgrade` + the requested `Upgrade`).
        let upgrade = req.headers().get(header::UPGRADE).cloned();
        let mut forwarded = req.headers().clone();
        strip_hop_by_hop(&mut forwarded);
        pool.strip_sticky_cookie(&mut forwarded);
        forward_headers(&forwarded, headers);
        let client_cert = req
            .extensions()
            .get::<Arc<crate::client_auth::ClientCert>>()
            .cloned();
        set_client_cert_header(headers, rt.client_cert_header, client_cert.as_deref());
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        if let Some(v) = upgrade {
            headers.insert(header::UPGRADE, v);
        }
        set_forwarding_headers(
            headers,
            ip,
            forwarded_proto(
                &rt.cfg,
                req.extensions().get::<ForwardingTrusted>().is_some(),
                req.headers(),
            ),
            req.extensions()
                .get::<EffectiveHost>()
                .and_then(|h| h.0.as_deref()),
        );
        if let Ok(v) = HeaderValue::from_str(request_id) {
            headers.insert(HeaderName::from_static(REQUEST_ID_HEADER), v);
        }
    }
    let upstream_req = match up.body(Body::empty()) {
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
    // The handshake has no body, so any target refusing the connection can be followed by the next.
    let template = (tries.len() > 1).then(|| {
        (
            upstream_req.method().clone(),
            upstream_req.headers().clone(),
        )
    });
    let again = |target: &crate::pool::Target| {
        let (method, headers) = template.as_ref()?;
        let mut req = Request::builder()
            .method(method.clone())
            .uri(format!("{}{raw_path}", target.base))
            .body(Body::empty())
            .ok()?;
        *req.headers_mut() = headers.clone();
        Some(req)
    };

    // Counted on the handshake's answer: what follows a `101` is a tunnel, not an exchange.
    let sent = Instant::now();
    let attempt = send_to_pool(state, pool, &tries, upstream_req, again, deadline, path).await;
    let waited = sent.elapsed();
    let target = attempt.target;
    // A tunnel holds a connection to the target for its whole life: in flight until it closes.
    let in_flight = attempt.in_flight;
    let up_stats = m.upstream_stats(&target.label);
    let _ = ctx.upstream.set(target.label.clone());
    // The redacted form, for the failure logs below: the path's query redacted, and (as defence in
    // depth: `target.base` has none) any URL credentials. See the note in `handle_inner`.
    let log_uri = format!("{}{path}", crate::redact::userinfo(&target.base));
    let timed_out = || {
        warn!(upstream = %log_uri, "upstream timed out (upgrade)");
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

    let _ = ctx.upstream_ms.set(waited.as_millis() as u64);
    let mut up_resp = match attempt.result {
        Ok(Ok(r)) => {
            up_stats.observe_headers(attempt.waited);
            up_stats.record(UpstreamResult::from_status(r.status().as_u16()));
            let _ = ctx.upstream_busy.set(waited);
            r
        }
        Ok(Err(e)) => {
            up_stats.record(UpstreamResult::classify(&e));
            warn!(
                error = crate::upstream::error_chain(&e),
                upstream = %log_uri,
                "upstream unreachable (upgrade)"
            );
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
        Err(_) => {
            up_stats.record(UpstreamResult::Timeout);
            return timed_out();
        }
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
        let _in_flight = in_flight;
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
    /// Request (ingress) bytes, read when the response finishes: a streamed request body may still
    /// be counting while the response starts.
    ingress: Arc<std::sync::atomic::AtomicUsize>,
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
    /// The request this body answers: its consumer, whose bytes these are, and the access line
    /// this body writes when it ends.
    ctx: Option<Arc<RequestCtx>>,
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

/// Reads the usage an SSE stream reports as it passes ([`crate::llm::StreamUsage`]), so it is known
/// when the body finishes. Holds the model + price book; records to metrics and reconciles the L1
/// budget on drop.
struct LlmStreamMeter {
    model: String,
    llm: Arc<crate::llm::LlmRuntime>,
    usage: crate::llm::StreamUsage,
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
        ingress: Arc<std::sync::atomic::AtomicUsize>,
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
            ctx: None,
        }
    }

    /// Count this body's bytes to the request's consumer, and write its access line when the body
    /// ends.
    fn with_ctx(mut self, ctx: Arc<RequestCtx>) -> Self {
        ctx.streamed
            .store(true, std::sync::atomic::Ordering::Release);
        self.ctx = Some(ctx);
        self
    }

    /// Feed the bytes the client will actually receive to the stream's usage reader, so the usage
    /// it reports (in its first frames, its last, or both) is known on drop.
    fn push_meter(&mut self, data: &[u8]) {
        if let Some(meter) = self.llm.as_mut() {
            // Stamp first/last emitted-frame time for TTFT/TPOT (this runs on the bytes the client
            // actually receives, so it measures server-side time-to-first-token with no client clock).
            if !data.is_empty() {
                let now = Instant::now();
                meter.first_at.get_or_insert(now);
                meter.last_at = Some(now);
            }
            meter.usage.feed(data);
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
                                    this.push_meter(&out);
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
                                this.push_meter(&out);
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
                    this.push_meter(&out);
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                if this.dlp.as_ref().is_some_and(|s| s.redact) {
                    // Redact mode: rewrite the emitted bytes (deterministic spans only). The emitted
                    // length may differ from the input frame; account for the bytes the client gets.
                    let out = Bytes::from(this.dlp.as_mut().unwrap().redact_frame(&data));
                    this.egress = this.egress.saturating_add(out.len());
                    this.push_meter(&out);
                    Poll::Ready(Some(Ok(Frame::data(out))))
                } else {
                    this.egress = this.egress.saturating_add(data.len());
                    this.push_meter(&data);
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
                            this.push_meter(&out);
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
                        this.push_meter(&out);
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
        let ingress = self.ingress.load(std::sync::atomic::Ordering::Relaxed);
        self.metrics.add_usage_bytes(ingress, self.egress);
        if let Some(ctx) = &self.ctx {
            if let Some(consumer) = ctx.consumer.get() {
                consumer.add_bytes(ingress, self.egress);
            }
            let line = ctx
                .pending
                .lock()
                .expect("request ctx mutex poisoned")
                .take();
            if let Some(mut line) = line {
                line.record.bytes_in = Some(ingress as u64);
                line.record.bytes_out = Some(self.egress as u64);
                write_access_line(&self.metrics, line);
            }
        }
        // LLM metering for the streamed body: the usage the stream reported. An OpenAI Chat client
        // gets usage only if it sent `stream_options.include_usage`; otherwise `no_usage`.
        if let Some(meter) = self.llm.as_mut() {
            let actual = match std::mem::take(&mut meter.usage).finish() {
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
/// Copy the client's end-to-end headers (the hop-by-hop ones already gone) onto the upstream
/// request: every value of every header, in order, but `Host`, which the upstream client sets.
/// A header sent twice is forwarded twice, as the client sent it. Several `Cookie` headers, which
/// is how an HTTP/2 client sends its cookies, become one joined with `"; "`, as RFC 9113 §8.2.3
/// asks of a hop to HTTP/1.1, where a client sends one.
///
/// Headers the edge sets itself afterwards (`X-Forwarded-For`, the request id, `traceparent`, an
/// `Authorization` from the key vault) are inserted over these, replacing every client value.
fn forward_headers(from: &HeaderMap, to: &mut HeaderMap) {
    for (name, value) in from.iter() {
        if name != header::HOST && name != header::COOKIE {
            to.append(name.clone(), value.clone());
        }
    }
    let cookies: Vec<&[u8]> = from
        .get_all(header::COOKIE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let joined = match cookies.as_slice() {
        [] => None,
        [one] => HeaderValue::from_bytes(one).ok(),
        many => HeaderValue::from_bytes(&many.join(&b"; "[..])).ok(),
    };
    if let Some(cookie) = joined {
        to.insert(header::COOKIE, cookie);
    }
}

/// Set the headers that tell the upstream who the client is, after [`forward_headers`] copied the
/// client's: every one of them is the edge's own, never what the client wrote. Frameworks read
/// different ones (Go's chi `RealIP` prefers `True-Client-IP` and `X-Real-IP`; RFC 7239 ones read
/// `Forwarded`), and a client value left in any of them would undo the edge's resolution.
///
/// * `X-Forwarded-For` and `X-Real-IP`: the resolved client address, one value.
/// * `X-Forwarded-Proto`: `proto`.
/// * `Forwarded`: replaced by `for=<ip>;proto=<proto>` (RFC 7239, an IPv6 address quoted and
///   bracketed). The client's, and any proxy's before the edge, are dropped: the edge has already
///   decided which of them to believe.
/// * `True-Client-IP`: removed (a CDN's header, which only the CDN should write).
/// * `X-Forwarded-Host`: `host`, the request's effective host ([`effective_host`], the one the
///   WAF checked), since the upstream request carries the upstream's own; removed when there is
///   none. A client's separate
///   `X-Forwarded-Host` never passes. `Host` itself is still the client's choice (the edge checks
///   no allowed-hosts list), so an app building links from it must validate the host. A CDN that
///   rewrites `Host` should forward the viewer's `Host` to the edge instead.
fn set_forwarding_headers(
    headers: &mut HeaderMap,
    ip: IpAddr,
    proto: &'static str,
    host: Option<&str>,
) {
    let ip_text = ip.to_string();
    if let Ok(v) = HeaderValue::from_str(&ip_text) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), v.clone());
        headers.insert(HeaderName::from_static("x-real-ip"), v);
    }
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(proto),
    );
    headers.remove(HeaderName::from_static("true-client-ip"));
    let node = match ip {
        IpAddr::V4(_) => ip_text,
        IpAddr::V6(_) => format!("\"[{ip_text}]\""),
    };
    match HeaderValue::from_str(&format!("for={node};proto={proto}")) {
        Ok(v) => {
            headers.insert(header::FORWARDED, v);
        }
        Err(_) => {
            headers.remove(header::FORWARDED);
        }
    }
    let host = host.and_then(|h| HeaderValue::from_str(h).ok());
    match host {
        Some(host) => {
            headers.insert(HeaderName::from_static("x-forwarded-host"), host);
        }
        None => {
            headers.remove(HeaderName::from_static("x-forwarded-host"));
        }
    }
}

/// The host a request is for, one rule for every protocol: the `Host` header as sent when there
/// is one (what 0.7.0's WAF saw), else the target's authority (an HTTP/2 `:authority` without a
/// `host` header) without the scheme's default port; `host[:port]`, never userinfo. An empty
/// `Host` or authority counts as none, and `None` comes back when there is neither. An error when
/// the target has an authority (an HTTP/2 `:authority`, an HTTP/1.1 absolute-form target, RFC
/// 9112 §3.2.2) that differs from `Host` (RFC 9113 §8.3.1 requires them to match), or `Host` is
/// sent twice or is not text.
pub(crate) fn effective_host(
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> Result<Option<String>, &'static str> {
    let mut lines = headers.get_all(header::HOST).iter();
    let header = match (lines.next(), lines.next()) {
        (None, _) => None,
        (Some(_), Some(_)) => return Err("Host sent more than once"),
        // `Host:` with nothing in it names no host (RFC 9112 §3.2 allows it only for a target
        // without an authority, which no request this proxy serves has).
        (Some(v), None) => {
            Some(v.to_str().map_err(|_| "Host is not text")?.trim()).filter(|h| !h.is_empty())
        }
    };
    let authority = uri
        .host()
        .filter(|h| !h.is_empty())
        .map(|h| match uri.port_u16() {
            Some(port) => format!("{h}:{port}"),
            None => h.to_string(),
        });
    // The scheme's default port written on one side and not the other is the same origin.
    let default_port = if uri.scheme_str() == Some("https") {
        ":443"
    } else {
        ":80"
    };
    let same = |a: &str, h: &str| {
        let bare = |s: &'_ str| {
            s.strip_suffix(default_port)
                .unwrap_or(s)
                .to_ascii_lowercase()
        };
        a.eq_ignore_ascii_case(h) || bare(a) == bare(h)
    };
    match (authority, header) {
        (Some(a), Some(h)) if !same(&a, h) => Err("the request target's authority and Host differ"),
        // Agreeing, or Host alone: Host as sent, the string 0.7.0's WAF and `X-Forwarded-Host`
        // had (`http://app.test:80/` with `Host: app.test` is `app.test`; with `Host:
        // app.test:80`, `app.test:80`).
        (_, Some(h)) => Ok(Some(h.to_string())),
        // An authority alone (HTTP/2 without a `host` header): without the scheme's default port.
        (Some(a), None) => Ok(Some(match a.strip_suffix(default_port) {
            Some(bare) => bare.to_string(),
            None => a,
        })),
        (None, None) => Ok(None),
    }
}

/// [`effective_host`], and an error for an HTTP/1.1 or HTTP/2 request with no host at all (they
/// require one). An HTTP/1.0 request may omit it, and comes back `None`.
fn request_host(
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    version: axum::http::Version,
) -> Result<Option<String>, &'static str> {
    match effective_host(headers, uri)? {
        None if version >= axum::http::Version::HTTP_11 => {
            Err("no host: no Host header and no authority in the target")
        }
        host => Ok(host),
    }
}

/// The request's effective host ([`request_host`]), decided once in `handle` and carried to the
/// forward paths.
#[derive(Clone)]
struct EffectiveHost(Option<String>);

/// What the WAF made of a request.
enum WafVerdict {
    Pass,
    Reported,
    Block,
}

/// The WAF on a request, counted and logged the same way on every path (the buffered request and
/// a WebSocket handshake): a hit is counted, logged, and in `block` mode answered by the caller
/// with `403` and the `forbidden` outcome. The WAF reads the request's effective host as its
/// `host:` line, in place of the raw `Host` header (an empty one when there is no host at all), so
/// a Host rule checks the very string `X-Forwarded-Host` carries, whatever the protocol.
#[allow(clippy::too_many_arguments)]
fn screen(
    waf: &WafEngine,
    m: &Metrics,
    raw_path: &str,
    headers: &HeaderMap,
    host: Option<&str>,
    body: &[u8],
    ip: IpAddr,
    path: &str,
) -> WafVerdict {
    let Some(hit) = waf.evaluate(raw_path, headers, Some(host.unwrap_or("")), body) else {
        return WafVerdict::Pass;
    };
    m.record_waf_hit(hit.class);
    match waf.mode() {
        WafMode::Block => {
            warn!(
                rule = %hit.rule_id,
                class = hit.class,
                location = hit.location,
                client_ip = %ip,
                path = %path,
                "WAF blocked request"
            );
            WafVerdict::Block
        }
        WafMode::Report => {
            warn!(
                rule = %hit.rule_id,
                class = hit.class,
                location = hit.location,
                client_ip = %ip,
                path = %path,
                "WAF rule matched (report-only)"
            );
            WafVerdict::Reported
        }
        // `evaluate` returns `None` when off.
        WafMode::Off => WafVerdict::Pass,
    }
}

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
/// hop is HTTPS. Otherwise, from a trusted hop (`trusted`: `trust_forwarded_for`, and the TCP peer
/// in `trusted_forwarders` when that is set) we preserve the proto the edge reported (falling back
/// to `http`); an untrusted client's `X-Forwarded-Proto` is never honored, mirroring the client-IP
/// trust model. Returns a `'static` token so the caller can build a `HeaderValue` without fallible
/// parsing.
fn forwarded_proto(cfg: &Config, trusted: bool, headers: &HeaderMap) -> &'static str {
    if cfg.tls.enabled {
        return "https";
    }
    if trusted {
        if let Some(value) = headers
            .get_all("x-forwarded-proto")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
        {
            // The last value: the one the nearest (trusted) proxy wrote. An appending proxy keeps
            // whatever the client sent on the left, as with `X-Forwarded-For`.
            match value.rsplit(',').next().map(str::trim) {
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
/// What sending a request to a route's targets came to.
struct Sent<'p> {
    /// The target that gave `result`: the last one tried.
    target: &'p crate::pool::Target,
    result: Result<
        Result<hyper::Response<hyper::body::Incoming>, hyper_util::client::legacy::Error>,
        tokio::time::error::Elapsed,
    >,
    /// That target's attempt, from sending to `result`.
    waited: Duration,
    /// The request counted in flight to that target, for a `least_conn` pool: to be held until
    /// the exchange (or the tunnel) is over.
    in_flight: Option<crate::pool::InFlight>,
}

/// Send `first` to `tries[0]`. When it cannot connect (refused, unreachable, a failed handshake),
/// nothing reached the upstream: count that against the target and send `again(next)` to the next
/// one, while there is one and `again` can build the request. Each attempt's passive health is
/// recorded here, and the per-upstream series of each abandoned one; the caller records the last,
/// with what it learns from the response. `path` is the redacted target, for the log.
async fn send_to_pool<'p>(
    state: &AppState,
    pool: &crate::pool::Pool,
    tries: &[&'p crate::pool::Target],
    first: Request<Body>,
    mut again: impl FnMut(&crate::pool::Target) -> Option<Request<Body>>,
    deadline: Option<tokio::time::Instant>,
    path: &str,
) -> Sent<'p> {
    let mut req = first;
    let mut i = 0;
    loop {
        let target = tries[i];
        // Dropped, and so no longer counted, if this attempt is abandoned for the next.
        let in_flight = pool.start(target);
        let sent = Instant::now();
        let result = within(deadline, state.client.request(req)).await;
        let waited = sent.elapsed();
        if let Ok(outcome) = &result {
            match outcome {
                Ok(resp) => pool.answered(target, resp.status().as_u16()),
                Err(e) => {
                    let class = UpstreamResult::classify(e);
                    if matches!(
                        class,
                        UpstreamResult::ConnectError | UpstreamResult::TlsError
                    ) {
                        let error = crate::upstream::error_chain(e);
                        pool.connect_failed(target, &error);
                        if let Some(next) = tries.get(i + 1) {
                            if let Some(r) = again(next) {
                                state.metrics.upstream_stats(&target.label).record(class);
                                warn!(
                                    error,
                                    upstream = %format!(
                                        "{}{path}",
                                        crate::redact::userinfo(&target.base)
                                    ),
                                    next = %next.label,
                                    "upstream unreachable; trying the next target"
                                );
                                req = r;
                                i += 1;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        return Sent {
            target,
            result,
            waited,
            in_flight,
        };
    }
}

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

/// What `finish()` decided about a request, carried back on the response.
///
/// Threading a span handle through `finish` would mean editing all 38 of its call sites, and the one
/// that gets missed is always the interesting one. `finish` is the single convergence point every
/// terminal path already goes through, so it stamps its verdict into the response extensions and
/// `handle()` — which is the only place that has both the request and the finished response —
/// builds the span. One producer, one consumer.
#[derive(Clone, Debug)]
struct FinishInfo {
    outcome: String,
    status: u16,
    elapsed: Duration,
    request_id: String,
    /// The sanitised request target, as logged.
    target: String,
    client_ip: IpAddr,
}

/// What the pipeline learns about a request on its way through, for the access line and the
/// per-consumer series `handle` writes once the response is known. Shared with a streamed
/// response's body, which writes the line when it ends.
#[derive(Default)]
pub(crate) struct RequestCtx {
    consumer: std::sync::OnceLock<Arc<crate::metrics::ConsumerStats>>,
    principal: std::sync::OnceLock<String>,
    /// The upstream it was forwarded to, as logged ([`upstream_for_log`]).
    upstream: std::sync::OnceLock<String>,
    upstream_ms: std::sync::OnceLock<u64>,
    /// How long the response waited on the upstream: its headers and, buffered, its body. Set
    /// only when the upstream answered; the rest of the time to headers is the edge's own.
    upstream_busy: std::sync::OnceLock<Duration>,
    /// Request and response bytes of a buffered proxied exchange.
    bytes: std::sync::OnceLock<(u64, u64)>,
    /// Set when the response body streams: that body writes the access line.
    streamed: std::sync::atomic::AtomicBool,
    /// The request counted in flight to its `least_conn` target, released with this context.
    in_flight: std::sync::OnceLock<crate::pool::InFlight>,
    pending: std::sync::Mutex<Option<AccessLine>>,
}

/// An access line waiting to be written, and when its request started.
pub(crate) struct AccessLine {
    started: Instant,
    record: crate::logship::AccessRecord,
}

/// Write one access line: to stdout, and to `[log.ship]` when configured. Shipping is a single
/// non-blocking `try_send` onto a bounded queue — it never awaits and never touches the network,
/// so a slow or absent collector costs dropped telemetry rather than request latency.
fn write_access_line(metrics: &Metrics, line: AccessLine) {
    let mut r = line.record;
    r.duration_ms = line.started.elapsed().as_millis() as u64;
    info!(
        request_id = %r.request_id,
        method = %r.method,
        path = %r.target,
        client_ip = %r.client_ip,
        status = r.status,
        outcome = %r.outcome,
        latency_ms = r.latency_ms,
        duration_ms = r.duration_ms,
        route = %r.route,
        principal = r.principal.as_deref(),
        user_agent = r.user_agent.as_deref(),
        upstream = r.upstream.as_deref(),
        upstream_ms = r.upstream_ms,
        bytes_in = r.bytes_in,
        bytes_out = r.bytes_out,
        tls_version = r.tls_version.as_deref(),
        client_cert = r.client_cert.as_deref(),
        "request"
    );
    if let Some(shipper) = metrics.log_shipper() {
        r.ts = rfc3339_now();
        r.edge_id = shipper.edge_id().to_string();
        shipper.record(r);
    }
}

/// An upstream base URL as the access log records it: `scheme://host:port`, without any userinfo
/// a configured URL might carry.
pub(crate) fn upstream_for_log(base: &str) -> String {
    match base.parse::<axum::http::Uri>() {
        Ok(uri) => {
            let scheme = uri.scheme_str().unwrap_or("http");
            let host = uri.host().unwrap_or_default();
            let port = uri
                .port_u16()
                .unwrap_or(if scheme == "https" { 443 } else { 80 });
            format!("{scheme}://{host}:{port}")
        }
        Err(_) => String::new(),
    }
}

/// RFC3339 UTC, to the second, without pulling in a date-time crate.
///
/// A collector needs to order records from many edges, and arrival order will not do it — batching
/// means a record can arrive seconds after one from another box that happened later. Second
/// resolution is enough for that: the access log already reports latency separately, and sub-second
/// ordering within one edge is what `request_id` is for.
fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339(secs)
}

/// The conversion itself, split out from [`rfc3339_now`] so it is testable against known
/// timestamps. A hand-rolled date conversion that is only ever called with "now" is a conversion
/// nobody has checked.
pub(crate) fn rfc3339(secs: i64) -> String {
    // Civil-time conversion from a Unix timestamp (days since epoch -> y/m/d), the standard
    // algorithm. Cheaper than a dependency for one format, and it has no local-timezone concept to
    // get wrong: this is UTC by construction.
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, mi, sec) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{sec:02}Z")
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
    // `method` is part of the tuple every call site passes; the access line `handle` writes takes
    // it from the request instead.
    let _ = method;
    let elapsed = started.elapsed();
    metrics.record_request(outcome);
    metrics.observe_latency(elapsed);
    // For `handle()`, which writes the access line and builds the server span from it. `path` is
    // already sanitised by `accesslog::sanitize_target` at the call sites, so credentials in the
    // query string never reach the line or the collector.
    let status = resp.status().as_u16();
    resp.extensions_mut().insert(FinishInfo {
        outcome: outcome.to_string(),
        status,
        elapsed,
        request_id: request_id.to_string(),
        target: path.to_string(),
        client_ip: ip,
    });
    // Managed mode: count every finished request (proxied or rejected) toward the usage delta, and
    // — when the edge denied it — the drainable `blocked` figure. Cheap (relaxed atomic adds) and
    // inert unless a control plane drains it for reporting.
    metrics.add_usage_request(outcome);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every feature that reads the whole response forces buffering on its own; with none of
    /// them, the switch decides.
    /// Every reader of the request body forces buffering on its own.
    #[test]
    fn the_logged_upstream_drops_userinfo_and_names_the_port() {
        assert_eq!(
            upstream_for_log("http://user:secret@api.internal:4000/base"),
            "http://api.internal:4000"
        );
        assert_eq!(
            upstream_for_log("https://api.example.com"),
            "https://api.example.com:443"
        );
        assert_eq!(upstream_for_log("http://[::1]"), "http://[::1]:80");
    }

    #[test]
    fn a_request_streams_only_when_nothing_reads_its_body() {
        assert!(streams_request(true, false, false, false));
        assert!(
            !streams_request(false, false, false, false),
            "off by default"
        );
        assert!(!streams_request(true, true, false, false), "WAF body rule");
        assert!(!streams_request(true, false, true, false), "inbound DLP");
        assert!(!streams_request(true, false, false, true), "LLM features");
    }

    #[test]
    fn a_response_streams_only_when_nothing_needs_the_whole_body() {
        assert!(streams_any_response(true, false, false, false));
        assert!(
            !streams_any_response(false, false, false, false),
            "off by default"
        );
        assert!(
            !streams_any_response(true, true, false, false),
            "LLM metering"
        );
        assert!(
            !streams_any_response(true, false, true, false),
            "reversible DLP"
        );
        assert!(
            !streams_any_response(true, false, false, true),
            "outbound DLP"
        );
    }

    fn headers_with(name: &'static str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn rfc3339_matches_known_timestamps() {
        // A hand-rolled civil-time conversion is exactly the kind of code that is subtly wrong for
        // years because it is only ever called with "now" and nobody checks the answer.
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1), "1970-01-01T00:00:01Z");
        // A leap day, and the year-2000 leap (divisible by 400, so it IS a leap year — the case
        // the naive every-four-years rule gets right and the every-century rule gets wrong).
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        // 2100 is NOT a leap year (divisible by 100, not by 400).
        assert_eq!(rfc3339(4_107_542_400), "2100-03-01T00:00:00Z");
        assert_eq!(rfc3339(1_234_567_890), "2009-02-13T23:31:30Z");
        // End of a day, and the first second of the next.
        assert_eq!(rfc3339(1_767_225_599), "2025-12-31T23:59:59Z");
        assert_eq!(rfc3339(1_767_225_600), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_is_always_a_fixed_width_sortable_string() {
        // A collector orders records lexically. Any field that is not zero-padded sorts wrongly the
        // moment it crosses a digit boundary, which would show up as records interleaving on the
        // 10th of a month and not before.
        for t in [
            0i64,
            1,
            951_782_400,
            1_234_567_890,
            1_767_225_600,
            4_107_542_400,
        ] {
            let s = rfc3339(t);
            assert_eq!(s.len(), 20, "{s}");
            assert!(s.ends_with('Z'), "{s}");
        }
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
        assert_eq!(client_ip(&h, peer, false, 1), (peer.ip(), None));
        // An IPv4 client on a dual-stack socket is keyed as the IPv4 address, trusted or not.
        let mapped: SocketAddr = "[::ffff:203.0.113.9]:55000".parse().unwrap();
        assert_eq!(client_ip(&h, mapped, false, 1).0, peer.ip());
        assert_eq!(client_ip(&HeaderMap::new(), mapped, true, 1).0, peer.ip());
    }

    #[test]
    fn client_ip_walks_no_further_than_the_chosen_entry() {
        let peer: SocketAddr = "10.0.0.5:55000".parse().unwrap();
        // A client can send thousands of entries; only `hops` from the right are looked at.
        let long = format!("{}198.51.100.7", "1.2.3.4, ".repeat(5000));
        assert_eq!(
            client_ip(&xff(&[&long]), peer, true, 1).0.to_string(),
            "198.51.100.7"
        );
        // Out-of-range hop counts are clamped (the runtime build refuses them anyway).
        assert_eq!(
            client_ip(&xff(&["1.2.3.4, 198.51.100.7"]), peer, true, 0)
                .0
                .to_string(),
            "198.51.100.7"
        );
    }

    #[test]
    fn one_effective_host_per_request() {
        use axum::http::{Uri, Version};
        let host = |h: &[&str], uri: &str, v: Version| {
            let mut headers = HeaderMap::new();
            for v in h {
                headers.append(header::HOST, HeaderValue::from_str(v).unwrap());
            }
            request_host(&headers, &uri.parse::<Uri>().unwrap(), v)
        };
        let ok = |s: &str| Ok(Some(s.to_string()));
        // HTTP/2: `:authority` is the URI's, with no Host header.
        assert_eq!(
            host(&[], "http://app.test/", Version::HTTP_2),
            ok("app.test")
        );
        assert_eq!(
            host(&[], "http://app.test:8080/x", Version::HTTP_2),
            ok("app.test:8080")
        );
        // Both, agreeing: Host as sent, the string 0.7.0 saw.
        assert_eq!(
            host(&["APP.test"], "http://app.test/", Version::HTTP_2),
            ok("APP.test")
        );
        assert!(host(&["evil.test"], "http://app.test/", Version::HTTP_2).is_err());
        // The scheme's default port on one side only: the same origin, named as Host names it.
        assert_eq!(
            host(&["app.test"], "http://app.test:80/", Version::HTTP_11),
            ok("app.test")
        );
        assert_eq!(
            host(&["app.test:80"], "http://app.test/", Version::HTTP_11),
            ok("app.test:80")
        );
        assert_eq!(
            host(&["app.test:443"], "https://app.test/", Version::HTTP_2),
            ok("app.test:443")
        );
        assert_eq!(
            host(&["[::1]"], "http://[::1]:80/", Version::HTTP_11),
            ok("[::1]")
        );
        // An authority alone: without the scheme's default port.
        assert_eq!(
            host(&[], "https://app.test:443/", Version::HTTP_2),
            ok("app.test")
        );
        assert_eq!(host(&[], "http://[::1]:80/", Version::HTTP_2), ok("[::1]"));
        // Another scheme's default port is a port.
        assert_eq!(
            host(&[], "https://app.test:80/", Version::HTTP_2),
            ok("app.test:80")
        );
        // An empty or blank Host names no host: refused over HTTP/1.1 and HTTP/2, none over
        // HTTP/1.0; with an authority, the authority.
        for blank in ["", "   "] {
            assert!(host(&[blank], "/", Version::HTTP_11).is_err(), "{blank:?}");
            assert!(host(&[blank], "/", Version::HTTP_2).is_err(), "{blank:?}");
            assert_eq!(host(&[blank], "/", Version::HTTP_10), Ok(None), "{blank:?}");
            assert_eq!(
                host(&[blank], "http://app.test/", Version::HTTP_2),
                ok("app.test")
            );
        }
        assert!(host(&["app.test:8080"], "http://app.test/", Version::HTTP_2).is_err());
        assert!(host(&[], "/", Version::HTTP_2).is_err(), "no :authority");
        // HTTP/1.1 origin-form and absolute-form (userinfo never part of the host).
        assert_eq!(host(&["app.test"], "/", Version::HTTP_11), ok("app.test"));
        assert_eq!(
            host(&[], "http://u:p@app.test/", Version::HTTP_11),
            ok("app.test")
        );
        assert!(host(&["app.test"], "http://evil.test/", Version::HTTP_11).is_err());
        assert!(
            host(&["a.test", "a.test"], "/", Version::HTTP_11).is_err(),
            "twice"
        );
        assert!(host(&[], "/", Version::HTTP_11).is_err(), "required");
        // HTTP/1.0 may omit it.
        assert_eq!(host(&[], "/", Version::HTTP_10), Ok(None));
        // IPv6.
        assert_eq!(
            host(&["[::1]:8080"], "/", Version::HTTP_11),
            ok("[::1]:8080")
        );
        assert_eq!(
            host(&[], "http://[::1]:8080/", Version::HTTP_2),
            ok("[::1]:8080")
        );
    }

    #[test]
    fn the_upstream_gets_the_edges_client_headers_not_the_clients() {
        let mut inbound = HeaderMap::new();
        for (k, v) in [
            ("host", "shop.example"),
            ("x-real-ip", "1.2.3.4"),
            ("true-client-ip", "1.2.3.4"),
            ("forwarded", "for=1.2.3.4;proto=https"),
            ("x-forwarded-host", "evil.example"),
        ] {
            inbound.append(k, HeaderValue::from_static(v));
        }
        let mut out = HeaderMap::new();
        forward_headers(&inbound, &mut out);
        let uri: axum::http::Uri = "/reset".parse().unwrap();
        set_forwarding_headers(
            &mut out,
            "198.51.100.7".parse().unwrap(),
            "https",
            effective_host(&inbound, &uri).unwrap().as_deref(),
        );
        let one = |name: &str| {
            let all: Vec<_> = out.get_all(name).iter().collect();
            assert!(all.len() <= 1, "{name}: {all:?}");
            all.first().map(|v| v.to_str().unwrap().to_string())
        };
        assert_eq!(one("x-forwarded-for").as_deref(), Some("198.51.100.7"));
        assert_eq!(one("x-real-ip").as_deref(), Some("198.51.100.7"));
        assert_eq!(one("true-client-ip"), None);
        assert_eq!(
            one("forwarded").as_deref(),
            Some("for=198.51.100.7;proto=https")
        );
        assert_eq!(one("x-forwarded-host").as_deref(), Some("shop.example"));
        assert_eq!(one("x-forwarded-proto").as_deref(), Some("https"));

        // IPv6, quoted and bracketed (RFC 7239 §6); an HTTP/2 request's authority as the host.
        let mut out = HeaderMap::new();
        let uri: axum::http::Uri = "https://shop.example:8443/reset".parse().unwrap();
        set_forwarding_headers(
            &mut out,
            "2001:db8::7".parse().unwrap(),
            "http",
            effective_host(&HeaderMap::new(), &uri).unwrap().as_deref(),
        );
        assert_eq!(out["forwarded"], "for=\"[2001:db8::7]\";proto=http");
        assert_eq!(out["x-forwarded-host"], "shop.example:8443");
        // No host at all: the client's X-Forwarded-Host is not left behind.
        let mut out = HeaderMap::new();
        out.insert("x-forwarded-host", HeaderValue::from_static("evil.example"));
        set_forwarding_headers(&mut out, "198.51.100.7".parse().unwrap(), "http", None);
        assert!(!out.contains_key("x-forwarded-host"));
    }

    /// A header map with one `X-Forwarded-For` line per value, in order.
    fn xff(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn client_ip_takes_the_entry_the_trusted_proxy_appended_not_the_clients() {
        let peer: SocketAddr = "10.0.0.5:55000".parse().unwrap();
        let ip = |values: &[&str], hops| client_ip(&xff(values), peer, true, hops);
        // A client writes `1.2.3.4`; the balancer appends the address it saw, `198.51.100.7`.
        assert_eq!(
            ip(&["1.2.3.4, 198.51.100.7"], 1),
            ("198.51.100.7".parse().unwrap(), Some(ForwardedFor::Used))
        );
        // A one-entry header (a proxy that overwrites) gives the same answer as before.
        assert_eq!(ip(&["198.51.100.7"], 1).0.to_string(), "198.51.100.7");
        // Two proxies (CloudFront → ALB): the client is two from the right.
        assert_eq!(
            ip(&["1.2.3.4, 198.51.100.7, 130.176.0.1"], 2).0.to_string(),
            "198.51.100.7"
        );
        // Several header lines are one list, in order.
        assert_eq!(
            ip(&["1.2.3.4", "198.51.100.7"], 1).0.to_string(),
            "198.51.100.7"
        );
        assert_eq!(
            ip(&["1.2.3.4, 198.51.100.7", "130.176.0.1"], 2)
                .0
                .to_string(),
            "198.51.100.7"
        );
        // Spaces, empty entries, ports and brackets.
        assert_eq!(
            ip(&[" 1.2.3.4 ,, 198.51.100.7:4711 "], 1).0.to_string(),
            "198.51.100.7"
        );
        assert_eq!(
            ip(&["1.2.3.4, 2001:db8::7"], 1).0.to_string(),
            "2001:db8::7"
        );
        assert_eq!(
            ip(&["1.2.3.4, [2001:db8::7]"], 1).0.to_string(),
            "2001:db8::7"
        );
        assert_eq!(
            ip(&["1.2.3.4, [2001:db8::7]:4711"], 1).0.to_string(),
            "2001:db8::7"
        );
        assert_eq!(
            ip(&["::ffff:198.51.100.7"], 1).0.to_string(),
            "198.51.100.7"
        );
    }

    #[test]
    fn client_ip_falls_back_to_the_peer_and_says_why() {
        let peer: SocketAddr = "10.0.0.5:55000".parse().unwrap();
        let ip = |values: &[&str], hops| client_ip(&xff(values), peer, true, hops);
        assert_eq!(ip(&[], 1), (peer.ip(), Some(ForwardedFor::Absent)));
        assert_eq!(
            ip(&["198.51.100.7"], 2),
            (peer.ip(), Some(ForwardedFor::Short))
        );
        assert_eq!(ip(&[" , "], 1), (peer.ip(), Some(ForwardedFor::Short)));
        // The chosen entry does not parse: never walk on to another one.
        assert_eq!(
            ip(&["198.51.100.7, unknown"], 1),
            (peer.ip(), Some(ForwardedFor::Invalid))
        );
        assert_eq!(
            ip(&["198.51.100.7, 1.2.3.4.5"], 1),
            (peer.ip(), Some(ForwardedFor::Invalid))
        );
        // A bad entry further left is the client's, and does not matter.
        assert_eq!(
            ip(&["garbage, 198.51.100.7"], 1),
            ("198.51.100.7".parse().unwrap(), Some(ForwardedFor::Used))
        );
        // Bytes that are not text: in the chosen entry, the peer; on the left, where the client
        // writes, they do not matter (or any client could make itself the balancer).
        let raw = |lines: &[&[u8]]| {
            let mut h = HeaderMap::new();
            for line in lines {
                h.append("x-forwarded-for", HeaderValue::from_bytes(line).unwrap());
            }
            client_ip(&h, peer, true, 1)
        };
        assert_eq!(
            raw(&[&b"198.51.100.7\xff"[..]]),
            (peer.ip(), Some(ForwardedFor::Invalid))
        );
        assert_eq!(
            raw(&[&b"1.2.3.4, 198.51.100.7\xff"[..]]),
            (peer.ip(), Some(ForwardedFor::Invalid))
        );
        assert_eq!(
            raw(&[&b"\xff\xfe garbage, 198.51.100.7"[..]]),
            ("198.51.100.7".parse().unwrap(), Some(ForwardedFor::Used))
        );
        assert_eq!(
            raw(&[&b"\xffclient-written"[..], &b"198.51.100.7"[..]]),
            ("198.51.100.7".parse().unwrap(), Some(ForwardedFor::Used)),
            "a whole line of it, in its own header line"
        );
    }

    #[test]
    fn header_bytes_sums_names_and_values() {
        let mut h = HeaderMap::new();
        h.insert("a", HeaderValue::from_static("bb")); // 1 + 2
        h.insert("ccc", HeaderValue::from_static("dddd")); // 3 + 4
        assert_eq!(header_bytes(&h), 1 + 2 + 3 + 4);
    }

    #[test]
    fn every_value_of_a_repeated_header_is_forwarded_and_cookies_become_one() {
        let mut from = HeaderMap::new();
        from.insert(header::HOST, HeaderValue::from_static("edge.example"));
        from.append("x-multi", HeaderValue::from_static("1"));
        from.append("x-multi", HeaderValue::from_static("2"));
        from.append(header::ACCEPT, HeaderValue::from_static("text/html"));
        from.append(header::COOKIE, HeaderValue::from_static("a=1"));
        from.append(header::COOKIE, HeaderValue::from_static("b=2; c=3"));
        from.append(header::COOKIE, HeaderValue::from_bytes(b"d=\xe9").unwrap());
        let mut to = HeaderMap::new();
        forward_headers(&from, &mut to);
        let all = |name: &str| -> Vec<&[u8]> {
            to.get_all(name).iter().map(HeaderValue::as_bytes).collect()
        };
        assert_eq!(all("x-multi"), [b"1", b"2"], "both, in order");
        assert_eq!(all("accept"), [b"text/html"]);
        assert_eq!(
            all("cookie"),
            [&b"a=1; b=2; c=3; d=\xe9"[..]],
            "one, bytes kept"
        );
        assert!(
            to.get(header::HOST).is_none(),
            "the upstream client sets Host"
        );
        // One Cookie header goes as it came.
        let mut one = HeaderMap::new();
        one.insert(header::COOKIE, HeaderValue::from_static("a=1;b=2"));
        let mut to = HeaderMap::new();
        forward_headers(&one, &mut to);
        assert_eq!(to[header::COOKIE], "a=1;b=2");
        let mut to = HeaderMap::new();
        forward_headers(&HeaderMap::new(), &mut to);
        assert!(to.is_empty());
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

    fn forwarders(trust: bool, hops: crate::config::ForwardedHops, list: &[&str]) -> Forwarders {
        Forwarders::from_cfg(&crate::config::ServerCfg {
            trust_forwarded_for: trust,
            forwarded_hops: hops,
            trusted_forwarders: list.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        })
        .unwrap()
    }

    fn forwarders_err(trust: bool, hops: crate::config::ForwardedHops, list: &[&str]) -> String {
        let e = Forwarders::from_cfg(&crate::config::ServerCfg {
            trust_forwarded_for: trust,
            forwarded_hops: hops,
            trusted_forwarders: list.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        })
        .unwrap_err();
        format!("{e:#}")
    }

    #[test]
    fn trusted_forwarders_parse_and_refuse_what_would_trust_anyone_or_do_nothing() {
        use crate::config::ForwardedHops::{Auto, Count};
        let f = forwarders(
            true,
            Count(1),
            &["10.0.0.0/20", "192.0.2.7", "2001:db8::/32"],
        );
        assert!(f.listed("10.0.15.255".parse().unwrap()));
        assert!(!f.listed("10.0.16.0".parse().unwrap()));
        assert!(f.listed("192.0.2.7".parse().unwrap()));
        assert!(f.listed("2001:db8::1".parse().unwrap()));
        // An IPv4 peer on a dual-stack socket matches its IPv4 entry.
        assert!(f.listed("::ffff:10.0.1.5".parse().unwrap()));
        for everything in ["0.0.0.0/0", "::/0"] {
            let e = forwarders_err(true, Count(1), &["10.0.0.0/8", everything]);
            assert!(e.contains("every address"), "{e}");
        }
        assert!(forwarders_err(true, Count(1), &["10.0.0.300"]).contains("trusted_forwarders"));
        assert!(
            forwarders_err(false, Count(1), &["10.0.0.0/8"]).contains("trust_forwarded_for is off")
        );
        assert!(forwarders_err(true, Auto, &[]).contains("\"auto\""));
        assert!(forwarders_err(true, Count(0), &[]).contains("server.forwarded_hops = 0"));
        assert!(forwarders(true, Count(1), &[]).trusts_any_peer());
        assert!(!forwarders(true, Count(1), &["10.0.0.0/8"]).trusts_any_peer());
        assert!(!forwarders(false, Count(1), &[]).trusts_any_peer());
    }

    #[test]
    fn from_an_unlisted_peer_the_headers_are_ignored_and_counted() {
        use crate::config::ForwardedHops::Count;
        let f = forwarders(true, Count(1), &["10.0.0.0/20"]);
        let peer: SocketAddr = "10.9.0.7:5000".parse().unwrap();
        let xff = headers_with("x-forwarded-for", "1.2.3.4");
        assert!(!f.believes(peer.ip()));
        assert_eq!(
            f.resolve(&xff, peer, peer.ip()),
            (peer.ip(), Some(ForwardedFor::UntrustedPeer))
        );
        assert_eq!(
            f.resolve(&HeaderMap::new(), peer, peer.ip()),
            (peer.ip(), Some(ForwardedFor::Absent))
        );
        // The list is matched against the TCP peer, never the client a PROXY header named.
        let named: SocketAddr = "10.0.1.5:5000".parse().unwrap();
        assert_eq!(
            f.resolve(&xff, named, peer.ip()),
            (named.ip(), Some(ForwardedFor::UntrustedPeer))
        );
        // A listed peer: main's hop counting, unchanged.
        let alb: IpAddr = "10.0.1.5".parse().unwrap();
        assert!(f.believes(alb));
        assert_eq!(
            f.resolve(
                &headers_with("x-forwarded-for", "6.6.6.6, 1.2.3.4"),
                peer,
                alb
            ),
            ("1.2.3.4".parse().unwrap(), Some(ForwardedFor::Used))
        );
        // Off: nothing is read or counted.
        let off = forwarders(false, Count(1), &[]);
        assert_eq!(off.resolve(&xff, peer, alb), (peer.ip(), None));
        assert!(!off.believes(alb));
        // An empty list believes everyone, as 0.7 did.
        assert!(forwarders(true, Count(1), &[]).believes(peer.ip()));
    }

    #[test]
    fn auto_walks_past_the_listed_proxies_to_the_first_entry_that_is_not() {
        use crate::config::ForwardedHops::Auto;
        let f = forwarders(true, Auto, &["10.0.0.0/20", "198.51.100.0/24"]);
        let alb: IpAddr = "10.0.1.5".parse().unwrap();
        let peer = SocketAddr::new(alb, 5000);
        let walk = |lines: &[&str]| {
            let mut h = HeaderMap::new();
            for l in lines {
                h.append("x-forwarded-for", HeaderValue::from_str(l).unwrap());
            }
            f.resolve(&h, peer, alb)
        };
        let used = |ip: &str| (ip.parse::<IpAddr>().unwrap(), Some(ForwardedFor::Used));
        // One trusted hop (the CDN's entry), then the client.
        assert_eq!(walk(&["203.0.113.9, 198.51.100.4"]), used("203.0.113.9"));
        // No CDN in front: the client directly.
        assert_eq!(walk(&["203.0.113.9"]), used("203.0.113.9"));
        // Two trusted, over two lines; a client-prepended entry further left is not believed.
        assert_eq!(
            walk(&["6.6.6.6, 203.0.113.9", "198.51.100.4, 10.0.2.1"]),
            used("203.0.113.9")
        );
        // Every entry trusted: the leftmost.
        assert_eq!(walk(&["10.0.2.1, 198.51.100.4"]), used("10.0.2.1"));
        // Garbage the client wrote further left is never parsed, so it cannot force the fallback.
        assert_eq!(
            walk(&["garbage, 203.0.113.9, 198.51.100.4"]),
            used("203.0.113.9")
        );
        // A bad entry among those walked over is invalid: the peer.
        assert_eq!(
            walk(&["203.0.113.9, nope"]),
            (alb, Some(ForwardedFor::Invalid))
        );
        assert_eq!(walk(&[" , "]), (alb, Some(ForwardedFor::Short)));
        assert_eq!(walk(&[]), (alb, Some(ForwardedFor::Absent)));
        // At most 32 entries are walked: exactly that many trusted is the leftmost, one more is
        // invalid, however short the rest.
        let trusted = vec!["198.51.100.1"; MAX_FORWARDED_WALK].join(", ");
        assert_eq!(walk(&[&trusted]), used("198.51.100.1"));
        assert_eq!(
            walk(&[&format!("203.0.113.9, {trusted}")]),
            (alb, Some(ForwardedFor::Invalid))
        );
        // Ports and brackets, as with a count.
        assert_eq!(
            walk(&["[2001:db8::9]:443, 198.51.100.4:80"]),
            used("2001:db8::9")
        );
    }

    #[test]
    fn forwarded_proto_reflects_tls_and_trust() {
        let mut cfg = Config::default();

        // We terminate TLS -> always https, regardless of any incoming header.
        cfg.tls.enabled = true;
        assert_eq!(
            forwarded_proto(&cfg, true, &headers_with("x-forwarded-proto", "http")),
            "https"
        );

        // Plain HTTP from an untrusted hop: http, and an incoming XFP is NOT trusted.
        cfg.tls.enabled = false;
        assert_eq!(
            forwarded_proto(&cfg, false, &headers_with("x-forwarded-proto", "https")),
            "http"
        );

        // Plain HTTP from a trusted hop: preserve the edge's reported proto.
        assert_eq!(
            forwarded_proto(&cfg, true, &headers_with("x-forwarded-proto", "https")),
            "https"
        );
        // The last value is the nearest proxy's; the first may be the client's own.
        assert_eq!(
            forwarded_proto(
                &cfg,
                true,
                &headers_with("x-forwarded-proto", "http, https")
            ),
            "https"
        );
        assert_eq!(
            forwarded_proto(
                &cfg,
                true,
                &headers_with("x-forwarded-proto", "https, http")
            ),
            "http"
        );
        // Over several header lines, the last line's last value.
        let mut lines = HeaderMap::new();
        lines.append("x-forwarded-proto", HeaderValue::from_static("http"));
        lines.append("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(forwarded_proto(&cfg, true, &lines), "https");
        let mut lines = HeaderMap::new();
        lines.append("x-forwarded-proto", HeaderValue::from_static("https"));
        lines.append(
            "x-forwarded-proto",
            HeaderValue::from_static("garbage, http"),
        );
        assert_eq!(forwarded_proto(&cfg, true, &lines), "http");
        // Missing or unrecognized -> http.
        assert_eq!(forwarded_proto(&cfg, true, &HeaderMap::new()), "http");
        assert_eq!(
            forwarded_proto(&cfg, true, &headers_with("x-forwarded-proto", "garbage")),
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
        // path for a JS-readable double-submit CSRF cookie (e.g. app_csrf).
        let out = harden_cookie("app_csrf=tok", false);
        assert!(out.contains("; Secure"), "{out}");
        assert!(out.contains("; SameSite=Lax"), "{out}");
        assert!(!out.to_ascii_lowercase().contains("httponly"), "{out}");
    }

    #[test]
    fn cookie_name_exempt_matches_by_name_only() {
        let exempt = vec!["app_csrf".to_string()];
        assert!(cookie_name_exempt("app_csrf=abc; Path=/; Secure", &exempt));
        // a different cookie is not exempt; the value never triggers a match
        assert!(!cookie_name_exempt("app_auth=app_csrf; Path=/", &exempt));
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
