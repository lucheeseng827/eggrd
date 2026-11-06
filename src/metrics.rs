//! Prometheus metrics, hand-rolled.
//!
//! A full metrics library (`prometheus`, `metrics`) would be a heavy dependency for the
//! handful of series EdgeGuard exposes, so — in the same spirit as `parse_host_port` being a
//! small URL parser rather than a full one — this is a minimal text-exposition renderer over
//! a few atomics. It emits the Prometheus text format (v0.0.4) at `/__edgeguard/metrics`.
//!
//! The registry lives in [`crate::proxy::AppState`] *outside* the hot-swappable runtime, so
//! counters survive a config hot-reload instead of resetting to zero.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::upstream::UpstreamResult;

/// Request `outcome` label values. These mirror the `outcome` field already emitted on the
/// JSON access log in [`crate::proxy`], so a metric series lines up 1:1 with a log line.
/// Anything not in this list is bucketed under `other` rather than silently dropped.
const OUTCOMES: &[&str] = &[
    "ok",
    "rate_limited",
    "over_quota",
    "over_budget",
    "unpriced_model",
    "limiter_error",
    "unauthorized",
    "forbidden",
    "method_not_allowed",
    "not_found",
    "payload_too_large",
    "header_too_large",
    "bad_gateway",
    "upstream_error",
    "upstream_timeout",
    "upstream_body_too_large",
    "upstream_body_error",
    "no_policy",
    "bad_request",
    "other",
];

/// Outcomes where the edge itself *denied* the request by policy — auth, WAF-forbidden, rate limit,
/// quota, hard budget, or an unpriced LLM model. Distinct from protocol/upstream failures
/// (`not_found`, `bad_gateway`, `upstream_*`), which aren't "blocked by eggrd". Feeds the managed-mode
/// usage report's `blocked` figure.
fn outcome_is_blocked(outcome: &str) -> bool {
    matches!(
        outcome,
        "rate_limited"
            | "over_quota"
            | "over_budget"
            | "unpriced_model"
            | "unauthorized"
            | "forbidden"
    )
}

/// Rate-limit `scope` label values (which limiter rejected the request).
const RL_SCOPES: &[&str] = &["ip", "route", "key"];

/// WAF `rule` label values (which ruleset class matched). Custom `[[waf.rules]]` all roll up
/// under `custom`; the specific rule id is in the log line, not the metric.
const WAF_RULES: &[&str] = &["sqli", "xss", "path_traversal", "custom"];

/// Upper bounds (seconds) for the request-duration histogram, plus an implicit `+Inf`.
const LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Buckets for `edgeguard_edge_overhead_seconds`. What the edge adds is normally well under a
/// millisecond, below request latency's first bucket, so these start at 100 µs.
const OVERHEAD_BUCKETS: &[f64] = &[
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0,
];

/// The `route` label of a request no configured route matched.
pub const DEFAULT_ROUTE: &str = "default";

/// Per-route `method` label values. Anything else, extension methods included, is `OTHER`: the
/// method is the client's to choose, so it cannot be a label value as sent.
const ROUTE_METHODS: [&str; 8] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "OTHER",
];

/// `status_class` label values.
const STATUS_CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];

fn status_class(status: u16) -> usize {
    usize::from((status / 100).clamp(1, 5)) - 1
}

/// The `consumer` label of a request with no authenticated principal.
pub const ANON_CONSUMER: &str = "_anon";

/// `metrics.consumer_series_max` when it is not set.
pub const DEFAULT_CONSUMER_SERIES: usize = 100;

/// One route's requests by method and status class, and its latency histogram. Atomics only, so
/// recording a request takes no lock.
#[derive(Debug)]
pub struct RouteStats {
    /// `[method * STATUS_CLASSES.len() + status_class]`.
    requests: [AtomicU64; ROUTE_METHODS.len() * STATUS_CLASSES.len()],
    buckets: Vec<AtomicU64>,
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Default for RouteStats {
    fn default() -> Self {
        RouteStats {
            requests: std::array::from_fn(|_| AtomicU64::new(0)),
            buckets: LATENCY_BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl RouteStats {
    /// Count one request on this route: its method, the status the client got, and the time to
    /// its response headers.
    pub fn record(&self, method: &str, status: u16, elapsed: Duration) {
        let m = ROUTE_METHODS
            .iter()
            .position(|known| *known == method)
            .unwrap_or(ROUTE_METHODS.len() - 1);
        self.requests[m * STATUS_CLASSES.len() + status_class(status)]
            .fetch_add(1, Ordering::Relaxed);
        observe_hist(&self.buckets, &self.sum_micros, &self.count, elapsed);
    }
}

/// One upstream's exchanges by how they ended, and the time to its response headers. Atomics only,
/// like [`RouteStats`].
#[derive(Debug)]
pub struct UpstreamStats {
    /// By [`UpstreamResult::ALL`] order.
    results: [AtomicU64; UpstreamResult::ALL.len()],
    buckets: Vec<AtomicU64>,
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Default for UpstreamStats {
    fn default() -> Self {
        UpstreamStats {
            results: std::array::from_fn(|_| AtomicU64::new(0)),
            buckets: LATENCY_BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl UpstreamStats {
    /// Count one exchange, once, when it has ended as far as the edge waited for it.
    pub fn record(&self, result: UpstreamResult) {
        let i = UpstreamResult::ALL
            .iter()
            .position(|r| *r == result)
            .expect("every result is in ALL");
        self.results[i].fetch_add(1, Ordering::Relaxed);
    }

    /// The time from sending the request to the upstream's response headers. Only exchanges that
    /// got headers are timed: a refusal would sit at zero and a timeout at the deadline, and
    /// either would say nothing about how fast the upstream answers.
    pub fn observe_headers(&self, elapsed: Duration) {
        observe_hist(&self.buckets, &self.sum_micros, &self.count, elapsed);
    }
}

/// One consumer's requests by status class, and the bytes it sent and received.
#[derive(Debug, Default)]
pub struct ConsumerStats {
    requests: [AtomicU64; 5],
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl ConsumerStats {
    pub fn record(&self, status: u16) {
        self.requests[status_class(status)].fetch_add(1, Ordering::Relaxed);
    }

    /// Request bytes received from the consumer and response bytes sent to it.
    pub fn add_bytes(&self, ingress: usize, egress: usize) {
        self.bytes_in.fetch_add(ingress as u64, Ordering::Relaxed);
        self.bytes_out.fetch_add(egress as u64, Ordering::Relaxed);
    }
}

/// LLM metering `result` label values (per [`crate::llm`]): a request whose response carried usage
/// for a priced model (`metered`), for an unpriced model (`unpriced`, tokens counted but no cost),
/// or that reported no usage at all (`no_usage`, e.g. an error or a stream without `include_usage`).
const LLM_RESULTS: &[&str] = &["metered", "unpriced", "no_usage"];

/// Per-model token `kind` label values on `edgeguard_llm_model_tokens_total`. `input`/`output` are
/// the prompt/completion totals; `cached` and `reasoning` are the sub-dimensions (⊆ input / ⊆ output)
/// that providers bill differently — surfaced separately so the "~7× undercount" is visible.
const LLM_TOKEN_KINDS: &[&str] = &["input", "output", "cached", "reasoning"];

/// Budget `scope` label values (which budget dimension blocked / was consumed). Mirrors
/// [`crate::budget::BudgetScope`]; a scope not in this list is bucketed under `other`.
const BUDGET_SCOPES: &[&str] = &["global", "key", "model", "team", "claim", "other"];

/// Cap on the number of distinct `model` label values tracked for the per-model token/cost series.
/// Clients can send an arbitrary `model` string, so the map is bounded to keep Prometheus cardinality
/// flat; once full, further models fold into the `_over_cap` bucket rather than growing without limit.
const MAX_LLM_MODEL_SERIES: usize = 128;

/// The overflow bucket a new model folds into once [`MAX_LLM_MODEL_SERIES`] distinct models are seen.
const LLM_MODEL_OVERFLOW: &str = "_over_cap";

/// Key-vault (gateway L2) `result` label values: a request whose virtual key resolved and was
/// swapped for the provider key (`swapped`), rejected because the virtual key was unknown
/// (`denied_key`), or rejected because the requested model was off the key's egress allowlist
/// (`denied_model`).
const KEYVAULT_RESULTS: &[&str] = &["swapped", "denied_key", "denied_model"];

/// DLP (gateway L3) finding categories — the `category` label on `edgeguard_llm_dlp_findings_total`.
/// Mirrors [`crate::dlp::CATEGORIES`]; kept here to avoid a cross-module compile dependency in the
/// hot render path. A category not in this list is bucketed under `other`.
const DLP_CATEGORIES: &[&str] = &[
    "email",
    "credit_card",
    "aws_key",
    "api_key",
    "private_key",
    "ssn",
    "phone",
    "iban",
    "high_entropy",
    "gazetteer",
    "person",
    "address",
    "org",
    "prompt_injection",
    "custom",
    "other",
];

/// A drained snapshot of the managed-mode usage accumulators (requests + bandwidth + LLM
/// tokens/cost). Returned by [`Metrics::drain_usage`] and re-applied by [`Metrics::restore_usage`]
/// if the report fails to send.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DrainedUsage {
    pub requests: u64,
    pub ingress_bytes: u64,
    pub egress_bytes: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_micros: u64,
    /// Requests the edge denied since the last drain (a subset of `requests`).
    pub blocked: u64,
    /// WAF matches since the last drain, by rule class (indices parallel to [`WAF_RULES`] =
    /// `[sqli, xss, path_traversal, custom]`). Reported to the control plane for the console's
    /// per-category security breakdown.
    pub waf_sqli: u64,
    pub waf_xss: u64,
    pub waf_path_traversal: u64,
    pub waf_custom: u64,
}

impl DrainedUsage {
    /// True when nothing accrued — the reporter skips an empty report.
    pub fn is_empty(&self) -> bool {
        *self == DrainedUsage::default()
    }
}

/// One metered LLM request's token/cost breakdown, passed to [`Metrics::record_llm_usage`]. Carries
/// the four token dimensions plus the cost (present only when the model was priced). Grouping them in
/// a struct keeps the call site readable and the four dims impossible to transpose positionally.
#[derive(Clone, Copy, Debug, Default)]
pub struct LlmSample {
    pub tokens_in: u64,
    pub tokens_out: u64,
    /// Cached prompt tokens (⊆ `tokens_in`).
    pub cached_tokens: u64,
    /// Reasoning completion tokens (⊆ `tokens_out`).
    pub reasoning_tokens: u64,
    /// Cost in micro-dollars; `None` when the model is unpriced (tokens still counted).
    pub cost_micros: Option<u64>,
}

/// Per-model token/cost accumulators (behind the [`Metrics::per_model`] mutex). Plain integers, not
/// atomics: the map is small, updated under the lock, and read only at render time.
#[derive(Clone, Copy, Debug, Default)]
struct PerModelCounters {
    tokens_in: u64,
    tokens_out: u64,
    cached_tokens: u64,
    reasoning_tokens: u64,
    cost_micros: u64,
}

/// Process-wide metric registry. All methods take `&self` and use relaxed atomics — metrics
/// are monotonic counters/observations where exact inter-thread ordering doesn't matter.
pub struct Metrics {
    /// Off-box access-log shipping, when `[log.ship]` is enabled.
    ///
    /// It lives here because `Metrics` is already the telemetry sink threaded to every response
    /// path — `finish()` in proxy.rs takes it and has 40 call sites. Giving the shipper its own
    /// parameter would mean touching all forty to carry a value that is `None` in the default
    /// configuration, for no gain in clarity: an access log IS telemetry, and this is where the
    /// telemetry object lives.
    ///
    /// `OnceLock` because the shipper needs a Tokio runtime to spawn its task, so it cannot be
    /// built in `Metrics::new()` — it is installed once, at startup, after the runtime exists.
    log_shipper: std::sync::OnceLock<crate::logship::LogShipper>,
    /// Request-tracing span shipper, when `[tracing]` is enabled. Same `OnceLock`-installed-at-boot
    /// shape and the same reason as `log_shipper`: it needs a Tokio runtime to spawn its task, and
    /// it rides the object the response path already holds rather than a parameter added to
    /// `finish`'s 38 call sites.
    span_shipper: std::sync::OnceLock<crate::telemetry::SpanShipper>,
    /// The live TLS certificate, when the listener terminates TLS. Installed once at startup (the
    /// store is built after the registry) so its expiry, reload and renewal series render with
    /// everything else, and `GET /__edgeguard/tls` can find it through the state it already has.
    cert_store: std::sync::OnceLock<std::sync::Arc<crate::certstore::CertStore>>,
    /// The extra `[[tls.certs]]` pairs, served by hostname (SNI). Rendered as more series in the
    /// same families, labelled `cert="<first host>"`.
    sni_certs: std::sync::OnceLock<Vec<crate::certstore::SniCert>>,
    /// The listener's client-certificate verifier, when `[tls.client_auth]` is on: its CAs join the
    /// certificate series and its CRLs get `edgeguard_tls_crl_next_update_seconds`.
    client_auth: std::sync::OnceLock<std::sync::Arc<crate::client_auth::ClientAuth>>,
    /// `edgeguard_client_cert_header_total`, by [`HeaderResult::ALL`](crate::client_cert_header::HeaderResult::ALL)
    /// order; rendered only when `[trusted_client_cert_header]` is on.
    client_cert_header: [AtomicU64; 4],
    /// `edgeguard_forwarded_for_total`, by [`ForwardedFor::ALL`](crate::proxy::ForwardedFor::ALL)
    /// order; counted, and rendered, only with `server.trust_forwarded_for`.
    forwarded_for: [AtomicU64; 5],
    /// The header's settings, when it is on: its `ca_path` CAs and CRLs join the certificate series.
    trusted_header: std::sync::OnceLock<std::sync::Arc<crate::client_cert_header::TrustedHeader>>,
    /// The hot-swapped runtime, for the upstream pool series ([`Metrics::watch_runtime`]).
    runtime: std::sync::OnceLock<std::sync::Arc<arc_swap::ArcSwap<crate::proxy::Runtime>>>,
    /// Report the process's client certificates (`outbound::in_use`). They are process-wide, not
    /// this registry's, so only the registry `main` serves turns this on; a test building several
    /// pipelines in one process would otherwise see the others' certificates.
    client_certs: std::sync::atomic::AtomicBool,
    /// Connection counts per listener (`public`, `redirect`, `admin`), registered at startup by
    /// [`Metrics::listener_stats`]. Rendered only once one is registered, so a registry with no
    /// listeners renders exactly as before.
    listeners: Mutex<Vec<(&'static str, std::sync::Arc<crate::serve::ListenerStats>)>>,
    /// One counter per [`OUTCOMES`] entry (parallel index).
    requests: Vec<AtomicU64>,
    /// One counter per [`RL_SCOPES`] entry (parallel index).
    ratelimit_hits: Vec<AtomicU64>,
    /// One counter per [`WAF_RULES`] entry (parallel index).
    waf_hits: Vec<AtomicU64>,
    /// Cumulative histogram buckets (parallel to [`LATENCY_BUCKETS`]): `bucket[i]` counts
    /// observations with value <= `LATENCY_BUCKETS[i]`.
    latency_buckets: Vec<AtomicU64>,
    latency_sum_micros: AtomicU64,
    latency_count: AtomicU64,
    csp_reports: AtomicU64,
    /// CSP reports the sink did not keep, indexed like [`crate::csp_sink::CspDrop::ALL`].
    csp_dropped: [AtomicU64; 3],
    /// Folded CSP report requests sent to the control plane, and those that failed.
    csp_forwarded: AtomicU64,
    csp_forward_failed: AtomicU64,
    /// Drainable usage accumulators for managed-mode reporting (requests + bandwidth *since the
    /// last drain*). Kept separate from the monotonic Prometheus counters above precisely because
    /// the usage reporter resets these to zero each period — a Prometheus counter must not decrease.
    usage_requests: AtomicU64,
    usage_ingress_bytes: AtomicU64,
    usage_egress_bytes: AtomicU64,
    /// Drainable count of requests the edge *denied* (auth / WAF-forbidden / rate-limit / quota /
    /// budget / unpriced-model) since the last drain, for the managed-mode usage report's "blocked"
    /// figure. A subset of `usage_requests`. Distinct from the monotonic per-outcome counters.
    usage_blocked: AtomicU64,
    /// Drainable LLM token/cost usage for managed-mode cost reports (reset each report period,
    /// like the request/byte accumulators above). Distinct from the monotonic `llm_*` counters.
    usage_tokens_in: AtomicU64,
    usage_tokens_out: AtomicU64,
    usage_cost_micros: AtomicU64,
    /// Drainable WAF matches by rule class (parallel to [`WAF_RULES`]), for the managed-mode usage
    /// report's per-category security breakdown. Distinct from the monotonic `waf_hits` counters,
    /// which the reporter must not reset.
    usage_waf_hits: Vec<AtomicU64>,
    /// LLM input (prompt) tokens metered (monotonic).
    llm_tokens_in: AtomicU64,
    /// LLM output (completion) tokens metered (monotonic).
    llm_tokens_out: AtomicU64,
    /// LLM cached prompt tokens (⊆ input), metered separately (monotonic). The dim the "~7× undercount"
    /// gap is about — surfaced so cache utilisation and its cost impact are both visible.
    llm_cached_tokens: AtomicU64,
    /// LLM reasoning completion tokens (⊆ output), metered separately (monotonic).
    llm_reasoning_tokens: AtomicU64,
    /// Accumulated LLM cost in micro-dollars (1e-6 USD), for priced models only.
    llm_cost_micros: AtomicU64,
    /// Server-side time-to-first-token histogram (buckets parallel to [`LATENCY_BUCKETS`]) for
    /// streamed LLM responses, measured in the gateway as frames flow — no client clock, no in-app
    /// instrumentation. A trace backend only sees span-end duration, so this is a request-path-only
    /// signal, and a server-measured one rather than a client-clock approximation.
    llm_ttft_buckets: Vec<AtomicU64>,
    llm_ttft_sum_micros: AtomicU64,
    llm_ttft_count: AtomicU64,
    /// Mean time-per-output-token histogram for streamed LLM responses with >1 output token
    /// (inter-token latency = span of the output stream / (output_tokens − 1)).
    llm_tpot_buckets: Vec<AtomicU64>,
    llm_tpot_sum_micros: AtomicU64,
    llm_tpot_count: AtomicU64,
    /// One counter per [`LLM_RESULTS`] entry (parallel index).
    llm_results: Vec<AtomicU64>,
    /// Per-model token/cost breakdown (`edgeguard_llm_model_*`), bounded to [`MAX_LLM_MODEL_SERIES`]
    /// distinct models (overflow → [`LLM_MODEL_OVERFLOW`]) so client-chosen model strings can't blow
    /// up Prometheus cardinality.
    per_model: Mutex<BTreeMap<String, PerModelCounters>>,
    /// Per-team token/cost breakdown (`edgeguard_llm_team_*`), keyed by the `[llm].team_header` value
    /// (absent → `_none`). Same cardinality bound + overflow bucket as `per_model`, so it answers
    /// "which team spent this" for chargeback/showback without a Prometheus label explosion.
    per_team: Mutex<BTreeMap<String, PerModelCounters>>,
    /// Per-key token/cost breakdown (`edgeguard_llm_key_*`), keyed by the authenticated **principal**
    /// (API-key id / Basic user / JWT `sub`; unauthenticated → `_anon`) — the OSS identity primitive.
    /// Same cardinality bound + overflow bucket, so per-user attribution is reachable in the OSS core.
    per_key: Mutex<BTreeMap<String, PerModelCounters>>,
    /// One counter per [`BUDGET_SCOPES`] entry (parallel index): requests blocked by a hard budget.
    budget_blocked: Vec<AtomicU64>,
    /// Latest observed consumed ratio (`used / limit`, 0.0–1.0+) per budget *name* — the near-limit
    /// signal. A coarse gauge (one value per budget name, last writer wins across scope keys), which
    /// is what an "any budget near its cap" alert needs. Bounded by the operator-defined name set.
    budget_consumed: Mutex<BTreeMap<String, f64>>,
    /// One counter per [`KEYVAULT_RESULTS`] entry (parallel index).
    keyvault_results: Vec<AtomicU64>,
    /// One counter per [`DLP_CATEGORIES`] entry (parallel index): DLP findings by category.
    dlp_findings: Vec<AtomicU64>,
    /// Requests blocked (`403`) by DLP `block` mode.
    dlp_blocked: AtomicU64,
    /// Budget reconcile/release operations that ultimately FAILED (after retries) against the shared
    /// store. Each failure means a reserve→settle didn't complete, so the distributed counter has
    /// drifted (a leaked hold → phantom `BudgetExceededError`, or an uncharged settle → silent
    /// bypass). Surfaced so this drift is **observable** instead of only logged — alert on it.
    budget_reconcile_failures: AtomicU64,
    /// Per-route series, by route label. Read on every request and written only when a route is
    /// first seen, hence an `ArcSwap` rather than a lock. Lives here, outside the hot-swappable
    /// runtime, so a config reload does not reset the counters.
    routes: arc_swap::ArcSwap<BTreeMap<String, std::sync::Arc<RouteStats>>>,
    /// Per-consumer series, by principal; same shape and reason as `routes`. Bounded by
    /// `consumer_cap`: past it, new consumers fold into [`LLM_MODEL_OVERFLOW`].
    consumers: arc_swap::ArcSwap<BTreeMap<String, std::sync::Arc<ConsumerStats>>>,
    /// `metrics.consumer_series_max`; `0` turns per-consumer series off.
    consumer_cap: std::sync::atomic::AtomicUsize,
    /// Per-upstream series, by `scheme://host:port`; same shape and reason as `routes`. Bounded by
    /// the configured upstreams, which is all a request can be sent to.
    upstreams: arc_swap::ArcSwap<BTreeMap<String, std::sync::Arc<UpstreamStats>>>,
    /// `edgeguard_edge_overhead_seconds`, parallel to [`OVERHEAD_BUCKETS`].
    overhead_buckets: Vec<AtomicU64>,
    overhead_sum_micros: AtomicU64,
    overhead_count: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            log_shipper: std::sync::OnceLock::new(),
            span_shipper: std::sync::OnceLock::new(),
            cert_store: std::sync::OnceLock::new(),
            sni_certs: std::sync::OnceLock::new(),
            client_auth: std::sync::OnceLock::new(),
            client_certs: std::sync::atomic::AtomicBool::new(false),
            client_cert_header: std::array::from_fn(|_| AtomicU64::new(0)),
            forwarded_for: std::array::from_fn(|_| AtomicU64::new(0)),
            trusted_header: std::sync::OnceLock::new(),
            runtime: std::sync::OnceLock::new(),
            listeners: Mutex::new(Vec::new()),
            requests: OUTCOMES.iter().map(|_| AtomicU64::new(0)).collect(),
            ratelimit_hits: RL_SCOPES.iter().map(|_| AtomicU64::new(0)).collect(),
            waf_hits: WAF_RULES.iter().map(|_| AtomicU64::new(0)).collect(),
            latency_buckets: LATENCY_BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            latency_sum_micros: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            csp_reports: AtomicU64::new(0),
            csp_dropped: Default::default(),
            csp_forwarded: AtomicU64::new(0),
            csp_forward_failed: AtomicU64::new(0),
            usage_requests: AtomicU64::new(0),
            usage_ingress_bytes: AtomicU64::new(0),
            usage_egress_bytes: AtomicU64::new(0),
            usage_blocked: AtomicU64::new(0),
            usage_tokens_in: AtomicU64::new(0),
            usage_tokens_out: AtomicU64::new(0),
            usage_cost_micros: AtomicU64::new(0),
            usage_waf_hits: WAF_RULES.iter().map(|_| AtomicU64::new(0)).collect(),
            llm_tokens_in: AtomicU64::new(0),
            llm_tokens_out: AtomicU64::new(0),
            llm_cached_tokens: AtomicU64::new(0),
            llm_reasoning_tokens: AtomicU64::new(0),
            llm_cost_micros: AtomicU64::new(0),
            llm_ttft_buckets: LATENCY_BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            llm_ttft_sum_micros: AtomicU64::new(0),
            llm_ttft_count: AtomicU64::new(0),
            llm_tpot_buckets: LATENCY_BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            llm_tpot_sum_micros: AtomicU64::new(0),
            llm_tpot_count: AtomicU64::new(0),
            llm_results: LLM_RESULTS.iter().map(|_| AtomicU64::new(0)).collect(),
            per_model: Mutex::new(BTreeMap::new()),
            per_team: Mutex::new(BTreeMap::new()),
            per_key: Mutex::new(BTreeMap::new()),
            budget_blocked: BUDGET_SCOPES.iter().map(|_| AtomicU64::new(0)).collect(),
            budget_consumed: Mutex::new(BTreeMap::new()),
            keyvault_results: KEYVAULT_RESULTS.iter().map(|_| AtomicU64::new(0)).collect(),
            dlp_findings: DLP_CATEGORIES.iter().map(|_| AtomicU64::new(0)).collect(),
            dlp_blocked: AtomicU64::new(0),
            budget_reconcile_failures: AtomicU64::new(0),
            routes: arc_swap::ArcSwap::default(),
            consumers: arc_swap::ArcSwap::default(),
            consumer_cap: std::sync::atomic::AtomicUsize::new(DEFAULT_CONSUMER_SERIES),
            upstreams: arc_swap::ArcSwap::default(),
            overhead_buckets: OVERHEAD_BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            overhead_sum_micros: AtomicU64::new(0),
            overhead_count: AtomicU64::new(0),
        }
    }
}

/// Observe `elapsed` into a cumulative histogram (buckets parallel to [`LATENCY_BUCKETS`]) plus its
/// running sum (micros) and count. Shared by the request-latency and the LLM TTFT/TPOT histograms so
/// their bucketing can't drift.
fn observe_hist(
    buckets: &[AtomicU64],
    sum_micros: &AtomicU64,
    count: &AtomicU64,
    elapsed: Duration,
) {
    observe_hist_in(LATENCY_BUCKETS, buckets, sum_micros, count, elapsed);
}

/// [`observe_hist`] over `bounds`, for a histogram whose range is not request latency's.
fn observe_hist_in(
    bounds: &[f64],
    buckets: &[AtomicU64],
    sum_micros: &AtomicU64,
    count: &AtomicU64,
    elapsed: Duration,
) {
    let secs = elapsed.as_secs_f64();
    for (i, bound) in bounds.iter().enumerate() {
        if secs <= *bound {
            buckets[i].fetch_add(1, Ordering::Relaxed);
        }
    }
    sum_micros.fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    count.fetch_add(1, Ordering::Relaxed);
}

/// Render one Prometheus histogram (`_bucket`/`_sum`/`_count`) to `out`, sharing the exposition
/// shape with the request-latency histogram above.
fn render_hist(
    out: &mut String,
    name: &str,
    help: &str,
    buckets: &[AtomicU64],
    sum_micros: &AtomicU64,
    count: &AtomicU64,
) {
    render_hist_in(out, name, help, LATENCY_BUCKETS, buckets, sum_micros, count);
}

/// [`render_hist`] over `bounds`.
fn render_hist_in(
    out: &mut String,
    name: &str,
    help: &str,
    bounds: &[f64],
    buckets: &[AtomicU64],
    sum_micros: &AtomicU64,
    count: &AtomicU64,
) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} histogram\n"));
    for (i, bound) in bounds.iter().enumerate() {
        let v = buckets[i].load(Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{le=\"{bound}\"}} {v}\n"));
    }
    // The `+Inf` bucket equals the total observation count by definition.
    let c = count.load(Ordering::Relaxed);
    out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {c}\n"));
    let sum_secs = sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    out.push_str(&format!("{name}_sum {sum_secs}\n"));
    out.push_str(&format!("{name}_count {c}\n"));
}

/// Render one per-dimension token/cost breakdown (`per_model` / `per_team` / `per_key`) to `out`,
/// sharing the exposition shape across all three so they can't drift from one another.
fn render_breakdown(
    out: &mut String,
    metric_prefix: &str,
    label_name: &str,
    dim_desc: &str,
    map: &BTreeMap<String, PerModelCounters>,
) {
    out.push_str(&format!(
        "# HELP {metric_prefix}_tokens_total LLM tokens metered by {dim_desc} and kind.\n"
    ));
    out.push_str(&format!("# TYPE {metric_prefix}_tokens_total counter\n"));
    for (k, c) in map.iter() {
        let label = escape_label(k);
        for kind in LLM_TOKEN_KINDS {
            let v = match *kind {
                "input" => c.tokens_in,
                "output" => c.tokens_out,
                "cached" => c.cached_tokens,
                "reasoning" => c.reasoning_tokens,
                _ => 0,
            };
            out.push_str(&format!(
                "{metric_prefix}_tokens_total{{{label_name}=\"{label}\",kind=\"{kind}\"}} {v}\n"
            ));
        }
    }
    out.push_str(&format!(
        "# HELP {metric_prefix}_cost_microdollars_total LLM cost (micro-dollars) by {dim_desc}.\n"
    ));
    out.push_str(&format!(
        "# TYPE {metric_prefix}_cost_microdollars_total counter\n"
    ));
    for (k, c) in map.iter() {
        out.push_str(&format!(
            "{metric_prefix}_cost_microdollars_total{{{label_name}=\"{}\"}} {}\n",
            escape_label(k),
            c.cost_micros
        ));
    }
}

/// Add `s` to the `key` bucket of a bounded per-dimension accumulator (`per_model` / `per_team`): a
/// new key is inserted only while under [`MAX_LLM_MODEL_SERIES`]; past the cap it folds into
/// [`LLM_MODEL_OVERFLOW`], so a flood of distinct label values can't grow the map without bound.
fn accumulate_bounded(map: &Mutex<BTreeMap<String, PerModelCounters>>, key: &str, s: &LlmSample) {
    let mut map = map.lock().expect("per-dimension mutex poisoned");
    let k = if map.contains_key(key) || map.len() < MAX_LLM_MODEL_SERIES {
        key
    } else {
        LLM_MODEL_OVERFLOW
    };
    let c = map.entry(k.to_string()).or_default();
    c.tokens_in = c.tokens_in.saturating_add(s.tokens_in);
    c.tokens_out = c.tokens_out.saturating_add(s.tokens_out);
    c.cached_tokens = c.cached_tokens.saturating_add(s.cached_tokens);
    c.reasoning_tokens = c.reasoning_tokens.saturating_add(s.reasoning_tokens);
    c.cost_micros = c.cost_micros.saturating_add(s.cost_micros.unwrap_or(0));
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the access-log shipper. Called once at startup, after the Tokio runtime exists.
    ///
    /// Returns whether it took: a second call is ignored rather than replacing a live shipper,
    /// which would leak the first one's background task and its queued records.
    pub fn set_log_shipper(&self, s: crate::logship::LogShipper) -> bool {
        self.log_shipper.set(s).is_ok()
    }

    /// The shipper, if `[log.ship]` is enabled.
    pub fn log_shipper(&self) -> Option<&crate::logship::LogShipper> {
        self.log_shipper.get()
    }

    /// Install the span shipper. Called once at startup, after the Tokio runtime exists.
    pub fn set_span_shipper(&self, s: crate::telemetry::SpanShipper) -> bool {
        self.span_shipper.set(s).is_ok()
    }

    /// The span shipper, if `[tracing]` is enabled. `None` is also the cheap gate on the request
    /// path: with tracing off, nothing about a span is computed.
    pub fn span_shipper(&self) -> Option<&crate::telemetry::SpanShipper> {
        self.span_shipper.get()
    }

    /// Install the live certificate store. Called once at startup, when TLS is enabled.
    pub fn set_cert_store(&self, store: std::sync::Arc<crate::certstore::CertStore>) -> bool {
        self.cert_store.set(store).is_ok()
    }

    /// Install the extra SNI pairs. Called once at startup, when `[[tls.certs]]` lists any.
    pub fn set_sni_certs(&self, certs: Vec<crate::certstore::SniCert>) -> bool {
        self.sni_certs.set(certs).is_ok()
    }

    /// Install the client-certificate verifier. Called once at startup, when client auth is on.
    pub fn set_client_auth(&self, auth: std::sync::Arc<crate::client_auth::ClientAuth>) -> bool {
        self.client_auth.set(auth).is_ok()
    }

    pub fn client_auth(&self) -> Option<&std::sync::Arc<crate::client_auth::ClientAuth>> {
        self.client_auth.get()
    }

    /// Install `[trusted_client_cert_header]`: its counters render, and its verification CAs and
    /// CRLs join the certificate series.
    pub fn set_trusted_header(
        &self,
        header: std::sync::Arc<crate::client_cert_header::TrustedHeader>,
    ) -> bool {
        self.trusted_header.set(header).is_ok()
    }

    /// Read the upstream pools' series from `runtime`, whichever one is current when scraped.
    pub fn watch_runtime(
        &self,
        runtime: std::sync::Arc<arc_swap::ArcSwap<crate::proxy::Runtime>>,
    ) -> bool {
        self.runtime.set(runtime).is_ok()
    }

    pub fn trusted_header(
        &self,
    ) -> Option<&std::sync::Arc<crate::client_cert_header::TrustedHeader>> {
        self.trusted_header.get()
    }

    /// Count what became of one request's forwarded client certificate.
    pub fn record_client_cert_header(&self, result: crate::client_cert_header::HeaderResult) {
        let all = crate::client_cert_header::HeaderResult::ALL;
        if let Some(i) = all.iter().position(|r| *r == result) {
            self.client_cert_header[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count how one request's `X-Forwarded-For` was read (with `trust_forwarded_for` on).
    pub fn record_forwarded_for(&self, result: crate::proxy::ForwardedFor) {
        let all = crate::proxy::ForwardedFor::ALL;
        if let Some(i) = all.iter().position(|r| *r == result) {
            self.forwarded_for[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Report the client certificates this process presents, in the certificate series and
    /// `GET /__edgeguard/tls`. Called once by `main` for the registry it serves.
    pub fn report_client_certs(&self) {
        self.client_certs.store(true, Ordering::Relaxed);
    }

    /// The client certificates in use, when this registry reports them.
    pub fn client_certs(&self) -> Vec<crate::outbound::InUse> {
        if self.client_certs.load(Ordering::Relaxed) {
            crate::outbound::in_use()
        } else {
            Vec::new()
        }
    }

    /// The connection counts for the listener called `name`, created and registered on first use.
    /// Pass them to the listener in [`ServeOpts`](crate::serve::ServeOpts) so they are exported.
    pub fn listener_stats(
        &self,
        name: &'static str,
    ) -> std::sync::Arc<crate::serve::ListenerStats> {
        let mut listeners = self.listeners.lock().expect("listeners mutex poisoned");
        if let Some((_, stats)) = listeners.iter().find(|(n, _)| *n == name) {
            return std::sync::Arc::clone(stats);
        }
        let stats = std::sync::Arc::default();
        listeners.push((name, std::sync::Arc::clone(&stats)));
        stats
    }

    /// The counters for `route`, created on first use. Lock-free once the route exists.
    pub fn route_stats(&self, route: &str) -> std::sync::Arc<RouteStats> {
        if let Some(stats) = self.routes.load().get(route) {
            return std::sync::Arc::clone(stats);
        }
        let mut created = None;
        self.routes.rcu(|map| {
            let mut map = BTreeMap::clone(map);
            let stats = map.entry(route.to_string()).or_default();
            created = Some(std::sync::Arc::clone(stats));
            map
        });
        created.expect("rcu runs its closure")
    }

    /// The counters for the upstream `upstream` (`scheme://host:port`), created on first use.
    /// An upstream's requests by result, in [`UpstreamResult::ALL`] order; zeros for one never
    /// sent a request. Unlike [`Metrics::upstream_stats`], creates no series.
    pub fn upstream_results(&self, upstream: &str) -> [u64; UpstreamResult::ALL.len()] {
        match self.upstreams.load().get(upstream) {
            Some(stats) => std::array::from_fn(|i| stats.results[i].load(Ordering::Relaxed)),
            None => [0; UpstreamResult::ALL.len()],
        }
    }

    pub fn upstream_stats(&self, upstream: &str) -> std::sync::Arc<UpstreamStats> {
        if let Some(stats) = self.upstreams.load().get(upstream) {
            return std::sync::Arc::clone(stats);
        }
        let mut created = None;
        self.upstreams.rcu(|map| {
            let mut map = BTreeMap::clone(map);
            let stats = map.entry(upstream.to_string()).or_default();
            created = Some(std::sync::Arc::clone(stats));
            map
        });
        created.expect("rcu runs its closure")
    }

    /// The counters for the consumer `principal` (`None`: unauthenticated, [`ANON_CONSUMER`]), or
    /// `None` when per-consumer series are off. Past `metrics.consumer_series_max` distinct
    /// consumers, a new one shares the overflow series.
    pub fn consumer_stats(&self, principal: Option<&str>) -> Option<std::sync::Arc<ConsumerStats>> {
        let cap = self.consumer_cap.load(Ordering::Relaxed);
        if cap == 0 {
            return None;
        }
        let key = principal.unwrap_or(ANON_CONSUMER);
        // The anonymous series and the overflow series do not count against the cap.
        let named = |map: &BTreeMap<String, std::sync::Arc<ConsumerStats>>| {
            map.keys()
                .filter(|k| *k != ANON_CONSUMER && *k != LLM_MODEL_OVERFLOW)
                .count()
        };
        let current = self.consumers.load();
        if let Some(stats) = current.get(key) {
            return Some(std::sync::Arc::clone(stats));
        }
        // Past the cap, a new consumer is counted on the overflow series as it stands: no copy of
        // the map per request, which a stream of new principals would otherwise cost.
        if key != ANON_CONSUMER && named(&current) >= cap {
            if let Some(overflow) = current.get(LLM_MODEL_OVERFLOW) {
                return Some(std::sync::Arc::clone(overflow));
            }
        }
        let mut found = None;
        self.consumers.rcu(|map| {
            let mut map = BTreeMap::clone(map);
            let key = if key == ANON_CONSUMER || named(&map) < cap {
                key
            } else {
                LLM_MODEL_OVERFLOW
            };
            found = Some(std::sync::Arc::clone(
                map.entry(key.to_string()).or_default(),
            ));
            map
        });
        found
    }

    /// Set `metrics.consumer_series_max`. Called once at startup.
    pub fn set_consumer_series_max(&self, max: usize) {
        self.consumer_cap.store(max, Ordering::Relaxed);
    }

    /// The extra SNI pairs (empty when none are configured).
    pub fn sni_certs(&self) -> &[crate::certstore::SniCert] {
        self.sni_certs.get().map(Vec::as_slice).unwrap_or(&[])
    }

    /// The live certificate store, if this process terminates TLS.
    pub fn cert_store(&self) -> Option<&std::sync::Arc<crate::certstore::CertStore>> {
        self.cert_store.get()
    }

    /// Count one finished request under its `outcome` label.
    pub fn record_request(&self, outcome: &str) {
        let idx = OUTCOMES
            .iter()
            .position(|o| *o == outcome)
            .unwrap_or(OUTCOMES.len() - 1); // -> "other"
        self.requests[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Observe a request's end-to-end latency into the histogram.
    /// Time the edge itself added to a proxied request the upstream answered: its time to response
    /// headers, less the time spent waiting on the upstream.
    pub fn observe_edge_overhead(&self, overhead: Duration) {
        observe_hist_in(
            OVERHEAD_BUCKETS,
            &self.overhead_buckets,
            &self.overhead_sum_micros,
            &self.overhead_count,
            overhead,
        );
    }

    pub fn observe_latency(&self, elapsed: Duration) {
        observe_hist(
            &self.latency_buckets,
            &self.latency_sum_micros,
            &self.latency_count,
            elapsed,
        );
    }

    /// Observe a streamed LLM response's server-side **time-to-first-token** and, when the response
    /// had more than one output token, its mean **time-per-output-token**. Called once per streamed
    /// LLM request from the response body's `Drop`, after the terminal `usage` frame is parsed. The
    /// gateway sits in the token stream, so these are measured with no client clock and no in-app
    /// instrumentation — the request-path advantage a trace backend (which only sees span-end
    /// duration) can't offer.
    pub fn record_llm_latency(&self, ttft: Duration, tpot: Option<Duration>) {
        observe_hist(
            &self.llm_ttft_buckets,
            &self.llm_ttft_sum_micros,
            &self.llm_ttft_count,
            ttft,
        );
        if let Some(tpot) = tpot {
            observe_hist(
                &self.llm_tpot_buckets,
                &self.llm_tpot_sum_micros,
                &self.llm_tpot_count,
                tpot,
            );
        }
    }

    /// Count a rate-limit rejection by which limiter scope tripped (`ip`/`route`/`key`).
    pub fn record_ratelimit_hit(&self, scope: &str) {
        if let Some(idx) = RL_SCOPES.iter().position(|s| *s == scope) {
            self.ratelimit_hits[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count one WAF rule match by rule class (`sqli`/`xss`/`path_traversal`/`custom`).
    /// Recorded for both report-only and blocking modes — so a report-first rollout is
    /// visible — while a *blocked* request is additionally counted under the `forbidden`
    /// request outcome.
    pub fn record_waf_hit(&self, class: &str) {
        if let Some(idx) = WAF_RULES.iter().position(|c| *c == class) {
            self.waf_hits[idx].fetch_add(1, Ordering::Relaxed);
            // Parallel drainable accumulator for the managed-mode usage report.
            self.usage_waf_hits[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count one received CSP violation report.
    pub fn record_csp_report(&self) {
        self.csp_reports.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a CSP report the sink did not keep.
    pub fn record_csp_dropped(&self, reason: crate::csp_sink::CspDrop) {
        let i = crate::csp_sink::CspDrop::ALL
            .iter()
            .position(|r| *r == reason)
            .unwrap_or(0);
        self.csp_dropped[i].fetch_add(1, Ordering::Relaxed);
    }

    /// Count one folded CSP report request sent to the control plane, or one that failed.
    pub fn record_csp_forwarded(&self, ok: bool) {
        if ok {
            &self.csp_forwarded
        } else {
            &self.csp_forward_failed
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// Count one request toward the drainable usage accumulator (managed mode). Called once per
    /// request from the single `finish` exit, so every request — proxied or rejected — counts.
    /// `outcome` is the request's outcome label; a denial outcome (see [`outcome_is_blocked`]) also
    /// bumps the drainable `blocked` accumulator, so the control plane can show what the edge screened.
    pub fn add_usage_request(&self, outcome: &str) {
        self.usage_requests.fetch_add(1, Ordering::Relaxed);
        if outcome_is_blocked(outcome) {
            self.usage_blocked.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Add request (ingress) + response (egress) bytes to the drainable usage accumulator. Called
    /// on the proxied path where both bodies are buffered and the counts are known.
    pub fn add_usage_bytes(&self, ingress: usize, egress: usize) {
        self.usage_ingress_bytes
            .fetch_add(ingress as u64, Ordering::Relaxed);
        self.usage_egress_bytes
            .fetch_add(egress as u64, Ordering::Relaxed);
    }

    /// Atomically read-and-zero the usage accumulators — the delta the usage reporter ships to the
    /// control plane (requests + bandwidth + LLM tokens/cost, gateway L4).
    pub fn drain_usage(&self) -> DrainedUsage {
        debug_assert_eq!(WAF_RULES, ["sqli", "xss", "path_traversal", "custom"]);
        DrainedUsage {
            requests: self.usage_requests.swap(0, Ordering::Relaxed),
            ingress_bytes: self.usage_ingress_bytes.swap(0, Ordering::Relaxed),
            egress_bytes: self.usage_egress_bytes.swap(0, Ordering::Relaxed),
            tokens_in: self.usage_tokens_in.swap(0, Ordering::Relaxed),
            tokens_out: self.usage_tokens_out.swap(0, Ordering::Relaxed),
            cost_micros: self.usage_cost_micros.swap(0, Ordering::Relaxed),
            blocked: self.usage_blocked.swap(0, Ordering::Relaxed),
            // Indices parallel to WAF_RULES = [sqli, xss, path_traversal, custom].
            waf_sqli: self.usage_waf_hits[0].swap(0, Ordering::Relaxed),
            waf_xss: self.usage_waf_hits[1].swap(0, Ordering::Relaxed),
            waf_path_traversal: self.usage_waf_hits[2].swap(0, Ordering::Relaxed),
            waf_custom: self.usage_waf_hits[3].swap(0, Ordering::Relaxed),
        }
    }

    /// Add a previously-drained delta back, e.g. when a usage report failed to send — so the
    /// next period reships it instead of losing billable usage. (New requests that arrived during
    /// the failed send simply add on top, as intended.)
    pub fn restore_usage(&self, u: &DrainedUsage) {
        debug_assert_eq!(WAF_RULES, ["sqli", "xss", "path_traversal", "custom"]);
        self.usage_requests.fetch_add(u.requests, Ordering::Relaxed);
        self.usage_ingress_bytes
            .fetch_add(u.ingress_bytes, Ordering::Relaxed);
        self.usage_egress_bytes
            .fetch_add(u.egress_bytes, Ordering::Relaxed);
        self.usage_tokens_in
            .fetch_add(u.tokens_in, Ordering::Relaxed);
        self.usage_tokens_out
            .fetch_add(u.tokens_out, Ordering::Relaxed);
        self.usage_cost_micros
            .fetch_add(u.cost_micros, Ordering::Relaxed);
        self.usage_blocked.fetch_add(u.blocked, Ordering::Relaxed);
        // Indices parallel to WAF_RULES = [sqli, xss, path_traversal, custom].
        self.usage_waf_hits[0].fetch_add(u.waf_sqli, Ordering::Relaxed);
        self.usage_waf_hits[1].fetch_add(u.waf_xss, Ordering::Relaxed);
        self.usage_waf_hits[2].fetch_add(u.waf_path_traversal, Ordering::Relaxed);
        self.usage_waf_hits[3].fetch_add(u.waf_custom, Ordering::Relaxed);
    }

    /// Record one metered LLM request for `model`: add its four token dimensions and — when the model
    /// was priced — its cost (micro-dollars). `cost_micros == None` means the model isn't in the price
    /// book, so tokens are still counted but the request is bucketed `unpriced` rather than `metered`.
    /// Also updates the bounded per-model breakdown (`edgeguard_llm_model_*`).
    pub fn record_llm_usage(&self, model: &str, s: LlmSample) {
        self.llm_tokens_in.fetch_add(s.tokens_in, Ordering::Relaxed);
        self.llm_tokens_out
            .fetch_add(s.tokens_out, Ordering::Relaxed);
        self.llm_cached_tokens
            .fetch_add(s.cached_tokens, Ordering::Relaxed);
        self.llm_reasoning_tokens
            .fetch_add(s.reasoning_tokens, Ordering::Relaxed);
        // Drainable accumulators for the managed-mode cost report.
        self.usage_tokens_in
            .fetch_add(s.tokens_in, Ordering::Relaxed);
        self.usage_tokens_out
            .fetch_add(s.tokens_out, Ordering::Relaxed);
        let result = match s.cost_micros {
            Some(c) => {
                self.llm_cost_micros.fetch_add(c, Ordering::Relaxed);
                self.usage_cost_micros.fetch_add(c, Ordering::Relaxed);
                "metered"
            }
            None => "unpriced",
        };
        self.bump_llm_result(result);
        self.record_per_model(model, &s);
    }

    /// Update the bounded per-model accumulator. A new model is only inserted while under the cap;
    /// once full it folds into [`LLM_MODEL_OVERFLOW`], so a flood of distinct model strings can't grow
    /// the map without bound.
    fn record_per_model(&self, model: &str, s: &LlmSample) {
        accumulate_bounded(&self.per_model, model, s);
    }

    /// Record one metered LLM request against its team (`[llm].team_header` value; absent → `_none`),
    /// for per-team chargeback/showback (`edgeguard_llm_team_*`). Bounded exactly like the per-model
    /// breakdown. Called alongside [`Self::record_llm_usage`] from the request path.
    pub fn record_llm_team_usage(&self, team: &str, s: &LlmSample) {
        accumulate_bounded(&self.per_team, team, s);
    }

    /// Record one metered LLM request against its authenticated key/principal (`_anon` when
    /// unauthenticated), for per-user cost attribution (`edgeguard_llm_key_*`). Bounded exactly like
    /// the per-model breakdown. Reuses the existing OSS auth principal as the identity — so per-key
    /// FinOps is reachable without the EE control plane.
    pub fn record_llm_key_usage(&self, key: &str, s: &LlmSample) {
        accumulate_bounded(&self.per_key, key, s);
    }

    /// Record a request blocked by a hard LLM budget, by the budget's `scope` (unknown → `other`).
    pub fn record_budget_blocked(&self, scope: &str) {
        let idx = BUDGET_SCOPES
            .iter()
            .position(|s| *s == scope)
            .unwrap_or(BUDGET_SCOPES.len() - 1); // -> "other"
        self.budget_blocked[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Record the latest consumed ratio (`used / limit`) for a budget by `name` — the near-limit
    /// gauge. Last writer wins per name (a coarse "is any budget near its cap" signal). NaN/negative
    /// samples are dropped so a divide-by-zero can't poison the gauge.
    pub fn record_budget_consumed(&self, name: &str, ratio: f64) {
        if !ratio.is_finite() || ratio < 0.0 {
            return;
        }
        let mut map = self
            .budget_consumed
            .lock()
            .expect("budget_consumed mutex poisoned");
        // Bound the map the same way as models: operator-defined names are few, but never grow past
        // the cap if a config churns budget names.
        if map.contains_key(name) || map.len() < MAX_LLM_MODEL_SERIES {
            map.insert(name.to_string(), ratio);
        }
    }

    /// Record `n` budget reconcile/release failures against the shared store (after retries). A
    /// non-zero rate here means the distributed budget counter is drifting — the signal to alert on.
    pub fn record_budget_reconcile_failures(&self, n: usize) {
        if n > 0 {
            self.budget_reconcile_failures
                .fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    /// Record an LLM request whose response carried no usage (error, or a stream the client didn't
    /// opt into usage on). No tokens/cost, but the request is visible as `no_usage`.
    pub fn record_llm_no_usage(&self) {
        self.bump_llm_result("no_usage");
    }

    fn bump_llm_result(&self, result: &str) {
        if let Some(idx) = LLM_RESULTS.iter().position(|r| *r == result) {
            self.llm_results[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a key-vault decision by `result` (`swapped`/`denied_key`/`denied_model`).
    pub fn record_keyvault(&self, result: &str) {
        if let Some(idx) = KEYVAULT_RESULTS.iter().position(|r| *r == result) {
            self.keyvault_results[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record one DLP finding under its `category` (unknown → `other`).
    pub fn record_dlp_finding(&self, category: &str) {
        let idx = DLP_CATEGORIES
            .iter()
            .position(|c| *c == category)
            .unwrap_or(DLP_CATEGORIES.len() - 1); // -> "other"
        self.dlp_findings[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a request blocked by DLP `block` mode.
    pub fn record_dlp_blocked(&self) {
        self.dlp_blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// Render the Prometheus text exposition (format version 0.0.4).
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(1024);

        out.push_str("# HELP edgeguard_requests_total Total proxied requests by outcome.\n");
        out.push_str("# TYPE edgeguard_requests_total counter\n");
        for (i, label) in OUTCOMES.iter().enumerate() {
            let v = self.requests[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "edgeguard_requests_total{{outcome=\"{label}\"}} {v}\n"
            ));
        }

        out.push_str(
            "# HELP edgeguard_ratelimit_hits_total Requests rejected by a rate limiter, by scope.\n",
        );
        out.push_str("# TYPE edgeguard_ratelimit_hits_total counter\n");
        for (i, label) in RL_SCOPES.iter().enumerate() {
            let v = self.ratelimit_hits[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "edgeguard_ratelimit_hits_total{{scope=\"{label}\"}} {v}\n"
            ));
        }

        out.push_str(
            "# HELP edgeguard_waf_hits_total WAF rule matches by class (report-only + blocked).\n",
        );
        out.push_str("# TYPE edgeguard_waf_hits_total counter\n");
        for (i, label) in WAF_RULES.iter().enumerate() {
            let v = self.waf_hits[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "edgeguard_waf_hits_total{{rule=\"{label}\"}} {v}\n"
            ));
        }

        out.push_str("# HELP edgeguard_csp_reports_total CSP violation reports received.\n");
        out.push_str("# TYPE edgeguard_csp_reports_total counter\n");
        out.push_str(&format!(
            "edgeguard_csp_reports_total {}\n",
            self.csp_reports.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP edgeguard_csp_reports_dropped_total CSP reports the sink did not keep, by reason.\n",
        );
        out.push_str("# TYPE edgeguard_csp_reports_dropped_total counter\n");
        for (reason, n) in crate::csp_sink::CspDrop::ALL.iter().zip(&self.csp_dropped) {
            out.push_str(&format!(
                "edgeguard_csp_reports_dropped_total{{reason=\"{}\"}} {}\n",
                reason.label(),
                n.load(Ordering::Relaxed)
            ));
        }
        out.push_str(
            "# HELP edgeguard_csp_forward_requests_total Folded CSP report requests sent to the control plane, by result.\n",
        );
        out.push_str("# TYPE edgeguard_csp_forward_requests_total counter\n");
        out.push_str(&format!(
            "edgeguard_csp_forward_requests_total{{result=\"ok\"}} {}\nedgeguard_csp_forward_requests_total{{result=\"error\"}} {}\n",
            self.csp_forwarded.load(Ordering::Relaxed),
            self.csp_forward_failed.load(Ordering::Relaxed)
        ));

        // Connections per listener. `rejected` climbing means `server.max_connections` is turning
        // clients away: raise it, or find out who is holding connections open.
        let listeners = self
            .listeners
            .lock()
            .expect("listeners mutex poisoned")
            .clone();
        if !listeners.is_empty() {
            out.push_str(
                "# HELP edgeguard_connections_open Client connections open now, by listener.\n\
                 # TYPE edgeguard_connections_open gauge\n",
            );
            for (name, stats) in &listeners {
                out.push_str(&format!(
                    "edgeguard_connections_open{{listener=\"{name}\"}} {}\n",
                    stats.open()
                ));
            }
            out.push_str(
                "# HELP edgeguard_connections_rejected_total Connections closed at accept because \
                 the listener was at server.max_connections.\n\
                 # TYPE edgeguard_connections_rejected_total counter\n",
            );
            for (name, stats) in &listeners {
                out.push_str(&format!(
                    "edgeguard_connections_rejected_total{{listener=\"{name}\"}} {}\n",
                    stats.rejected()
                ));
            }
            // Requests, not connections: one HTTP/2 connection can carry many, and an idle
            // keep-alive connection none. Counted until hyper has taken the end of the response
            // body, so a long stream holds its count. A scrape on the listener it reads counts
            // itself.
            out.push_str(
                "# HELP edgeguard_requests_in_flight Requests still being answered, from the \
                 request head until the end of the response body, by listener.\n\
                 # TYPE edgeguard_requests_in_flight gauge\n",
            );
            for (name, stats) in &listeners {
                out.push_str(&format!(
                    "edgeguard_requests_in_flight{{listener=\"{name}\"}} {}\n",
                    stats.in_flight()
                ));
            }
            // Only listeners with a cap, so `open / max` is defined wherever `max` exists.
            let capped: Vec<_> = listeners.iter().filter(|(_, s)| s.max() > 0).collect();
            if !capped.is_empty() {
                out.push_str(
                    "# HELP edgeguard_connections_max server.max_connections, for listeners that \
                     have a cap.\n\
                     # TYPE edgeguard_connections_max gauge\n",
                );
                for (name, stats) in capped {
                    out.push_str(&format!(
                        "edgeguard_connections_max{{listener=\"{name}\"}} {}\n",
                        stats.max()
                    ));
                }
            }
            // TLS listeners only. `client_cert` is the one to watch with `[tls.client_auth]` on:
            // clients refused for their certificate never reach the request log.
            let tls: Vec<_> = listeners.iter().filter(|(_, s)| s.is_tls()).collect();
            if !tls.is_empty() {
                // Every handshake that ended, failures included, so the failure ratio is
                // failures / handshakes.
                out.push_str(
                    "# HELP edgeguard_tls_handshakes_total TLS handshakes that ended, successful \
                     or not, by listener. Failures are also in \
                     edgeguard_tls_handshake_failures_total. A connection that closed before \
                     its ClientHello is not a handshake (edgeguard_tls_no_client_hello_total).\n\
                     # TYPE edgeguard_tls_handshakes_total counter\n",
                );
                for (name, stats) in &tls {
                    out.push_str(&format!(
                        "edgeguard_tls_handshakes_total{{listener=\"{name}\"}} {}\n",
                        stats.tls_handshakes()
                    ));
                }
                out.push_str(
                    "# HELP edgeguard_tls_handshake_failures_total Failed TLS handshakes, by \
                     listener and reason (client_cert = refused for its client certificate).\n\
                     # TYPE edgeguard_tls_handshake_failures_total counter\n",
                );
                for (name, stats) in &tls {
                    for (reason, v) in crate::serve::TLS_FAILURE_REASONS
                        .iter()
                        .zip(stats.tls_failures())
                    {
                        out.push_str(&format!(
                            "edgeguard_tls_handshake_failures_total{{listener=\"{name}\",reason=\"{reason}\"}} {v}\n"
                        ));
                    }
                }
                // Not failures: no handshake was attempted. A load balancer's TCP or PROXY
                // `LOCAL` health checks land here, a few a second behind an NLB.
                out.push_str(
                    "# HELP edgeguard_tls_no_client_hello_total Connections to a TLS listener \
                     that closed before sending a ClientHello (TCP and PROXY protocol health \
                     checks, scans), by listener. Not handshakes: in neither \
                     edgeguard_tls_handshakes_total nor edgeguard_tls_handshake_failures_total.\n\
                     # TYPE edgeguard_tls_no_client_hello_total counter\n",
                );
                for (name, stats) in &tls {
                    out.push_str(&format!(
                        "edgeguard_tls_no_client_hello_total{{listener=\"{name}\"}} {}\n",
                        stats.no_client_hello()
                    ));
                }
            }
            // Listeners with `server.proxy_protocol` only. `untrusted` climbing means a balancer
            // outside `proxy_protocol_trusted` (a new address, or one that preserves client IPs)
            // is having its connections closed; `missing` without `proxied`, that the balancer
            // is not sending headers, so every client looks like it.
            let pp: Vec<_> = listeners
                .iter()
                .filter(|(_, s)| s.reads_proxy_protocol())
                .collect();
            if !pp.is_empty() {
                out.push_str(
                    "# HELP edgeguard_proxy_protocol_total Connections by their PROXY protocol \
                     header, by listener and result (proxied: the header named the client; \
                     untrusted, invalid and timeout: closed).\n\
                     # TYPE edgeguard_proxy_protocol_total counter\n",
                );
                for (name, stats) in pp {
                    for (outcome, v) in crate::proxy_protocol::Outcome::ALL
                        .iter()
                        .zip(stats.proxy_protocol_outcomes())
                    {
                        out.push_str(&format!(
                            "edgeguard_proxy_protocol_total{{listener=\"{name}\",result=\"{}\"}} {v}\n",
                            outcome.label()
                        ));
                    }
                }
            }
        }

        // Access-log shipping. `dropped` is the important one: a log pipeline that silently drops
        // is worse than no pipeline, because the gap is invisible in the destination and the
        // absence of records reads as an absence of traffic. Alert on it.
        if let Some(shipper) = self.log_shipper.get() {
            let (sent, dropped_q, dropped_send, batches, failed) = shipper.stats().snapshot();
            out.push_str(
                "# HELP edgeguard_logship_sent_total Access-log records delivered to the collector.\n\
                 # TYPE edgeguard_logship_sent_total counter\n",
            );
            out.push_str(&format!("edgeguard_logship_sent_total {sent}\n"));
            out.push_str(
                "# HELP edgeguard_logship_dropped_total Access-log records dropped, by reason.\n\
                 # TYPE edgeguard_logship_dropped_total counter\n",
            );
            // Two reasons, kept apart because they call for different responses: `queue_full`
            // means the edge is producing faster than the collector accepts (raise queue_size, or
            // find out why the collector is slow); `send_failed` means the collector rejected or
            // was unreachable.
            out.push_str(&format!(
                "edgeguard_logship_dropped_total{{reason=\"queue_full\"}} {dropped_q}\n"
            ));
            out.push_str(&format!(
                "edgeguard_logship_dropped_total{{reason=\"send_failed\"}} {dropped_send}\n"
            ));
            out.push_str(
                "# HELP edgeguard_logship_batches_total Access-log batches POSTed, by outcome.\n\
                 # TYPE edgeguard_logship_batches_total counter\n",
            );
            out.push_str(&format!(
                "edgeguard_logship_batches_total{{outcome=\"sent\"}} {batches}\n"
            ));
            out.push_str(&format!(
                "edgeguard_logship_batches_total{{outcome=\"failed\"}} {failed}\n"
            ));
        }

        // Span shipping. Same reasoning as the log shipper's counters: a trace pipeline that drops
        // silently reads, at the destination, as an absence of traffic.
        if let Some(sh) = self.span_shipper.get() {
            let st = sh.stats();
            let sent = st.sent.load(Ordering::Relaxed);
            let dq = st.dropped_queue_full.load(Ordering::Relaxed);
            let df = st.dropped_send_failed.load(Ordering::Relaxed);
            out.push_str(
                "# HELP edgeguard_spans_sent_total Request spans delivered to the trace collector.\n\
                 # TYPE edgeguard_spans_sent_total counter\n",
            );
            out.push_str(&format!("edgeguard_spans_sent_total {sent}\n"));
            out.push_str(
                "# HELP edgeguard_spans_dropped_total Request spans dropped, by reason.\n\
                 # TYPE edgeguard_spans_dropped_total counter\n",
            );
            out.push_str(&format!(
                "edgeguard_spans_dropped_total{{reason=\"queue_full\"}} {dq}\n"
            ));
            out.push_str(&format!(
                "edgeguard_spans_dropped_total{{reason=\"send_failed\"}} {df}\n"
            ));
        }

        out.push_str(
            "# HELP edgeguard_request_duration_seconds Request handling latency in seconds.\n",
        );
        out.push_str("# TYPE edgeguard_request_duration_seconds histogram\n");
        for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
            let v = self.latency_buckets[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "edgeguard_request_duration_seconds_bucket{{le=\"{bound}\"}} {v}\n"
            ));
        }
        let count = self.latency_count.load(Ordering::Relaxed);
        // The `+Inf` bucket equals the total observation count by definition.
        out.push_str(&format!(
            "edgeguard_request_duration_seconds_bucket{{le=\"+Inf\"}} {count}\n"
        ));
        let sum_secs = self.latency_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        out.push_str(&format!(
            "edgeguard_request_duration_seconds_sum {sum_secs}\n"
        ));
        out.push_str(&format!(
            "edgeguard_request_duration_seconds_count {count}\n"
        ));

        // Streamed-LLM server-side latency: time-to-first-token and mean time-per-output-token,
        // measured in the request path (the signal a trace backend can't produce). Render at 0 too.
        render_hist(
            &mut out,
            "edgeguard_llm_ttft_seconds",
            "Server-side time-to-first-token for streamed LLM responses, in seconds.",
            &self.llm_ttft_buckets,
            &self.llm_ttft_sum_micros,
            &self.llm_ttft_count,
        );
        render_hist(
            &mut out,
            "edgeguard_llm_tpot_seconds",
            "Mean time-per-output-token for streamed LLM responses (>1 output token), in seconds.",
            &self.llm_tpot_buckets,
            &self.llm_tpot_sum_micros,
            &self.llm_tpot_count,
        );

        // LLM token metering (gateway L0). All series render even at 0 so dashboards/alerts don't
        // break on a quiet proxy.
        out.push_str("# HELP edgeguard_llm_tokens_total LLM tokens metered, by direction.\n");
        out.push_str("# TYPE edgeguard_llm_tokens_total counter\n");
        out.push_str(&format!(
            "edgeguard_llm_tokens_total{{direction=\"input\"}} {}\n",
            self.llm_tokens_in.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "edgeguard_llm_tokens_total{{direction=\"output\"}} {}\n",
            self.llm_tokens_out.load(Ordering::Relaxed)
        ));

        // Cached / reasoning sub-dimensions (⊆ input / ⊆ output). Kept as their own metric so they
        // are visible for the "~7× undercount" story without being double-summed into the direction
        // totals above.
        out.push_str(
            "# HELP edgeguard_llm_cached_tokens_total Cached prompt tokens metered (subset of input).\n",
        );
        out.push_str("# TYPE edgeguard_llm_cached_tokens_total counter\n");
        out.push_str(&format!(
            "edgeguard_llm_cached_tokens_total {}\n",
            self.llm_cached_tokens.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP edgeguard_llm_reasoning_tokens_total Reasoning completion tokens metered (subset of output).\n",
        );
        out.push_str("# TYPE edgeguard_llm_reasoning_tokens_total counter\n");
        out.push_str(&format!(
            "edgeguard_llm_reasoning_tokens_total {}\n",
            self.llm_reasoning_tokens.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP edgeguard_llm_cost_microdollars_total Accumulated LLM cost in micro-dollars (1e-6 USD).\n",
        );
        out.push_str("# TYPE edgeguard_llm_cost_microdollars_total counter\n");
        out.push_str(&format!(
            "edgeguard_llm_cost_microdollars_total {}\n",
            self.llm_cost_micros.load(Ordering::Relaxed)
        ));

        // Per-model breakdown (bounded cardinality). Tokens carry a `kind` label; cost is a separate
        // series. Rendered only for models actually seen, so a fresh proxy emits nothing here.
        {
            let map = self.per_model.lock().expect("per_model mutex poisoned");
            render_breakdown(&mut out, "edgeguard_llm_model", "model", "model", &map);
        }

        // Per-team token/cost breakdown (`edgeguard_llm_team_*`), for chargeback/showback. Same
        // cardinality bound as per-model; rendered only for teams actually seen.
        {
            let map = self.per_team.lock().expect("per_team mutex poisoned");
            render_breakdown(&mut out, "edgeguard_llm_team", "team", "team", &map);
        }

        // Per-key (per-principal) token/cost breakdown (`edgeguard_llm_key_*`), for per-user FinOps.
        // Same cardinality bound as per-model; rendered only for keys actually seen.
        {
            let map = self.per_key.lock().expect("per_key mutex poisoned");
            render_breakdown(
                &mut out,
                "edgeguard_llm_key",
                "key",
                "authenticated key/principal",
                &map,
            );
        }

        // Hard-budget signals (gateway L1): the near-limit gauge and per-scope block counter.
        out.push_str(
            "# HELP edgeguard_llm_budget_blocked_total Requests blocked by a hard LLM budget, by scope.\n",
        );
        out.push_str("# TYPE edgeguard_llm_budget_blocked_total counter\n");
        for (i, label) in BUDGET_SCOPES.iter().enumerate() {
            let v = self.budget_blocked[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "edgeguard_llm_budget_blocked_total{{scope=\"{label}\"}} {v}\n"
            ));
        }
        {
            let map = self
                .budget_consumed
                .lock()
                .expect("budget_consumed mutex poisoned");
            out.push_str(
                "# HELP edgeguard_llm_budget_consumed_ratio Latest consumed ratio (used/limit) per budget.\n",
            );
            out.push_str("# TYPE edgeguard_llm_budget_consumed_ratio gauge\n");
            for (name, ratio) in map.iter() {
                out.push_str(&format!(
                    "edgeguard_llm_budget_consumed_ratio{{budget=\"{}\"}} {ratio}\n",
                    escape_label(name)
                ));
            }
        }
        out.push_str(
            "# HELP edgeguard_llm_budget_reconcile_failures_total Budget reserve->settle reconciles that failed against the shared store (counter drift).\n",
        );
        out.push_str("# TYPE edgeguard_llm_budget_reconcile_failures_total counter\n");
        out.push_str(&format!(
            "edgeguard_llm_budget_reconcile_failures_total {}\n",
            self.budget_reconcile_failures.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP edgeguard_llm_requests_total LLM requests metered, by result.\n");
        out.push_str("# TYPE edgeguard_llm_requests_total counter\n");
        for (i, label) in LLM_RESULTS.iter().enumerate() {
            let v = self.llm_results[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "edgeguard_llm_requests_total{{result=\"{label}\"}} {v}\n"
            ));
        }

        out.push_str(
            "# HELP edgeguard_llm_keyvault_total Key-vault decisions by result (swap / egress denial).\n",
        );
        out.push_str("# TYPE edgeguard_llm_keyvault_total counter\n");
        for (i, label) in KEYVAULT_RESULTS.iter().enumerate() {
            let v = self.keyvault_results[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "edgeguard_llm_keyvault_total{{result=\"{label}\"}} {v}\n"
            ));
        }

        out.push_str(
            "# HELP edgeguard_llm_dlp_findings_total DLP findings (PII / secrets) by category.\n",
        );
        out.push_str("# TYPE edgeguard_llm_dlp_findings_total counter\n");
        for (i, label) in DLP_CATEGORIES.iter().enumerate() {
            let v = self.dlp_findings[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "edgeguard_llm_dlp_findings_total{{category=\"{label}\"}} {v}\n"
            ));
        }
        out.push_str(
            "# HELP edgeguard_llm_dlp_blocked_total Requests blocked by DLP block mode.\n",
        );
        out.push_str("# TYPE edgeguard_llm_dlp_blocked_total counter\n");
        out.push_str(&format!(
            "edgeguard_llm_dlp_blocked_total {}\n",
            self.dlp_blocked.load(Ordering::Relaxed)
        ));

        self.render_certs(&mut out);
        if self.trusted_header.get().is_some() {
            out.push_str(
                "# HELP edgeguard_client_cert_header_total Requests carrying \
                 [trusted_client_cert_header], by what became of it: accepted, untrusted_peer \
                 (dropped: not from trusted_proxies or trusted_proxy_names), invalid, unverified (refused by its ca_path).\n\
                 # TYPE edgeguard_client_cert_header_total counter\n",
            );
            for (i, result) in crate::client_cert_header::HeaderResult::ALL
                .iter()
                .enumerate()
            {
                out.push_str(&format!(
                    "edgeguard_client_cert_header_total{{result=\"{}\"}} {}\n",
                    result.label(),
                    self.client_cert_header[i].load(Ordering::Relaxed)
                ));
            }
        }

        // With `trust_forwarded_for` (in the current runtime), or once anything was counted, so a
        // reload that turns it off does not hide what was seen.
        let trusts_xff = self
            .runtime
            .get()
            .is_some_and(|rt| rt.load().cfg.server.trust_forwarded_for);
        let counts: [u64; 5] =
            std::array::from_fn(|i| self.forwarded_for[i].load(Ordering::Relaxed));
        if trusts_xff || counts.iter().any(|c| *c > 0) {
            out.push_str(
                "# HELP edgeguard_forwarded_for_total Requests by how X-Forwarded-For named the \
                 client, with server.trust_forwarded_for: used (the entry server.forwarded_hops \
                 from the right), or the TCP peer instead: absent, short (fewer entries than \
                 forwarded_hops), invalid (the entry is not an address), untrusted_peer (from a \
                 peer outside server.trusted_forwarders: ignored).\n\
                 # TYPE edgeguard_forwarded_for_total counter\n",
            );
            for (result, v) in crate::proxy::ForwardedFor::ALL.iter().zip(counts) {
                out.push_str(&format!(
                    "edgeguard_forwarded_for_total{{result=\"{}\"}} {v}\n",
                    result.label()
                ));
            }
        }

        self.render_routes(&mut out);
        self.render_consumers(&mut out);
        self.render_upstreams(&mut out);
        if let Some(runtime) = self.runtime.get() {
            crate::pool::render(&mut out, runtime.load().pools());
        }
        render_hist_in(
            &mut out,
            "edgeguard_edge_overhead_seconds",
            "Time the edge added to a proxied request the upstream answered: from receiving it to \
             sending the response headers, less the time spent waiting on the upstream (its headers \
             and, for a buffered response, its body).",
            OVERHEAD_BUCKETS,
            &self.overhead_buckets,
            &self.overhead_sum_micros,
            &self.overhead_count,
        );
        out
    }

    /// Every certificate the edge serves, presents or trusts, in the certificate series (see
    /// [`crate::certstore::render_cert_series`]), and the CRLs' `nextUpdate`.
    fn render_certs(&self, out: &mut String) {
        let clients: Vec<(String, std::sync::Arc<crate::certstore::CertStore>)> = self
            .client_certs()
            .into_iter()
            .map(|c| (format!("client:{}", c.store.cert_path()), c.store))
            .collect();
        // The listener's client-auth CAs, and the ones the forwarded-certificate header is verified
        // against: the same kind of dependency, told apart by prefix.
        let trusts: Vec<(&str, std::sync::Arc<crate::client_auth::TrustInfo>)> = self
            .client_auth
            .get()
            .map(|a| ("client-ca", a.trust()))
            .into_iter()
            .chain(
                self.trusted_header
                    .get()
                    .and_then(|h| h.verifier())
                    .map(|v| ("header-ca", v.trust())),
            )
            .collect();
        let cas: Vec<(String, crate::certstore::CertInfo)> = trusts
            .iter()
            .flat_map(|(prefix, t)| t.cas.iter().map(move |ca| (prefix, ca)))
            .map(|(prefix, ca)| (format!("{prefix}:{}", ca.name), ca.info.clone()))
            .collect();
        crate::certstore::render_cert_series(
            out,
            self.cert_store.get().map(|s| &**s),
            self.sni_certs(),
            &clients,
            &cas,
        );
        // A CRL past its nextUpdate goes on being used, so revocations published since are not
        // applied: this is the series to alert on (`EdgeGuardCrlStale`).
        // One series per file, though both may name the same one.
        let mut crls: Vec<(&str, i64)> = trusts
            .iter()
            .flat_map(|(_, t)| t.crls.iter())
            .filter_map(|c| Some((c.name.as_str(), c.info.next_update?)))
            .collect();
        crls.sort();
        crls.dedup_by(|a, b| a.0 == b.0);
        if !crls.is_empty() {
            out.push_str(
                "# HELP edgeguard_tls_crl_next_update_seconds When each CRL in \
                 tls.client_auth.crl_paths says the next one is due (unix seconds).\n\
                 # TYPE edgeguard_tls_crl_next_update_seconds gauge\n",
            );
            for (name, next) in crls {
                out.push_str(&format!(
                    "edgeguard_tls_crl_next_update_seconds{{crl=\"{}\"}} {next}\n",
                    escape_label(name)
                ));
            }
        }
    }

    /// Per-upstream series. Every result is written, zeros included, for each upstream that has
    /// been sent a request, so an error ratio has a denominator and a numerator from the start.
    fn render_upstreams(&self, out: &mut String) {
        let upstreams = self.upstreams.load();
        if upstreams.is_empty() {
            return;
        }
        out.push_str(
            "# HELP edgeguard_upstream_requests_total Requests forwarded to each upstream              (scheme://host:port), by how the exchange ended: ok, http_5xx, connect_error,              tls_error, timeout, reset or error.\n\
             # TYPE edgeguard_upstream_requests_total counter\n",
        );
        for (upstream, stats) in upstreams.iter() {
            let upstream = escape_label(upstream);
            for (i, result) in UpstreamResult::ALL.iter().enumerate() {
                let v = stats.results[i].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "edgeguard_upstream_requests_total{{upstream=\"{upstream}\",result=\"{}\"}} {v}\n",
                    result.label()
                ));
            }
        }
        out.push_str(
            "# HELP edgeguard_upstream_duration_seconds Time from sending the request to the \
             upstream's response headers, for exchanges that got them.\n\
             # TYPE edgeguard_upstream_duration_seconds histogram\n",
        );
        for (upstream, stats) in upstreams.iter() {
            let upstream = escape_label(upstream);
            let name = "edgeguard_upstream_duration_seconds";
            for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
                let v = stats.buckets[i].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "{name}_bucket{{upstream=\"{upstream}\",le=\"{bound}\"}} {v}\n"
                ));
            }
            let c = stats.count.load(Ordering::Relaxed);
            let sum = stats.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            out.push_str(&format!(
                "{name}_bucket{{upstream=\"{upstream}\",le=\"+Inf\"}} {c}\n\
                 {name}_sum{{upstream=\"{upstream}\"}} {sum}\n\
                 {name}_count{{upstream=\"{upstream}\"}} {c}\n"
            ));
        }
    }

    /// Per-route series. Only routes that have seen a request are present, and within one only the
    /// method and status-class pairs that have occurred, so an idle route costs nothing.
    fn render_routes(&self, out: &mut String) {
        let routes = self.routes.load();
        if routes.is_empty() {
            return;
        }
        out.push_str(
            "# HELP edgeguard_route_requests_total Proxied requests by route (its configured name \
             or prefix, `default` for the rest), method and status class.\n\
             # TYPE edgeguard_route_requests_total counter\n",
        );
        for (route, stats) in routes.iter() {
            let route = escape_label(route);
            for (m, method) in ROUTE_METHODS.iter().enumerate() {
                for (s, class) in STATUS_CLASSES.iter().enumerate() {
                    let v = stats.requests[m * STATUS_CLASSES.len() + s].load(Ordering::Relaxed);
                    if v > 0 {
                        out.push_str(&format!(
                            "edgeguard_route_requests_total{{route=\"{route}\",method=\"{method}\",status_class=\"{class}\"}} {v}\n"
                        ));
                    }
                }
            }
        }
        out.push_str(
            "# HELP edgeguard_route_request_duration_seconds Time to response headers, by route.\n\
             # TYPE edgeguard_route_request_duration_seconds histogram\n",
        );
        for (route, stats) in routes.iter() {
            let route = escape_label(route);
            let name = "edgeguard_route_request_duration_seconds";
            for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
                let v = stats.buckets[i].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "{name}_bucket{{route=\"{route}\",le=\"{bound}\"}} {v}\n"
                ));
            }
            let c = stats.count.load(Ordering::Relaxed);
            let sum = stats.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            out.push_str(&format!(
                "{name}_bucket{{route=\"{route}\",le=\"+Inf\"}} {c}\n\
                 {name}_sum{{route=\"{route}\"}} {sum}\n\
                 {name}_count{{route=\"{route}\"}} {c}\n"
            ));
        }
    }

    /// Per-consumer series: `_anon` for requests with no authenticated principal, `_over_cap`
    /// for consumers past `metrics.consumer_series_max`.
    fn render_consumers(&self, out: &mut String) {
        let consumers = self.consumers.load();
        if consumers.is_empty() {
            return;
        }
        out.push_str(
            "# HELP edgeguard_consumer_requests_total Requests by consumer (the authenticated \
             principal; _anon without one) and status class.\n\
             # TYPE edgeguard_consumer_requests_total counter\n",
        );
        for (consumer, stats) in consumers.iter() {
            let consumer = escape_label(consumer);
            for (s, class) in STATUS_CLASSES.iter().enumerate() {
                let v = stats.requests[s].load(Ordering::Relaxed);
                if v > 0 {
                    out.push_str(&format!(
                        "edgeguard_consumer_requests_total{{consumer=\"{consumer}\",status_class=\"{class}\"}} {v}\n"
                    ));
                }
            }
        }
        out.push_str(
            "# HELP edgeguard_consumer_bytes_total Bytes proxied by consumer: in = request, out = \
             response, headers included.\n\
             # TYPE edgeguard_consumer_bytes_total counter\n",
        );
        for (consumer, stats) in consumers.iter() {
            let consumer = escape_label(consumer);
            out.push_str(&format!(
                "edgeguard_consumer_bytes_total{{consumer=\"{consumer}\",direction=\"in\"}} {}\n\
                 edgeguard_consumer_bytes_total{{consumer=\"{consumer}\",direction=\"out\"}} {}\n",
                stats.bytes_in.load(Ordering::Relaxed),
                stats.bytes_out.load(Ordering::Relaxed)
            ));
        }
    }
}

/// Escape a dynamic label *value* for the Prometheus text format: backslash, double-quote, and
/// newline must be escaped (per the exposition spec) so a client-chosen `model` or operator-chosen
/// budget name can't inject a line break or unbalanced quote into the output.
pub(crate) fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_series_render_every_result_once_an_upstream_is_used() {
        let m = Metrics::new();
        assert!(!m.render().contains("edgeguard_upstream_"));
        let up = m.upstream_stats("http://api.internal:8080");
        up.record(UpstreamResult::Ok);
        up.record(UpstreamResult::ConnectError);
        up.observe_headers(Duration::from_millis(30));
        assert!(std::sync::Arc::ptr_eq(
            &up,
            &m.upstream_stats("http://api.internal:8080")
        ));
        let text = m.render();
        let label = "upstream=\"http://api.internal:8080\"";
        for (result, v) in [
            ("ok", 1),
            ("http_5xx", 0),
            ("connect_error", 1),
            ("tls_error", 0),
            ("timeout", 0),
            ("reset", 0),
            ("error", 0),
        ] {
            let line =
                format!("edgeguard_upstream_requests_total{{{label},result=\"{result}\"}} {v}");
            assert!(text.contains(&line), "{line}\n{text}");
        }
        assert!(text.contains(&format!(
            "edgeguard_upstream_duration_seconds_count{{{label}}} 1"
        )));
        assert!(text.contains(&format!(
            "edgeguard_upstream_duration_seconds_bucket{{{label},le=\"0.05\"}} 1"
        )));
    }

    #[test]
    fn listener_connection_series_render_once_a_listener_registers() {
        let m = Metrics::new();
        assert!(
            !m.render().contains("edgeguard_connections_open"),
            "no listener, no connection series"
        );
        let public = m.listener_stats("public");
        // The same name hands back the same counts rather than a second series.
        assert!(std::sync::Arc::ptr_eq(&public, &m.listener_stats("public")));
        m.listener_stats("admin");
        let text = m.render();
        assert!(
            text.contains("# TYPE edgeguard_connections_open gauge"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_connections_open{listener=\"public\"} 0"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_connections_open{listener=\"admin\"} 0"),
            "{text}"
        );
        assert!(
            text.contains("# TYPE edgeguard_connections_rejected_total counter"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_connections_rejected_total{listener=\"public\"} 0"),
            "{text}"
        );
        assert!(
            text.contains("# TYPE edgeguard_requests_in_flight gauge"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_requests_in_flight{listener=\"admin\"} 0"),
            "{text}"
        );
        assert!(
            !text.contains("edgeguard_tls_handshakes_total"),
            "only for TLS listeners: {text}"
        );
    }

    #[test]
    fn route_series_fold_unknown_methods_and_render_only_what_occurred() {
        let m = Metrics::new();
        assert!(!m.render().contains("edgeguard_route_requests_total"));
        let api = m.route_stats("api");
        api.record("GET", 200, Duration::from_millis(3));
        api.record("GET", 204, Duration::from_millis(3));
        api.record("BREW", 503, Duration::from_millis(30));
        m.route_stats("we\"ird")
            .record("POST", 404, Duration::from_millis(1));
        let text = m.render();
        assert!(
            text.contains(
                "edgeguard_route_requests_total{route=\"api\",method=\"GET\",status_class=\"2xx\"} 2"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "edgeguard_route_requests_total{route=\"api\",method=\"OTHER\",status_class=\"5xx\"} 1"
            ),
            "a client-chosen method is not a label value: {text}"
        );
        assert!(
            !text.contains("method=\"GET\",status_class=\"4xx\""),
            "no zero series"
        );
        assert!(
            text.contains("route=\"we\\\"ird\""),
            "labels are escaped: {text}"
        );
        assert!(text.contains("edgeguard_route_request_duration_seconds_count{route=\"api\"} 3"));
        // The same route hands back the same counters.
        assert!(std::sync::Arc::ptr_eq(&api, &m.route_stats("api")));
    }

    #[test]
    fn consumers_past_the_cap_share_one_series_and_zero_turns_them_off() {
        let m = Metrics::new();
        m.set_consumer_series_max(2);
        for who in ["alice", "bob", "carol", "dave"] {
            m.consumer_stats(Some(who)).unwrap().record(200);
        }
        m.consumer_stats(None).unwrap().record(401);
        let text = m.render();
        for line in [
            "edgeguard_consumer_requests_total{consumer=\"alice\",status_class=\"2xx\"} 1",
            "edgeguard_consumer_requests_total{consumer=\"bob\",status_class=\"2xx\"} 1",
            "edgeguard_consumer_requests_total{consumer=\"_over_cap\",status_class=\"2xx\"} 2",
            "edgeguard_consumer_requests_total{consumer=\"_anon\",status_class=\"4xx\"} 1",
        ] {
            assert!(text.contains(line), "{line} in {text}");
        }
        assert!(!text.contains("carol"));
        // A consumer already counted keeps its own series.
        assert!(std::sync::Arc::ptr_eq(
            &m.consumer_stats(Some("alice")).unwrap(),
            &m.consumer_stats(Some("alice")).unwrap()
        ));

        let off = Metrics::new();
        off.set_consumer_series_max(0);
        assert!(off.consumer_stats(Some("alice")).is_none());
        assert!(off.consumer_stats(None).is_none());
        assert!(!off.render().contains("edgeguard_consumer_"));
    }

    #[test]
    fn records_and_renders_request_outcomes() {
        let m = Metrics::new();
        m.record_request("ok");
        m.record_request("ok");
        m.record_request("rate_limited");
        // An unknown outcome falls into the `other` bucket, not "ok".
        m.record_request("totally_unknown");

        let text = m.render();
        assert!(
            text.contains("edgeguard_requests_total{outcome=\"ok\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_requests_total{outcome=\"rate_limited\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_requests_total{outcome=\"other\"} 1"),
            "{text}"
        );
    }

    #[test]
    fn latency_histogram_is_cumulative() {
        let m = Metrics::new();
        m.observe_latency(Duration::from_millis(3)); // <= 0.005
        m.observe_latency(Duration::from_millis(40)); // <= 0.05
        let text = m.render();
        // 3ms falls under every bucket >= 0.005; 40ms under every bucket >= 0.05.
        assert!(
            text.contains("edgeguard_request_duration_seconds_bucket{le=\"0.005\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_request_duration_seconds_bucket{le=\"0.05\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_request_duration_seconds_bucket{le=\"+Inf\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_request_duration_seconds_count 2"),
            "{text}"
        );
    }

    #[test]
    fn llm_ttft_tpot_histograms_render() {
        let m = Metrics::new();
        // TTFT 40ms (<= 0.05), TPOT 8ms (<= 0.01).
        m.record_llm_latency(Duration::from_millis(40), Some(Duration::from_millis(8)));
        // A single-output-token response has no defined TPOT — only TTFT is recorded.
        m.record_llm_latency(Duration::from_millis(3), None);
        let text = m.render();
        // Two TTFT observations; both <= 0.05, one <= 0.005.
        assert!(
            text.contains("edgeguard_llm_ttft_seconds_bucket{le=\"0.005\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_ttft_seconds_bucket{le=\"0.05\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_ttft_seconds_count 2"),
            "{text}"
        );
        // One TPOT observation (8ms), recorded only for the >1-token response.
        assert!(
            text.contains("edgeguard_llm_tpot_seconds_bucket{le=\"0.01\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_tpot_seconds_count 1"),
            "{text}"
        );
    }

    #[test]
    fn ratelimit_and_csp_counters() {
        let m = Metrics::new();
        m.record_ratelimit_hit("ip");
        m.record_ratelimit_hit("route");
        m.record_ratelimit_hit("route");
        m.record_csp_report();
        let text = m.render();
        assert!(
            text.contains("edgeguard_ratelimit_hits_total{scope=\"ip\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_ratelimit_hits_total{scope=\"route\"} 2"),
            "{text}"
        );
        assert!(text.contains("edgeguard_csp_reports_total 1"), "{text}");
    }

    #[test]
    fn usage_accumulates_drains_and_restores() {
        let m = Metrics::new();
        m.add_usage_request("ok"); // proxied — not blocked
        m.add_usage_request("forbidden"); // edge-denied — also counts toward `blocked`
        m.add_usage_bytes(100, 250);
        m.add_usage_bytes(0, 50);
        // LLM token usage also drains for the cost report (gateway L4).
        m.record_llm_usage(
            "gpt-4o",
            LlmSample {
                tokens_in: 1_000,
                tokens_out: 400,
                cost_micros: Some(2_500),
                ..Default::default()
            },
        );
        // Drain returns the accrued delta and zeroes the accumulator.
        let drained = m.drain_usage();
        assert_eq!(drained.requests, 2);
        assert_eq!(drained.blocked, 1); // only the "forbidden" request
        assert_eq!(drained.ingress_bytes, 100);
        assert_eq!(drained.egress_bytes, 300);
        assert_eq!(drained.tokens_in, 1_000);
        assert_eq!(drained.tokens_out, 400);
        assert_eq!(drained.cost_micros, 2_500);
        assert!(m.drain_usage().is_empty());
        // Restore (failed-report path) re-adds it for the next period.
        m.restore_usage(&drained);
        assert_eq!(m.drain_usage(), drained);
    }

    #[test]
    fn llm_token_and_cost_counters() {
        let m = Metrics::new();
        // Priced model: tokens + cost, bucketed `metered`. Includes cached/reasoning sub-dims.
        m.record_llm_usage(
            "gpt-4o",
            LlmSample {
                tokens_in: 100,
                tokens_out: 50,
                cached_tokens: 40,
                reasoning_tokens: 20,
                cost_micros: Some(1_250),
            },
        );
        // Unpriced model: tokens counted, no cost, bucketed `unpriced`.
        m.record_llm_usage(
            "mystery",
            LlmSample {
                tokens_in: 10,
                tokens_out: 5,
                cost_micros: None,
                ..Default::default()
            },
        );
        // No usage reported.
        m.record_llm_no_usage();
        let text = m.render();
        assert!(
            text.contains("edgeguard_llm_tokens_total{direction=\"input\"} 110"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_tokens_total{direction=\"output\"} 55"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_cached_tokens_total 40"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_reasoning_tokens_total 20"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_cost_microdollars_total 1250"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_requests_total{result=\"metered\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_requests_total{result=\"unpriced\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_requests_total{result=\"no_usage\"} 1"),
            "{text}"
        );
        // Per-model breakdown carries the model + kind labels and the priced model's cost.
        assert!(
            text.contains("edgeguard_llm_model_tokens_total{model=\"gpt-4o\",kind=\"cached\"} 40"),
            "{text}"
        );
        assert!(
            text.contains(
                "edgeguard_llm_model_tokens_total{model=\"gpt-4o\",kind=\"reasoning\"} 20"
            ),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_model_cost_microdollars_total{model=\"gpt-4o\"} 1250"),
            "{text}"
        );
    }

    #[test]
    fn per_team_tokens_and_cost_are_accumulated_and_rendered() {
        let m = Metrics::new();
        m.record_llm_team_usage(
            "acme",
            &LlmSample {
                tokens_in: 100,
                tokens_out: 40,
                cached_tokens: 30,
                reasoning_tokens: 10,
                cost_micros: Some(77),
            },
        );
        m.record_llm_team_usage(
            "acme",
            &LlmSample {
                tokens_in: 50,
                tokens_out: 20,
                cost_micros: Some(23),
                ..Default::default()
            },
        );
        // A request with no team falls into the shared `_none` bucket.
        m.record_llm_team_usage(
            "_none",
            &LlmSample {
                tokens_in: 5,
                ..Default::default()
            },
        );
        let text = m.render();
        assert!(
            text.contains("edgeguard_llm_team_tokens_total{team=\"acme\",kind=\"input\"} 150"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_team_tokens_total{team=\"acme\",kind=\"output\"} 60"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_team_cost_microdollars_total{team=\"acme\"} 100"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_team_tokens_total{team=\"_none\",kind=\"input\"} 5"),
            "{text}"
        );
    }

    #[test]
    fn budget_reconcile_failures_counter_renders() {
        let m = Metrics::new();
        m.record_budget_reconcile_failures(0); // a zero is a no-op
        m.record_budget_reconcile_failures(2);
        m.record_budget_reconcile_failures(1);
        assert!(
            m.render()
                .contains("edgeguard_llm_budget_reconcile_failures_total 3"),
            "{}",
            m.render()
        );
    }

    #[test]
    fn per_key_tokens_and_cost_are_accumulated_and_rendered() {
        let m = Metrics::new();
        m.record_llm_key_usage(
            "key-abc",
            &LlmSample {
                tokens_in: 100,
                tokens_out: 40,
                cost_micros: Some(77),
                ..Default::default()
            },
        );
        // An unauthenticated request falls into the shared `_anon` bucket.
        m.record_llm_key_usage(
            "_anon",
            &LlmSample {
                tokens_in: 5,
                ..Default::default()
            },
        );
        let text = m.render();
        assert!(
            text.contains("edgeguard_llm_key_tokens_total{key=\"key-abc\",kind=\"input\"} 100"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_key_cost_microdollars_total{key=\"key-abc\"} 77"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_key_tokens_total{key=\"_anon\",kind=\"input\"} 5"),
            "{text}"
        );
    }

    #[test]
    fn per_model_series_are_cardinality_bounded() {
        let m = Metrics::new();
        // Feed more distinct models than the cap; the overflow bucket absorbs the excess so the map
        // never grows past MAX_LLM_MODEL_SERIES + 1 (the overflow key).
        for i in 0..(MAX_LLM_MODEL_SERIES + 50) {
            m.record_llm_usage(
                &format!("model-{i}"),
                LlmSample {
                    tokens_in: 1,
                    ..Default::default()
                },
            );
        }
        let map = m.per_model.lock().unwrap();
        assert!(map.len() <= MAX_LLM_MODEL_SERIES + 1, "len={}", map.len());
        assert!(map.contains_key(LLM_MODEL_OVERFLOW));
    }

    #[test]
    fn budget_blocked_and_consumed_metrics() {
        let m = Metrics::new();
        m.record_budget_blocked("key");
        m.record_budget_blocked("key");
        m.record_budget_blocked("team");
        m.record_budget_blocked("totally_unknown"); // -> "other"
        m.record_budget_consumed("daily-cap", 0.75);
        m.record_budget_consumed("daily-cap", 0.92); // last writer wins
        m.record_budget_consumed("nan-guard", f64::NAN); // dropped
        let text = m.render();
        assert!(
            text.contains("edgeguard_llm_budget_blocked_total{scope=\"key\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_budget_blocked_total{scope=\"team\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_budget_blocked_total{scope=\"other\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_budget_consumed_ratio{budget=\"daily-cap\"} 0.92"),
            "{text}"
        );
        assert!(
            !text.contains("nan-guard"),
            "NaN sample must be dropped: {text}"
        );
    }

    #[test]
    fn label_values_are_escaped() {
        // A client-chosen model with a quote/newline must not break the exposition format.
        let m = Metrics::new();
        m.record_llm_usage(
            "evil\"\nmodel",
            LlmSample {
                tokens_in: 1,
                ..Default::default()
            },
        );
        let text = m.render();
        assert!(text.contains("model=\"evil\\\"\\nmodel\""), "{text}");
    }

    #[test]
    fn dlp_finding_and_blocked_counters() {
        let m = Metrics::new();
        m.record_dlp_finding("email");
        m.record_dlp_finding("email");
        m.record_dlp_finding("api_key");
        m.record_dlp_finding("totally_unknown"); // -> "other"
        m.record_dlp_blocked();
        let text = m.render();
        assert!(
            text.contains("edgeguard_llm_dlp_findings_total{category=\"email\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_dlp_findings_total{category=\"api_key\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_dlp_findings_total{category=\"other\"} 1"),
            "{text}"
        );
        assert!(text.contains("edgeguard_llm_dlp_blocked_total 1"), "{text}");
    }

    #[test]
    fn keyvault_result_counters() {
        let m = Metrics::new();
        m.record_keyvault("swapped");
        m.record_keyvault("swapped");
        m.record_keyvault("denied_model");
        m.record_keyvault("totally_unknown"); // ignored, not miscounted
        let text = m.render();
        assert!(
            text.contains("edgeguard_llm_keyvault_total{result=\"swapped\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_keyvault_total{result=\"denied_model\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_llm_keyvault_total{result=\"denied_key\"} 0"),
            "{text}"
        );
    }

    #[test]
    fn waf_hit_counters_by_class() {
        let m = Metrics::new();
        m.record_waf_hit("sqli");
        m.record_waf_hit("sqli");
        m.record_waf_hit("custom");
        // An unknown class is ignored rather than miscounted.
        m.record_waf_hit("totally_unknown");
        let text = m.render();
        assert!(
            text.contains("edgeguard_waf_hits_total{rule=\"sqli\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("edgeguard_waf_hits_total{rule=\"custom\"} 1"),
            "{text}"
        );
        // A class that never fired still renders at 0.
        assert!(
            text.contains("edgeguard_waf_hits_total{rule=\"xss\"} 0"),
            "{text}"
        );
    }
}
