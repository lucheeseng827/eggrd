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
const BUDGET_SCOPES: &[&str] = &["global", "key", "model", "team", "other"];

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
    /// signal (Phoenix declined to build first-class TTFT; Langfuse approximates from a client clock).
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
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            requests: OUTCOMES.iter().map(|_| AtomicU64::new(0)).collect(),
            ratelimit_hits: RL_SCOPES.iter().map(|_| AtomicU64::new(0)).collect(),
            waf_hits: WAF_RULES.iter().map(|_| AtomicU64::new(0)).collect(),
            latency_buckets: LATENCY_BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            latency_sum_micros: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            csp_reports: AtomicU64::new(0),
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
    let secs = elapsed.as_secs_f64();
    for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
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
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} histogram\n"));
    for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
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

    /// Count one finished request under its `outcome` label.
    pub fn record_request(&self, outcome: &str) {
        let idx = OUTCOMES
            .iter()
            .position(|o| *o == outcome)
            .unwrap_or(OUTCOMES.len() - 1); // -> "other"
        self.requests[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Observe a request's end-to-end latency into the histogram.
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

        out
    }
}

/// Escape a dynamic label *value* for the Prometheus text format: backslash, double-quote, and
/// newline must be escaped (per the exposition spec) so a client-chosen `model` or operator-chosen
/// budget name can't inject a line break or unbalanced quote into the output.
fn escape_label(s: &str) -> String {
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
