//! Prometheus metrics, hand-rolled.
//!
//! A full metrics library (`prometheus`, `metrics`) would be a heavy dependency for the
//! handful of series EdgeGuard exposes, so — in the same spirit as `parse_host_port` being a
//! small URL parser rather than a full one — this is a minimal text-exposition renderer over
//! a few atomics. It emits the Prometheus text format (v0.0.4) at `/__edgeguard/metrics`.
//!
//! The registry lives in [`crate::proxy::AppState`] *outside* the hot-swappable runtime, so
//! counters survive a config hot-reload instead of resetting to zero.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Request `outcome` label values. These mirror the `outcome` field already emitted on the
/// JSON access log in [`crate::proxy`], so a metric series lines up 1:1 with a log line.
/// Anything not in this list is bucketed under `other` rather than silently dropped.
const OUTCOMES: &[&str] = &[
    "ok",
    "rate_limited",
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

/// Rate-limit `scope` label values (which limiter rejected the request).
const RL_SCOPES: &[&str] = &["ip", "route", "key"];

/// WAF `rule` label values (which ruleset class matched). Custom `[[waf.rules]]` all roll up
/// under `custom`; the specific rule id is in the log line, not the metric.
const WAF_RULES: &[&str] = &["sqli", "xss", "path_traversal", "custom"];

/// Upper bounds (seconds) for the request-duration histogram, plus an implicit `+Inf`.
const LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

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
        }
    }
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
        let secs = elapsed.as_secs_f64();
        for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
            if secs <= *bound {
                self.latency_buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.latency_sum_micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
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
        }
    }

    /// Count one received CSP violation report.
    pub fn record_csp_report(&self) {
        self.csp_reports.fetch_add(1, Ordering::Relaxed);
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

        out
    }
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
