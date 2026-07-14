//! Outbound alerting (gateway L4) — threshold/regression alerts to Slack/webhook, in your own VPC.
//!
//! When `[alerts]` is enabled, EdgeGuard fires a Slack-compatible alert (`{ "text": … }`) when a
//! hard-budget's consumed ratio crosses a threshold — cost-regression alerting with **no SaaS
//! alerting plane** (the confirmed Phoenix gap: alerting gated behind the paid Arize AX cloud; teams
//! otherwise pipe to Datadog/Grafana). Fire-and-forget: a background POST that never blocks or fails
//! the request. **Edge-triggered**: exactly one alert per crossing into the alert zone (tracked per
//! budget), so a busy proxy over-budget for a while doesn't spam the channel.
//!
//! First cut on budget breaches; the same shape extends to latency-percentile / error-rate / (via a
//! trace store) eval-drift rules — the rule decision ([`AlertRuntime::decide_budget`]) is pure and
//! the delivery is a generic webhook POST.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::config::AlertsCfg;

/// Compiled alerting runtime, carried on the proxy [`Runtime`](crate::proxy::Runtime).
pub struct AlertRuntime {
    pub enabled: bool,
    webhook_url: String,
    budget_threshold: f64,
    client: reqwest::Client,
    /// Per-budget "currently in the alert zone" flag, for edge-triggering (fire on false→true only).
    alerting: Mutex<HashMap<String, bool>>,
}

impl AlertRuntime {
    /// Compile from config. `enabled` folds in "has a non-empty webhook_url" so a misconfigured
    /// switch (on, but no URL) is inert rather than trying to POST nowhere on every crossing.
    pub fn build(cfg: &AlertsCfg) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms.max(1)))
            .build()
            .unwrap_or_default();
        AlertRuntime {
            enabled: cfg.enabled && !cfg.webhook_url.trim().is_empty(),
            webhook_url: cfg.webhook_url.trim().to_string(),
            budget_threshold: cfg.budget_consumed_threshold,
            client,
            alerting: Mutex::new(HashMap::new()),
        }
    }

    /// An inert runtime (alerting off) — the default when `[alerts]` is absent.
    pub fn disabled() -> Self {
        Self::build(&AlertsCfg::default())
    }

    /// Decide whether a budget's `ratio` should fire an alert **now**, updating the edge-trigger
    /// state: fire only on the transition into the alert zone (was-below → now at/above the
    /// threshold); reset when it drops back below so a later crossing re-alerts. Pure of IO, so the
    /// dedup logic is directly testable.
    pub fn decide_budget(&self, budget: &str, ratio: f64) -> bool {
        if !self.enabled || !ratio.is_finite() {
            return false;
        }
        let over = ratio >= self.budget_threshold;
        let mut state = self.alerting.lock().expect("alert state mutex poisoned");
        let was_over = state.get(budget).copied().unwrap_or(false);
        if over {
            if was_over {
                false // already alerting for this budget — don't spam
            } else {
                state.insert(budget.to_string(), true);
                true
            }
        } else {
            state.insert(budget.to_string(), false); // reset so a future crossing re-alerts
            false
        }
    }

    /// Fire a Slack-compatible budget alert when the ratio first crosses the threshold. No-op unless
    /// enabled and the crossing is fresh. Fire-and-forget — any webhook error is swallowed at debug.
    pub fn fire_budget_alert(&self, budget: &str, ratio: f64) {
        if !self.decide_budget(budget, ratio) {
            return;
        }
        let text = format!(
            "⚠️ EdgeGuard: LLM budget \"{budget}\" at {:.0}% of its limit (alert threshold {:.0}%).",
            ratio * 100.0,
            self.budget_threshold * 100.0
        );
        let body = serde_json::json!({ "text": text });
        let client = self.client.clone();
        let url = self.webhook_url.clone();
        tokio::spawn(async move {
            match client.post(&url).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => tracing::debug!(status = %resp.status(), "alert webhook rejected"),
                Err(e) => tracing::debug!(error = %e, "alert webhook failed"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(threshold: f64) -> AlertRuntime {
        AlertRuntime::build(&AlertsCfg {
            enabled: true,
            webhook_url: "http://127.0.0.1:1/hook".into(),
            budget_consumed_threshold: threshold,
            ..AlertsCfg::default()
        })
    }

    #[test]
    fn budget_alert_is_edge_triggered_per_crossing() {
        let a = rt(0.9);
        // First time over the threshold → fire.
        assert!(a.decide_budget("monthly", 0.95));
        // Still over on subsequent requests → no repeat (no spam).
        assert!(!a.decide_budget("monthly", 0.96));
        assert!(!a.decide_budget("monthly", 1.20));
        // Drops back below → reset (no fire), then a fresh crossing fires again.
        assert!(!a.decide_budget("monthly", 0.50));
        assert!(a.decide_budget("monthly", 0.91));
        // A different budget name tracks its own edge.
        assert!(a.decide_budget("daily", 0.90)); // exactly at threshold counts as over
    }

    #[test]
    fn disabled_or_missing_url_never_fires() {
        let off = AlertRuntime::disabled();
        assert!(!off.decide_budget("b", 5.0));
        let no_url = AlertRuntime::build(&AlertsCfg {
            enabled: true,
            webhook_url: "   ".into(), // whitespace-only → treated as unset → inert
            ..AlertsCfg::default()
        });
        assert!(!no_url.enabled);
        assert!(!no_url.decide_budget("b", 5.0));
    }

    #[test]
    fn non_finite_ratio_never_fires() {
        let a = rt(0.9);
        assert!(!a.decide_budget("b", f64::NAN));
        assert!(!a.decide_budget("b", f64::INFINITY)); // inf is not finite → ignored, not a crossing
    }
}
