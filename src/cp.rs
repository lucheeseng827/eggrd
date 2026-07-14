//! Managed-mode client: talk to a remote control plane.
//!
//! Off by default. When `[control_plane]` is configured, the edge:
//!   * **pulls its policy** (conditional `GET`, ETag/`304`) and hot-reloads it through the same
//!     `build_runtime` + arc-swap path a local file edit uses;
//!   * **reports usage** (requests + ingress/egress bytes) as periodic deltas;
//!   * **forwards CSP reports** it receives to the control plane.
//!
//! This is a generic "pull config / report usage to a URL" client — it carries no control-plane
//! logic; it just speaks the control plane's edge HTTP API with a per-tenant bearer token. Built
//! on the same `reqwest` + rustls stack as the JWKS fetcher (`auth.rs`).

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{Config, ControlPlaneCfg};
use crate::metrics::Metrics;
use crate::proxy::Runtime;

/// A usage delta reported to the control plane (matches its `/v3/edge/{id}/usage` wire shape).
/// The LLM token fields (gateway L4) are only sent when the gateway is active; the control plane
/// treats them as `#[serde(default)]`, so an older control plane simply ignores them.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct UsageDelta {
    pub requests: u64,
    pub ingress_bytes: u64,
    pub egress_bytes: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_micros: u64,
    /// Requests the edge denied since the last report (a subset of `requests`). Serialized only; an
    /// older control plane treats it as `#[serde(default)]` and ignores it.
    pub blocked: u64,
    /// WAF matches by rule class since the last report. Serialized only; an older control plane
    /// treats them as `#[serde(default)]` and ignores them.
    pub waf_sqli: u64,
    pub waf_xss: u64,
    pub waf_path_traversal: u64,
    pub waf_custom: u64,
}

/// The subset of the control plane's `PolicyDocument` the edge needs.
#[derive(Debug, Deserialize)]
struct PolicyResp {
    etag: String,
    body: String,
}

/// The subset of the control plane's `QuotaStatus` the edge needs to enforce a hard stop.
#[derive(Debug, Deserialize)]
struct QuotaResp {
    over_quota: bool,
    #[serde(default)]
    reset_epoch: i64,
}

/// Shared, hot-reload-surviving quota verdict the proxy enforces. The [`quota_loop`] writes it from
/// the control plane's verdict; the proxy reads it per request. It lives in `AppState` (not the
/// hot-swappable `Runtime`) so a policy reload never resets the enforcement state.
#[derive(Debug, Default)]
pub struct QuotaState {
    /// `true` while the edge is over its quota — the proxy returns `429`.
    pub over_quota: AtomicBool,
    /// Unix second the quota resets (period rollover); `0` = unknown. The `Retry-After` hint.
    pub reset_epoch: AtomicI64,
}

impl QuotaState {
    /// Whether the proxy should currently hard-stop the edge's traffic.
    pub fn blocked(&self) -> bool {
        self.over_quota.load(Ordering::Relaxed)
    }

    /// The reset-epoch hint last reported by the control plane (`0` if none yet).
    pub fn reset_epoch(&self) -> i64 {
        self.reset_epoch.load(Ordering::Relaxed)
    }

    fn apply(&self, over_quota: bool, reset_epoch: i64) {
        self.over_quota.store(over_quota, Ordering::Relaxed);
        self.reset_epoch.store(reset_epoch, Ordering::Relaxed);
    }
}

/// Outcome of a conditional policy pull.
pub enum PullResult {
    /// The edge's ETag still matched — nothing changed.
    NotModified,
    /// A new policy: its opaque TOML body and the new ETag.
    Policy { body: String, etag: String },
}

/// Outbound client to a control plane's per-tenant edge API.
pub struct CpClient {
    http: reqwest::Client,
    /// `{base}/v3/edge/{tenant}` prefix, already trimmed.
    edge_base: String,
    token: String,
}

impl CpClient {
    /// Build the client if managed mode is enabled and configured; otherwise `None`. Fails fast on
    /// an enabled-but-incomplete config so a misconfigured edge doesn't silently run unmanaged.
    pub fn from_cfg(cfg: &ControlPlaneCfg) -> Result<Option<Arc<CpClient>>> {
        if !cfg.enabled {
            return Ok(None);
        }
        anyhow::ensure!(
            !cfg.url.is_empty(),
            "control_plane.url is required when enabled"
        );
        anyhow::ensure!(
            !cfg.tenant_id.is_empty(),
            "control_plane.tenant_id is required when enabled"
        );
        anyhow::ensure!(
            !cfg.edge_token.is_empty(),
            "control_plane.edge_token (or EDGEGUARD_CP_EDGE_TOKEN) is required when enabled"
        );
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("building control-plane HTTP client")?;
        let edge_base = format!(
            "{}/v3/edge/{}",
            cfg.url.trim_end_matches('/'),
            cfg.tenant_id
        );
        Ok(Some(Arc::new(CpClient {
            http,
            edge_base,
            token: cfg.edge_token.clone(),
        })))
    }

    /// Conditional policy pull. `200` → `Policy`; `304` → `NotModified`; other statuses → `Err`.
    pub async fn pull_policy(&self, etag: Option<&str>) -> Result<PullResult> {
        let mut req = self
            .http
            .get(format!("{}/policy", self.edge_base))
            .bearer_auth(&self.token);
        if let Some(e) = etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, e);
        }
        let resp = req.send().await.context("pulling policy")?;
        match resp.status() {
            reqwest::StatusCode::NOT_MODIFIED => Ok(PullResult::NotModified),
            s if s.is_success() => {
                let doc: PolicyResp = resp.json().await.context("parsing policy document")?;
                Ok(PullResult::Policy {
                    body: doc.body,
                    etag: doc.etag,
                })
            }
            s => anyhow::bail!("control plane returned {s} for policy pull"),
        }
    }

    /// Report a usage delta.
    pub async fn report_usage(&self, delta: &UsageDelta) -> Result<()> {
        self.http
            .post(format!("{}/usage", self.edge_base))
            .bearer_auth(&self.token)
            .json(delta)
            .send()
            .await
            .context("reporting usage")?
            .error_for_status()
            .context("control plane rejected usage report")?;
        Ok(())
    }

    /// Pull the tenant's current quota verdict (`over_quota` + `reset_epoch`). Any non-success
    /// status is an error so the caller keeps the last verdict rather than acting on a partial read.
    pub async fn pull_quota(&self) -> Result<(bool, i64)> {
        let resp = self
            .http
            .get(format!("{}/quota", self.edge_base))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("pulling quota")?
            .error_for_status()
            .context("control plane rejected quota poll")?;
        let q: QuotaResp = resp.json().await.context("parsing quota verdict")?;
        Ok((q.over_quota, q.reset_epoch))
    }

    /// Forward a raw CSP report body (best-effort; errors are logged, never surfaced).
    pub async fn forward_csp(&self, raw: &Bytes) {
        let res = self
            .http
            .post(format!("{}/csp-report", self.edge_base))
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(raw.clone())
            .send()
            .await;
        if let Err(e) = res {
            warn!(error = %e, "forwarding CSP report to control plane failed");
        }
    }
}

/// Sleep for `dur`, returning early (`true`) if shutdown is signalled.
async fn sleep_or_shutdown(rx: &mut watch::Receiver<bool>, dur: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(dur) => *rx.borrow(),
        _ = rx.changed() => true,
    }
}

/// Background loop: poll the control plane for policy and hot-reload it through `build_runtime` +
/// the arc-swap, exactly like a local file edit. A parse/build failure keeps the current policy.
pub async fn poll_loop(
    client: Arc<CpClient>,
    base: Arc<Config>,
    runtime: Arc<ArcSwap<Runtime>>,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut etag: Option<String> = None;
    info!(?interval, "control-plane policy poller started");
    loop {
        match client.pull_policy(etag.as_deref()).await {
            Ok(PullResult::NotModified) => {}
            Ok(PullResult::Policy { body, etag: new }) => {
                match apply_policy(&base, &body, &runtime) {
                    Ok(()) => {
                        etag = Some(new);
                        info!("applied policy from control plane");
                    }
                    Err(e) => warn!(
                        error = format!("{e:#}"),
                        "rejected control-plane policy; keeping current"
                    ),
                }
            }
            Err(e) => warn!(
                error = format!("{e:#}"),
                "policy pull failed; keeping current"
            ),
        }
        if sleep_or_shutdown(&mut shutdown, interval).await {
            break;
        }
    }
}

/// Overlay a pushed policy onto the local base config, rebuild the runtime, and swap it in.
fn apply_policy(base: &Config, body: &str, runtime: &ArcSwap<Runtime>) -> Result<()> {
    let merged = base.with_policy_from(body)?;
    let rt = crate::build_runtime(Arc::new(merged))?;
    runtime.store(Arc::new(rt));
    Ok(())
}

/// Background loop: flush the usage accumulator to the control plane each period. On a failed
/// report the drained delta is added back so billable usage isn't lost.
pub async fn report_loop(
    client: Arc<CpClient>,
    metrics: Arc<Metrics>,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    info!(?interval, "control-plane usage reporter started");
    loop {
        if sleep_or_shutdown(&mut shutdown, interval).await {
            break;
        }
        let drained = metrics.drain_usage();
        if drained.is_empty() {
            continue;
        }
        if let Err(e) = client.report_usage(&UsageDelta::from(drained)).await {
            warn!(
                error = format!("{e:#}"),
                "usage report failed; will retry next period"
            );
            metrics.restore_usage(&drained);
        }
    }
    // Best-effort final flush on graceful shutdown so billable usage isn't lost.
    let drained = metrics.drain_usage();
    if !drained.is_empty() {
        if let Err(e) = client.report_usage(&UsageDelta::from(drained)).await {
            warn!(
                error = format!("{e:#}"),
                "final usage report on shutdown failed"
            );
        }
    }
}

impl From<crate::metrics::DrainedUsage> for UsageDelta {
    fn from(u: crate::metrics::DrainedUsage) -> Self {
        UsageDelta {
            requests: u.requests,
            ingress_bytes: u.ingress_bytes,
            egress_bytes: u.egress_bytes,
            tokens_in: u.tokens_in,
            tokens_out: u.tokens_out,
            cost_micros: u.cost_micros,
            blocked: u.blocked,
            waf_sqli: u.waf_sqli,
            waf_xss: u.waf_xss,
            waf_path_traversal: u.waf_path_traversal,
            waf_custom: u.waf_custom,
        }
    }
}

/// Background loop: poll the control plane for the tenant's quota verdict and publish it to the
/// shared [`QuotaState`] the proxy enforces. A failed poll keeps the last verdict (fail-static), so
/// a control-plane blip neither suddenly blocks nor suddenly unblocks the edge.
pub async fn quota_loop(
    client: Arc<CpClient>,
    quota: Arc<QuotaState>,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    info!(?interval, "control-plane quota poller started");
    loop {
        match client.pull_quota().await {
            Ok((over_quota, reset_epoch)) => {
                quota.apply(over_quota, reset_epoch);
            }
            Err(e) => warn!(
                error = format!("{e:#}"),
                "quota poll failed; keeping last verdict"
            ),
        }
        if sleep_or_shutdown(&mut shutdown, interval).await {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ControlPlaneCfg;
    use std::net::SocketAddr;
    use std::sync::Mutex as StdMutex;

    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::{get, post},
        Json, Router,
    };

    const ETAG: &str = "\"abc123\"";

    #[derive(Clone, Default)]
    struct Stub {
        last_usage: Arc<StdMutex<Option<serde_json::Value>>>,
    }

    async fn policy(headers: HeaderMap) -> axum::response::Response {
        // Conditional: a matching If-None-Match gets a 304.
        if headers
            .get(axum::http::header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            == Some(ETAG)
        {
            return StatusCode::NOT_MODIFIED.into_response();
        }
        (
            [(axum::http::header::ETAG, ETAG)],
            Json(serde_json::json!({
                "version": 1, "etag": ETAG, "format": "toml",
                "body": "[auth]\nmode = \"none\"\n", "updated_at": 0
            })),
        )
            .into_response()
    }

    async fn usage(State(s): State<Stub>, body: axum::body::Bytes) -> StatusCode {
        *s.last_usage.lock().unwrap() = serde_json::from_slice(&body).ok();
        StatusCode::ACCEPTED
    }

    async fn quota() -> axum::response::Response {
        // A trimmed QuotaStatus: the edge only reads over_quota + reset_epoch.
        Json(serde_json::json!({
            "over_quota": true, "reset_epoch": 1_782_864_000_i64
        }))
        .into_response()
    }

    async fn spawn_stub() -> (SocketAddr, Stub) {
        let stub = Stub::default();
        let app = Router::new()
            .route("/v3/edge/t1/policy", get(policy))
            .route("/v3/edge/t1/usage", post(usage))
            .route("/v3/edge/t1/quota", get(quota))
            .with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, stub)
    }

    fn client(addr: SocketAddr) -> Arc<CpClient> {
        CpClient::from_cfg(&ControlPlaneCfg {
            enabled: true,
            url: format!("http://{addr}"),
            tenant_id: "t1".into(),
            edge_token: "tok".into(),
            ..Default::default()
        })
        .unwrap()
        .unwrap()
    }

    #[test]
    fn disabled_or_incomplete_config() {
        // Disabled -> no client.
        assert!(CpClient::from_cfg(&ControlPlaneCfg::default())
            .unwrap()
            .is_none());
        // Enabled but missing a token -> hard error (don't silently run unmanaged).
        assert!(CpClient::from_cfg(&ControlPlaneCfg {
            enabled: true,
            url: "http://x".into(),
            tenant_id: "t1".into(),
            ..Default::default()
        })
        .is_err());
    }

    #[tokio::test]
    async fn policy_pull_conditional() {
        let (addr, _) = spawn_stub().await;
        let c = client(addr);
        // First pull (no ETag) returns the policy + its ETag.
        match c.pull_policy(None).await.unwrap() {
            PullResult::Policy { body, etag } => {
                assert!(body.contains("mode = \"none\""));
                assert_eq!(etag, ETAG);
            }
            _ => panic!("expected a policy"),
        }
        // Re-pull with the ETag -> 304 NotModified.
        assert!(matches!(
            c.pull_policy(Some(ETAG)).await.unwrap(),
            PullResult::NotModified
        ));
    }

    #[tokio::test]
    async fn usage_report_posts_delta() {
        let (addr, stub) = spawn_stub().await;
        let c = client(addr);
        c.report_usage(&UsageDelta {
            requests: 3,
            ingress_bytes: 100,
            egress_bytes: 250,
            tokens_in: 1_200,
            tokens_out: 800,
            cost_micros: 5_000,
            blocked: 1,
            ..Default::default()
        })
        .await
        .unwrap();
        let got = stub.last_usage.lock().unwrap().clone().unwrap();
        assert_eq!(got["requests"], 3);
        assert_eq!(got["tokens_in"], 1_200);
        assert_eq!(got["cost_micros"], 5_000);
        assert_eq!(got["ingress_bytes"], 100);
        assert_eq!(got["egress_bytes"], 250);
        assert_eq!(got["blocked"], 1);
    }

    #[tokio::test]
    async fn quota_pull_returns_verdict() {
        let (addr, _) = spawn_stub().await;
        let c = client(addr);
        let (over, reset) = c.pull_quota().await.unwrap();
        assert!(over);
        assert_eq!(reset, 1_782_864_000);
    }

    #[tokio::test]
    async fn quota_loop_publishes_to_shared_state() {
        let (addr, _) = spawn_stub().await;
        let c = client(addr);
        let state = Arc::new(QuotaState::default());
        assert!(!state.blocked(), "starts permissive");

        let (tx, rx) = watch::channel(false);
        let st = state.clone();
        let handle =
            tokio::spawn(async move { quota_loop(c, st, Duration::from_millis(50), rx).await });

        // Give the loop one poll, then assert the verdict landed, and shut it down.
        for _ in 0..50 {
            if state.blocked() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            state.blocked(),
            "verdict from the control plane should publish"
        );
        assert_eq!(state.reset_epoch(), 1_782_864_000);
        let _ = tx.send(true);
        let _ = handle.await;
    }
}
