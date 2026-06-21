//! EdgeGuard library surface.
//!
//! The `edgeguard` binary (`src/main.rs`) is a thin CLI on top of this crate. Exposing the
//! pipeline as a library lets integration tests drive the *same* `build_state` /
//! `build_router` entry points the binary uses, so tests exercise the real request path
//! rather than a reimplementation of it.

pub mod acme;
pub mod auth;
pub mod config;
pub mod cp;
pub mod generate;
pub mod limiter;
pub mod metrics;
pub mod proxy;
pub mod reload;
pub mod supervisor;
pub mod tls;
pub mod waf;

use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::{
    extract::DefaultBodyLimit,
    routing::{any, get, post},
    Router,
};
use governor::{Quota, RateLimiter};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::auth::AuthEngine;
use crate::config::{parse_duration, parse_rate, parse_size, Config};
use crate::metrics::Metrics;
use crate::proxy::{
    csp_report, metrics_handler, ready, AppState, RouteLimiter, Runtime, StrLimiter,
};

pub use crate::auth::hash_password;

/// Translate a `rate`/`burst` policy into a GCRA [`Quota`]. Rejects degenerate input (a `0`
/// rate or burst) rather than silently coercing it to `1/1`, which would mask the operator's
/// mistake. Shared by the global, per-route, and per-key limiters.
fn quota(rate: &str, burst: u32) -> Result<Quota> {
    let (count, period) = parse_rate(rate)?;
    anyhow::ensure!(count > 0, "rate count must be > 0 (got \"{rate}\")");
    anyhow::ensure!(burst > 0, "burst must be > 0 (rate \"{rate}\")");
    // One cell replenishes every (period / count); burst is the bucket depth.
    let per_cell = period / count;
    let burst = NonZeroU32::new(burst).unwrap();
    Ok(Quota::with_period(per_cell)
        .context("rate too high for a usable replenish interval")?
        .allow_burst(burst))
}

/// Build the hot-swappable [`Runtime`] from a fully-resolved [`Config`]: the rate limiters
/// (global per-IP, per-route, per-key), the auth engine, and the parsed size/timeout limits.
/// Errors if any size/rate/auth setting is invalid, so a bad config fails fast — at startup
/// or on reload — rather than per-request. The HTTP client and metric registry live outside
/// the runtime (in [`AppState`]) so a reload preserves the connection pool and counters.
pub fn build_runtime(cfg: Arc<Config>) -> Result<Runtime> {
    let rl = &cfg.ratelimit;

    // Pick the limiter backend. `local` keeps the in-process `governor` limiters below; a
    // distributed store (`memory`/`redis`) builds a shared-store limiter instead, so the two
    // are mutually exclusive. An unknown store value fails here rather than silently disabling
    // limiting.
    let store_mode = crate::limiter::StoreMode::parse(&rl.store)?;
    let use_distributed = rl.enabled && store_mode.is_distributed();

    let distributed = if use_distributed {
        Some(crate::limiter::DistributedLimiter::build(rl, store_mode)?)
    } else {
        None
    };

    // The local `governor` limiters are built only when not using a shared store.
    let build_local = rl.enabled && !use_distributed;

    let ip_limiter = if build_local {
        Some(Arc::new(RateLimiter::keyed(quota(&rl.rate, rl.burst)?)))
    } else {
        None
    };

    let mut route_limiters = Vec::new();
    if build_local {
        for route in &rl.routes {
            anyhow::ensure!(
                !route.path.is_empty(),
                "ratelimit.routes[].path must not be empty"
            );
            route_limiters.push(RouteLimiter {
                prefix: route.path.clone(),
                limiter: Arc::new(RateLimiter::keyed(quota(&route.rate, route.burst)?)),
            });
        }
    }

    let key_limiter: Option<Arc<StrLimiter>> = if build_local && rl.per_key.enabled {
        Some(Arc::new(RateLimiter::keyed(quota(
            &rl.per_key.rate,
            rl.per_key.burst,
        )?)))
    } else {
        None
    };

    let auth = AuthEngine::build(&cfg.auth)?;
    // Compile the WAF here too, so a bad custom pattern fails fast at startup/reload rather
    // than per-request (and a broken hot-reload keeps the previous policy).
    let waf = crate::waf::WafEngine::build(&cfg.waf)?;

    let max_body = parse_size(&cfg.validation.max_body)?;
    let max_response_body = parse_size(&cfg.validation.max_response_body)?;
    let max_header_bytes = parse_size(&cfg.validation.max_header_bytes)?;
    // A zero duration ("0") means "no timeout".
    let upstream_timeout = parse_duration(&cfg.validation.upstream_timeout)?;
    let upstream_timeout = (!upstream_timeout.is_zero()).then_some(upstream_timeout);

    Ok(Runtime {
        upstream_base: Arc::new(cfg.upstream_base()),
        auth,
        waf,
        distributed,
        ip_limiter,
        route_limiters,
        key_limiter,
        max_body,
        max_response_body,
        max_header_bytes,
        upstream_timeout,
        stream_passthrough: cfg.validation.stream_passthrough,
        cfg,
    })
}

/// Build the shared [`AppState`]: a fresh [`Runtime`] wrapped in an [`ArcSwap`] for
/// hot-reload, the upstream HTTP client, and the metric registry.
pub fn build_state(cfg: Arc<Config>) -> Result<AppState> {
    // Build the managed-mode client (if `[control_plane]` is enabled) before `cfg` is consumed.
    let cp = crate::cp::CpClient::from_cfg(&cfg.control_plane)?;
    let runtime = build_runtime(cfg)?;
    let client =
        Client::builder(TokioExecutor::new()).build_http::<http_body_util::Full<bytes::Bytes>>();
    Ok(AppState {
        client,
        metrics: Arc::new(Metrics::new()),
        runtime: Arc::new(ArcSwap::from_pointee(runtime)),
        cp,
    })
}

/// Build the combined axum [`Router`]: the internal `/__edgeguard/*` endpoints (health,
/// readiness, Prometheus metrics, CSP report sink) plus the catch-all proxy handler, all on one
/// listener. This is the default (single-port) topology; for the public/private split see
/// [`build_public_router`] / [`build_admin_router`]. Body limits are enforced inside the proxy
/// handler, so the default layer is disabled there; the CSP sink keeps a small explicit cap
/// since it parses the body.
pub fn build_router(state: AppState) -> Router {
    public_routes()
        .merge(admin_routes())
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

/// The **public** router (used in public/private split mode): the catch-all proxy plus the
/// browser-facing CSP report sink. The ops endpoints (health/readiness/metrics) are *not* here
/// — they live on the private [`build_admin_router`] listener, so they aren't exposed publicly.
pub fn build_public_router(state: AppState) -> Router {
    public_routes()
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

/// The **private/admin** router (used in public/private split mode): the internal ops endpoints
/// (health, readiness, metrics). It has no proxy fallback, so an unknown path returns `404`
/// rather than being forwarded upstream. Shares the same [`AppState`] as the public router, so
/// `/__edgeguard/metrics` reports the live proxy counters.
pub fn build_admin_router(state: AppState) -> Router {
    admin_routes().with_state(state)
}

/// Public-surface routes: the proxy fallback and the CSP report sink (which browsers POST to
/// from the public web, so it stays on the public listener).
fn public_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/__edgeguard/csp-report",
            post(csp_report).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .fallback(any(proxy::handle))
}

/// Internal ops routes: liveness, readiness, and the Prometheus metrics scrape.
fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/__edgeguard/health", get(|| async { "ok" }))
        .route("/__edgeguard/ready", get(ready))
        .route("/__edgeguard/metrics", get(metrics_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitCfg;

    fn cfg_with_ratelimit(rate: &str, burst: u32) -> Config {
        Config {
            ratelimit: RateLimitCfg {
                enabled: true,
                rate: rate.into(),
                burst,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn build_state_rejects_zero_rate() {
        // `0/min` is a misconfiguration, not "1/min" — validation fails before we ever
        // build the client, so no async runtime is needed here.
        assert!(build_state(Arc::new(cfg_with_ratelimit("0/min", 20))).is_err());
    }

    #[test]
    fn build_state_rejects_zero_burst() {
        assert!(build_state(Arc::new(cfg_with_ratelimit("60/min", 0))).is_err());
    }

    #[test]
    fn build_runtime_builds_route_and_key_limiters() {
        let mut cfg = Config::default();
        cfg.ratelimit.routes = vec![crate::config::RouteRateLimit {
            path: "/api/".into(),
            rate: "10/sec".into(),
            burst: 5,
        }];
        cfg.ratelimit.per_key = crate::config::PerKeyRateLimit {
            enabled: true,
            rate: "1000/hour".into(),
            burst: 100,
        };
        let rt = build_runtime(Arc::new(cfg)).unwrap();
        assert_eq!(rt.route_limiters.len(), 1);
        assert_eq!(rt.route_limiters[0].prefix, "/api/");
        assert!(rt.key_limiter.is_some());
    }

    #[test]
    fn build_runtime_rejects_bad_route_rate() {
        let mut cfg = Config::default();
        cfg.ratelimit.routes = vec![crate::config::RouteRateLimit {
            path: "/api/".into(),
            rate: "0/sec".into(),
            burst: 5,
        }];
        assert!(build_runtime(Arc::new(cfg)).is_err());
    }
}
