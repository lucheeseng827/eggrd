//! EdgeGuard library surface.
//!
//! The `edgeguard` binary (`src/main.rs`) is a thin CLI on top of this crate. Exposing the
//! pipeline as a library lets integration tests drive the *same* `build_state` /
//! `build_router` entry points the binary uses, so tests exercise the real request path
//! rather than a reimplementation of it.

pub mod access;
pub mod accesslog;
pub mod acme;
pub mod acme_budget;
pub mod acme_dns;
pub mod alert;
pub mod auth;
pub mod budget;
pub mod certstore;
pub mod client_auth;
pub mod client_cert_header;
pub mod config;
pub mod cors;
pub mod cp;
pub mod dlp;
pub mod doctor;
pub mod generate;
pub mod keyvault;
pub mod limiter;
pub mod llm;
pub mod logship;
pub mod metrics;
pub mod otlp_metrics;
pub mod outbound;
pub mod policy;
pub mod pool;
pub mod proxy;
pub mod proxy_protocol;
pub mod reload;
pub mod scaffold;
pub mod selfsigned;
pub mod serve;
pub mod stream_inspect;
pub mod supervisor;
pub mod telemetry;
pub mod tls;
pub mod upstream;
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
    // Checked whether or not a section inherits it now, so a broken default fails here and not on
    // the reload that first turns on a client using it.
    crate::outbound::check_defaults(&cfg.outbound)?;
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

    // Per-path upstream overrides ([[upstreams]]), each a target or a pool, with each URL's
    // trailing '/' trimmed. A bad/empty entry fails here so it surfaces at startup/reload.
    let mut upstream_routes = Vec::with_capacity(cfg.upstreams.len());
    for route in &cfg.upstreams {
        anyhow::ensure!(!route.path.is_empty(), "upstreams[].path must not be empty");
        // The path is a URL path prefix matched against request paths (which start with '/'), so a
        // value like "api/" could never match — reject it at startup instead of silently routing
        // everything to the default upstream.
        anyhow::ensure!(
            route.path.starts_with('/'),
            "upstreams[].path must start with '/' (got {:?})",
            route.path
        );
        let label = if route.name.is_empty() {
            &route.path
        } else {
            &route.name
        };
        upstream_routes.push((
            route.path.clone(),
            crate::pool::Pool::from_route(route, label)?,
        ));
    }
    crate::pool::check_url(&cfg.upstream_base()).context("server.upstream")?;
    // Read once, by the connector at startup; parsed here too so a reload or `doctor` reports a typo.
    parse_duration(&cfg.validation.upstream_connect_timeout)
        .context("validation.upstream_connect_timeout")?;

    let auth = AuthEngine::build(&cfg.auth)?;
    // `[tls]` is edge-local and fixed for the process, but `auth.mode` can arrive in a pushed
    // policy: refuse one that authenticates by a client certificate this listener never asks for.
    let from_header = !cfg.trusted_client_cert_header.name.trim().is_empty();
    let client_cert_header =
        crate::client_auth::ForwardPolicy::from_cfg(&cfg.tls.client_auth, from_header)?;
    anyhow::ensure!(
        cfg.auth.mode != "mtls" || client_cert_header.strip_inbound,
        "auth.mode = \"mtls\" needs [tls.client_auth] mode = \"optional\" or \"required\", or \
         [trusted_client_cert_header]: without one no request carries a client certificate"
    );
    // The balancer's names are read from the certificate it presents in its TLS handshake, which
    // the listener asks for only with client authentication on (itself refused without `[tls]`).
    let header = &cfg.trusted_client_cert_header;
    anyhow::ensure!(
        !from_header || header.trusted_proxy_names.is_empty() || cfg.tls.client_auth.mode != "off",
        "trusted_client_cert_header.trusted_proxy_names needs [tls.client_auth] mode = \
         \"optional\" or \"required\": the names are read from the certificate the balancer \
         presents in its TLS handshake, and the listener asks for one only with client \
         authentication on"
    );
    // Compile the WAF here too, so a bad custom pattern fails fast at startup/reload rather
    // than per-request (and a broken hot-reload keeps the previous policy).
    let waf = Arc::new(crate::waf::WafEngine::build(&cfg.waf)?);
    // Compile the CORS policy (None when disabled). An incoherent policy — credentialed
    // wildcard, enabled-but-no-origins — fails here, so it's caught at startup/reload.
    let cors = crate::cors::CorsPolicy::build(&cfg.cors)?;
    // Compile the IP allow/deny lists (None when both empty). A bad CIDR fails here.
    let access = crate::access::AccessPolicy::build(&cfg.access)?;

    let max_body = parse_size(&cfg.validation.max_body)?;
    let max_response_body = parse_size(&cfg.validation.max_response_body)?;
    let max_header_bytes = parse_size(&cfg.validation.max_header_bytes)?;
    // A zero duration ("0") means "no timeout".
    let upstream_timeout = parse_duration(&cfg.validation.upstream_timeout)?;
    let upstream_timeout = (!upstream_timeout.is_zero()).then_some(upstream_timeout);

    // Route labels for the per-route metrics. A prefix listed in both tables keeps the upstream's
    // label; either may name it.
    let mut route_labels: Vec<(String, String)> = Vec::new();
    let routes = cfg
        .upstreams
        .iter()
        .map(|u| (&u.path, &u.name))
        .chain(cfg.ratelimit.routes.iter().map(|r| (&r.path, &r.name)));
    for (path, name) in routes {
        if path.is_empty() || route_labels.iter().any(|(p, _)| p == path) {
            continue;
        }
        let label = if name.is_empty() { path } else { name };
        route_labels.push((path.clone(), label.clone()));
    }

    Ok(Runtime {
        client_cert_header,
        route_labels,
        default_upstream: crate::pool::Pool::single(&cfg.upstream_base()),
        upstream_routes,
        auth,
        waf,
        cors,
        access,
        distributed,
        ip_limiter,
        route_limiters,
        key_limiter,
        max_body,
        max_response_body,
        max_header_bytes,
        upstream_timeout,
        stream_passthrough: cfg.validation.stream_passthrough,
        stream_responses: cfg.validation.stream_responses,
        stream_requests: cfg.validation.stream_requests,
        stream_inspect: crate::stream_inspect::InspectWindow::build(
            &cfg.validation.stream_inspect,
        )?,
        websocket_passthrough: cfg.validation.websocket_passthrough,
        llm: {
            // Validate the unpriced-model policy up front so a typo fails at load/reload rather than
            // silently falling back to `count` inside the infallible runtime builder.
            crate::llm::UnpricedPolicy::parse(&cfg.llm.on_unpriced_model)?;
            Arc::new(crate::llm::LlmRuntime::build(&cfg.llm))
        },
        budgets: crate::budget::BudgetEngine::build(&cfg.llm)?.map(Arc::new),
        keyvault: {
            crate::keyvault::check_claims_auth(&cfg.auth, &cfg.llm)?;
            crate::keyvault::KeyVault::build(&cfg.llm)?.map(Arc::new)
        },
        dlp: crate::dlp::DlpEngine::build(&cfg.llm.dlp)?.map(Arc::new),
        telemetry: Arc::new(crate::telemetry::TelemetryRuntime::build(
            &cfg.llm.telemetry,
        )?),
        alerts: Arc::new(crate::alert::AlertRuntime::build(&cfg.alerts)?),
        cfg,
    })
}

/// An upstream base URL the client can dial: `http://` or `https://`, with a host. Anything else
/// would load fine and then answer every request with `502`.
/// Build the shared [`AppState`]: a fresh [`Runtime`] wrapped in an [`ArcSwap`] for
/// hot-reload, the upstream HTTP client, and the metric registry.
pub fn build_state(cfg: Arc<Config>) -> Result<AppState> {
    // Build the managed-mode client (if `[control_plane]` is enabled) before `cfg` is consumed.
    let cp = crate::cp::CpClient::from_cfg(&cfg.control_plane)?;
    let metrics = Metrics::new();
    metrics.set_consumer_series_max(cfg.metrics.consumer_series_max);
    let upstream_tls = Arc::new(crate::upstream::UpstreamTls::from_cfg(&cfg.upstream_tls)?);
    // Edge-local and read once, like `upstream_tls`: which addresses may assert a client
    // certificate is fixed for the process.
    let cfg_header = cfg.trusted_client_cert_header.clone();
    let connect_timeout = parse_duration(&cfg.validation.upstream_connect_timeout)
        .context("validation.upstream_connect_timeout")?;
    let runtime = Arc::new(ArcSwap::from_pointee(build_runtime(cfg)?));
    // The pool series are read from whichever runtime is current.
    metrics.watch_runtime(Arc::clone(&runtime));
    let connector = crate::upstream::UpstreamConnector::new(
        Arc::clone(&upstream_tls),
        (!connect_timeout.is_zero()).then_some(connect_timeout),
    );
    let client = Client::builder(TokioExecutor::new()).build(connector.clone());
    let client_cert_header = crate::client_cert_header::TrustedHeader::from_cfg(&cfg_header)?;
    if let Some(header) = &client_cert_header {
        metrics.set_trusted_header(Arc::clone(header));
    }
    Ok(AppState {
        client,
        connector,
        upstream_tls,
        client_cert_header,
        metrics: Arc::new(metrics),
        runtime,
        cp,
        quota: Arc::new(crate::cp::QuotaState::default()),
        draining: Arc::default(),
        policy_pending: Arc::default(),
    })
}

/// Build the combined axum [`Router`]: the internal `/__edgeguard/*` endpoints (health,
/// readiness, Prometheus metrics, CSP report sink) plus the catch-all proxy handler, all on one
/// listener. This is the default (single-port) topology; for the public/private split see
/// [`build_public_router`] / [`build_admin_router`]. Body limits are enforced inside the proxy
/// handler, so the default layer is disabled there; the CSP sink keeps a small explicit cap
/// since it parses the body.
pub fn build_router(state: AppState) -> Router {
    let router = public_routes()
        .merge(admin_routes())
        .layer(DefaultBodyLimit::disable());
    maybe_compress(router, &state).with_state(state)
}

/// Optionally wrap the router in a gzip [`CompressionLayer`] when `validation.compress_responses`
/// is set. Compression is a listener-level concern (not hot-reloadable), so it reads the *initial*
/// config from `state`. The predicate excludes `text/event-stream` so SSE streaming is never held
/// back by the compressor (on top of the default skip-small / skip-already-compressed rules).
fn maybe_compress(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    use tower_http::compression::predicate::{DefaultPredicate, NotForContentType, Predicate};
    use tower_http::compression::CompressionLayer;

    if !state.runtime.load().cfg.validation.compress_responses {
        return router;
    }
    let predicate = DefaultPredicate::new().and(NotForContentType::const_new("text/event-stream"));
    router.layer(CompressionLayer::new().compress_when(predicate))
}

/// The **public** router (used in public/private split mode): the catch-all proxy plus the
/// browser-facing CSP report sink. The ops endpoints (health/readiness/metrics) are *not* here
/// — they live on the private [`build_admin_router`] listener, so they aren't exposed publicly.
pub fn build_public_router(state: AppState) -> Router {
    let router = public_routes().layer(DefaultBodyLimit::disable());
    maybe_compress(router, &state).with_state(state)
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

/// Internal ops routes: liveness, readiness, the Prometheus metrics scrape, and the served TLS
/// certificate's status.
fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/__edgeguard/health", get(|| async { "ok" }))
        .route("/__edgeguard/ready", get(ready))
        .route("/__edgeguard/metrics", get(metrics_handler))
        .route("/__edgeguard/tls", get(proxy::tls_status))
        .route("/__edgeguard/upstreams", get(proxy::upstreams_status))
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
    fn route_labels_come_from_both_route_tables_and_the_longest_prefix_wins() {
        use crate::config::{RouteRateLimit, UpstreamRoute};
        let mut cfg = Config {
            upstreams: vec![UpstreamRoute {
                path: "/api/".into(),
                target: "http://api:4000".into(),
                name: "api".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        cfg.ratelimit.routes = vec![
            RouteRateLimit {
                path: "/api/login".into(),
                ..Default::default()
            },
            // Also an upstream prefix: the upstream's label stands.
            RouteRateLimit {
                path: "/api/".into(),
                name: "ignored".into(),
                ..Default::default()
            },
        ];
        let rt = build_runtime(Arc::new(cfg)).unwrap();
        assert_eq!(rt.route_label("/api/users?page=2"), "api");
        assert_eq!(rt.route_label("/api/login?next=/"), "/api/login");
        assert_eq!(rt.route_label("/apiary"), "default", "segment boundaries");
        assert_eq!(rt.route_label("/"), "default");
        assert_eq!(rt.route_labels.len(), 2);
    }

    #[test]
    fn build_runtime_rejects_an_upstream_the_client_cannot_dial() {
        for bad in ["127.0.0.1:3000", "ftp://files.example", "https://"] {
            let cfg = Config {
                upstreams: vec![crate::config::UpstreamRoute {
                    path: "/api/".into(),
                    target: bad.into(),
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(
                build_runtime(Arc::new(cfg)).is_err(),
                "{bad} should be refused"
            );
        }
        let mut cfg = Config::default();
        cfg.server.upstream = "https://app.example.com".into();
        assert!(build_runtime(Arc::new(cfg)).is_ok());
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
            ..Default::default()
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
            ..Default::default()
        }];
        assert!(build_runtime(Arc::new(cfg)).is_err());
    }

    #[test]
    fn build_runtime_validates_upstream_route_paths() {
        // A leading '/' is required — "api/" could never match a request path.
        let bad = Config {
            upstreams: vec![crate::config::UpstreamRoute {
                path: "api/".into(),
                target: "http://api:4000".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(build_runtime(Arc::new(bad)).is_err());

        // A well-formed route compiles, with the target's trailing slash trimmed.
        let ok = Config {
            upstreams: vec![crate::config::UpstreamRoute {
                path: "/api/".into(),
                target: "http://api:4000/".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let rt = build_runtime(Arc::new(ok)).unwrap();
        assert_eq!(rt.pick_upstream("/api/x").primary(), "http://api:4000");
        assert_eq!(
            rt.pick_upstream("/other").primary(),
            rt.default_upstream.primary()
        );
    }
}
