//! Configuration. Env-first so EdgeGuard drops into any PaaS that injects `$PORT`
//! with zero edits; an optional TOML file layers richer policy on top.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::env;
use std::time::Duration;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerCfg,
    pub auth: AuthCfg,
    pub ratelimit: RateLimitCfg,
    pub validation: ValidationCfg,
    pub headers: HeadersCfg,
    pub tls: TlsCfg,
    pub waf: WafCfg,
    /// Optional "managed mode": pull policy from / report usage to a remote control plane. Off
    /// by default; the edge is a standalone proxy unless this is configured.
    pub control_plane: ControlPlaneCfg,
}

/// Managed-mode settings: when `enabled`, the edge pulls its policy from a remote control plane
/// (and hot-reloads it), reports usage deltas, and forwards CSP reports. The policy the control
/// plane pushes is the *policy subset* (auth/ratelimit/validation/headers/waf) — the edge keeps
/// its own local `server`/`tls`. The edge token is a secret, so prefer `EDGEGUARD_CP_EDGE_TOKEN`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ControlPlaneCfg {
    pub enabled: bool,
    /// Base URL of the control plane, e.g. `https://cp.example`.
    pub url: String,
    /// This edge's tenant id at the control plane.
    pub tenant_id: String,
    /// Per-tenant edge token (Bearer). Prefer `EDGEGUARD_CP_EDGE_TOKEN`.
    pub edge_token: String,
    /// How often to poll for policy, e.g. `"30s"`.
    pub poll_interval: String,
    /// How often to flush a usage delta, e.g. `"60s"`.
    pub report_interval: String,
    /// Forward received CSP reports to the control plane (default true).
    pub forward_csp: bool,
}

impl Default for ControlPlaneCfg {
    fn default() -> Self {
        ControlPlaneCfg {
            enabled: false,
            url: String::new(),
            tenant_id: String::new(),
            edge_token: String::new(),
            poll_interval: "30s".into(),
            report_interval: "60s".into(),
            forward_csp: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerCfg {
    /// Public listen port. Overridden by the `PORT` env var.
    pub port: u16,
    /// Internal port the wrapped/upstream app listens on. Overridden by `APP_PORT`.
    pub app_port: u16,
    /// Full upstream base URL. Overridden by `UPSTREAM`. If empty, derived from app_port.
    pub upstream: String,
    /// Trust the `X-Forwarded-For` header for client identity. Enable ONLY when
    /// EdgeGuard sits behind a trusted proxy/load balancer that sets it (e.g. a PaaS
    /// edge). When false (default) the peer socket address is used, so clients can't
    /// spoof their IP to defeat per-IP rate limiting or forge access-log entries.
    pub trust_forwarded_for: bool,
    /// Private listener port for the internal `/__edgeguard/*` ops endpoints (health,
    /// readiness, metrics). `0` (default) keeps them on the public port. When non-zero,
    /// EdgeGuard binds a second, plain-HTTP listener on `admin_addr:admin_port` that serves
    /// those endpoints, and the public port serves only the proxy (plus the browser-facing CSP
    /// report sink) — so metrics/health aren't exposed on the internet. Overridden by
    /// `ADMIN_PORT`. (Point your platform's health check at this port when you enable it.)
    pub admin_port: u16,
    /// Address the private admin listener binds when `admin_port` is set. Defaults to
    /// `127.0.0.1` (same-host only — e.g. a sidecar scraper); set to `0.0.0.0` to expose it on
    /// a private network interface (rely on your network policy to keep it off the internet).
    pub admin_addr: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthCfg {
    /// "none" | "basic" | "apikey" | "jwt". Selects the gate applied to every proxied
    /// request; the internal `/__edgeguard/*` endpoints are always exempt.
    pub mode: String,
    pub realm: String,
    /// username -> password. Value may be plaintext (dev) or a `$argon2...` PHC hash.
    /// Used when `mode = "basic"`.
    pub users: BTreeMap<String, String>,
    /// Accepted API keys (compared in constant time). Used when `mode = "apikey"`. A request
    /// may present a key either as `Authorization: Bearer <key>` or in `api_key_header`.
    /// Overridable from the env via `EDGEGUARD_API_KEYS` (comma-separated) so keys need not
    /// live in the config file.
    pub api_keys: Vec<String>,
    /// Header carrying the API key (in addition to `Authorization: Bearer`), default
    /// `X-API-Key`. Used when `mode = "apikey"`.
    pub api_key_header: String,
    /// JWT verification policy. Used when `mode = "jwt"`.
    pub jwt: JwtCfg,
}

/// JWT bearer-token verification. Either a symmetric `secret` (HS*) or an asymmetric key
/// (RS*/ES*/PS*) supplied as a static `public_key_pem` or fetched from `jwks_url`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct JwtCfg {
    /// Expected signature algorithm, e.g. "HS256", "RS256", "ES256". The token's own `alg`
    /// header must match this (we never trust the token to pick its own algorithm — that is
    /// the classic JWT downgrade/`alg=none` foot-gun).
    pub algorithm: String,
    /// Shared secret for HS* algorithms. Prefer the `EDGEGUARD_JWT_SECRET` env var over
    /// putting it in the config file.
    pub secret: String,
    /// Static PEM public key (SPKI or PKCS#1) for RS*/ES*/PS* verification, as an
    /// alternative to `jwks_url`.
    pub public_key_pem: String,
    /// JWKS endpoint to fetch verification keys from (RS*/ES*/PS*). Keys are cached and
    /// selected by the token's `kid`.
    pub jwks_url: String,
    /// How long (seconds) to cache a fetched JWKS before refetching. Default 300.
    pub jwks_cache_secs: u64,
    /// If set, the token's `iss` claim must equal this.
    pub issuer: String,
    /// If set, the token's `aud` claim must contain this.
    pub audience: String,
    /// Clock-skew leeway (seconds) applied to `exp`/`nbf` validation. Default 60.
    pub leeway_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitCfg {
    pub enabled: bool,
    /// Default per-client-IP limit, e.g. "60/min", "10/sec", "1000/hour".
    pub rate: String,
    pub burst: u32,
    /// Per-route overrides. A request whose path starts with `path` uses that route's limit
    /// (still keyed per client IP) instead of the global one; the longest matching prefix
    /// wins, so `/api/admin/` can be stricter than `/api/`.
    pub routes: Vec<RouteRateLimit>,
    /// An additional limit keyed by the authenticated principal (API-key id or JWT subject)
    /// rather than IP, so a single credential can't fan out across many IPs. Only applies to
    /// authenticated requests.
    pub per_key: PerKeyRateLimit,
    /// Where limiter state lives: `"local"` (default) is the in-process `governor` limiter (fast,
    /// no dependency, but per-replica). `"redis"` shares GCRA state across replicas via a Redis
    /// store, so N instances enforce one global limit. `"memory"` uses the same shared-store code
    /// path backed by an in-process map (a single-replica/testing backend). All three honor the
    /// same `rate`/`burst`/route/per-key settings above.
    pub store: String,
    /// Redis connection URL for `store = "redis"`, e.g. `redis://host:6379` or (TLS)
    /// `rediss://host:6379`. Prefer the `EDGEGUARD_REDIS_URL` env var over this file.
    pub redis_url: String,
    /// Key prefix/namespace for the shared store, so multiple EdgeGuard deployments can share one
    /// Redis without colliding. Keys look like `<prefix>:ip:<addr>`.
    pub redis_prefix: String,
    /// What to do when the shared store is unreachable. `false` (default) fails **closed** — a
    /// store error returns `503`, so an outage can't silently disable rate limiting. `true` fails
    /// **open** — a store error allows the request (favor availability over strict limiting).
    /// Only relevant for `store = "redis"`.
    pub fail_open: bool,
}

/// A per-route rate-limit override (matched by path prefix).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RouteRateLimit {
    /// Path prefix this limit applies to, e.g. "/api/".
    pub path: String,
    pub rate: String,
    pub burst: u32,
}

impl Default for RouteRateLimit {
    fn default() -> Self {
        RouteRateLimit {
            path: String::new(),
            rate: "60/min".into(),
            burst: 20,
        }
    }
}

/// Per-principal rate limit (keyed by API-key id / JWT subject).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PerKeyRateLimit {
    pub enabled: bool,
    pub rate: String,
    pub burst: u32,
}

impl Default for PerKeyRateLimit {
    fn default() -> Self {
        PerKeyRateLimit {
            enabled: false,
            rate: "1000/hour".into(),
            burst: 100,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ValidationCfg {
    /// e.g. "2MiB". Requests with a larger body are rejected with 413.
    pub max_body: String,
    /// Cap on the upstream response body EdgeGuard buffers, e.g. "16MiB". "0" disables
    /// the cap (unbounded). Protects against an upstream OOM-ing the proxy; raise it if
    /// you proxy large downloads.
    pub max_response_body: String,
    /// Max time to wait for the upstream response and to read its body, e.g. "30s",
    /// "500ms", "2m". "0" disables the timeout. Bounds a stalled upstream so it can't pin a
    /// handler task indefinitely; on elapse the proxy returns 504.
    pub upstream_timeout: String,
    /// Cap on the total size of incoming request headers (sum of name + value bytes), e.g.
    /// "32KiB". "0" disables the cap (default). Requests over the limit get `431`. This is a
    /// policy limit enforced by EdgeGuard on top of hyper's own transport-level header cap.
    pub max_header_bytes: String,
    /// Allowed HTTP methods; empty list means allow all.
    pub allow_methods: Vec<String>,
    /// Stream (don't buffer) responses whose `Content-Type` is `text/event-stream`. Off by
    /// default: the proxy normally buffers the whole upstream body so it can cap size
    /// (`max_response_body`) and account exact egress bytes. That buffering defeats Server-Sent
    /// Events / chunked streaming — the client only sees the body once the upstream finishes.
    /// Turn this on to forward SSE responses frame-by-frame as they arrive (preserving
    /// time-to-first-byte). When a response is streamed this way the `max_response_body` cap and
    /// the body-read deadline don't apply (the connect/first-byte `upstream_timeout` still
    /// does); egress bytes are tallied as frames flow. Non-SSE responses are unaffected.
    pub stream_passthrough: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HeadersCfg {
    pub hsts: bool,
    pub csp: String,
    /// Send the CSP as `Content-Security-Policy-Report-Only` instead of enforcing it. Lets
    /// you roll out / tighten a policy by collecting violations first without breaking the
    /// page.
    pub csp_report_only: bool,
    /// If set, a `report-uri <value>` directive is appended to the CSP so browsers POST
    /// violation reports there. Point it at EdgeGuard's own sink ("/__edgeguard/csp-report")
    /// to have them logged, or at any external collector.
    pub csp_report_uri: String,
    pub referrer_policy: String,
    pub permissions_policy: String,
    pub frame_options: String,
    pub force_secure_cookies: bool,
    /// Response headers to strip (case-insensitive), e.g. ["Server", "X-Powered-By"].
    pub strip: Vec<String>,
}

impl Default for ServerCfg {
    fn default() -> Self {
        ServerCfg {
            port: 8080,
            app_port: 3000,
            upstream: String::new(),
            trust_forwarded_for: false,
            admin_port: 0,
            admin_addr: "127.0.0.1".into(),
        }
    }
}

impl Default for AuthCfg {
    fn default() -> Self {
        AuthCfg {
            mode: "none".into(),
            realm: "EdgeGuard".into(),
            users: BTreeMap::new(),
            api_keys: vec![],
            api_key_header: "X-API-Key".into(),
            jwt: JwtCfg::default(),
        }
    }
}

impl Default for JwtCfg {
    fn default() -> Self {
        JwtCfg {
            algorithm: "HS256".into(),
            secret: String::new(),
            public_key_pem: String::new(),
            jwks_url: String::new(),
            jwks_cache_secs: 300,
            issuer: String::new(),
            audience: String::new(),
            leeway_secs: 60,
        }
    }
}

impl Default for RateLimitCfg {
    fn default() -> Self {
        RateLimitCfg {
            enabled: true,
            rate: "60/min".into(),
            burst: 20,
            routes: vec![],
            per_key: PerKeyRateLimit::default(),
            store: "local".into(),
            redis_url: "redis://127.0.0.1:6379".into(),
            redis_prefix: "edgeguard".into(),
            fail_open: false,
        }
    }
}

impl Default for ValidationCfg {
    fn default() -> Self {
        ValidationCfg {
            max_body: "2MiB".into(),
            max_response_body: "0".into(),
            upstream_timeout: "30s".into(),
            max_header_bytes: "0".into(),
            allow_methods: vec![],
            stream_passthrough: false,
        }
    }
}

impl Default for HeadersCfg {
    fn default() -> Self {
        HeadersCfg {
            hsts: true,
            csp: "default-src 'self'".into(),
            csp_report_only: false,
            csp_report_uri: String::new(),
            referrer_policy: "no-referrer".into(),
            permissions_policy: "geolocation=(), microphone=(), camera=()".into(),
            frame_options: "DENY".into(),
            force_secure_cookies: true,
            strip: vec!["Server".into(), "X-Powered-By".into()],
        }
    }
}

/// TLS termination. When `enabled`, EdgeGuard serves HTTPS on the public port using a
/// certificate either loaded from `cert_path`/`key_path` or obtained automatically via ACME.
/// All-default fields (disabled, empty paths, default ACME) so `Default` is derivable.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TlsCfg {
    pub enabled: bool,
    /// PEM certificate chain (leaf first). When ACME is enabled this is where the obtained
    /// certificate is written/read.
    pub cert_path: String,
    /// PEM private key (PKCS#8/PKCS#1/SEC1).
    pub key_path: String,
    pub acme: AcmeCfg,
}

/// Automatic certificate management (ACME / Let's Encrypt) via the HTTP-01 challenge. The
/// obtained certificate is written to `TlsCfg::cert_path`/`key_path` and served by the TLS
/// listener; a background task renews it before expiry.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AcmeCfg {
    pub enabled: bool,
    /// Domains to request a certificate for (the first is the primary CN).
    pub domains: Vec<String>,
    /// Contact email for the ACME account (registration + expiry notices).
    pub email: String,
    /// ACME directory URL. Defaults to Let's Encrypt **staging** so a misconfiguration can't
    /// burn the strict production rate limits; switch to production explicitly.
    pub directory_url: String,
    /// Directory for the cached ACME account key (so renewals reuse the same account).
    pub cache_dir: String,
    /// You must set this to `true` to signify acceptance of the ACME provider's Terms of
    /// Service; EdgeGuard refuses to register otherwise.
    pub accept_tos: bool,
}

impl Default for AcmeCfg {
    fn default() -> Self {
        AcmeCfg {
            enabled: false,
            domains: vec![],
            email: String::new(),
            // Let's Encrypt staging — safe default; see the field doc.
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            cache_dir: "./acme".into(),
            accept_tos: false,
        }
    }
}

/// WAF-lite input inspection (Phase 4 / v2). Screens a request for common attack signatures
/// before it is forwarded, using built-in heuristic rulesets (SQLi/XSS/path-traversal) plus
/// any operator-defined deny patterns. Disabled by default — these are heuristics, so the
/// intended rollout is `report` (log + count matches without blocking) until the operator is
/// confident, then `block` (return `403`). Compiled into a `crate::waf::WafEngine`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WafCfg {
    /// "off" (default) | "report" | "block". `report` evaluates rules and logs/counts matches
    /// but forwards the request anyway; `block` rejects a matching request with `403`.
    pub mode: String,
    /// Enable the built-in SQL-injection heuristic ruleset.
    pub sqli: bool,
    /// Enable the built-in cross-site-scripting heuristic ruleset.
    pub xss: bool,
    /// Enable the built-in path-traversal heuristic ruleset.
    pub path_traversal: bool,
    /// Inspect the request path + query string (matched raw and percent-decoded). Default true.
    pub inspect_path: bool,
    /// Inspect request header values. Off by default: header bytes (cookies, tokens, opaque
    /// blobs) are noisy and prone to false positives.
    pub inspect_headers: bool,
    /// Inspect the request body (already capped by `validation.max_body`). Off by default.
    pub inspect_body: bool,
    /// Operator-defined deny patterns, evaluated alongside the enabled built-in rulesets.
    pub rules: Vec<WafRule>,
}

/// A single operator-defined WAF deny pattern (a `[[waf.rules]]` entry).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WafRule {
    /// Identifier reported in logs/metrics when this rule matches (defaults to `custom-<n>`).
    pub id: String,
    /// Regular expression (RE2 syntax: linear-time, no backreferences/lookaround, so it can't
    /// ReDoS the proxy). A request matching it in any targeted location is treated as a hit.
    pub pattern: String,
    /// Request location to match against: "path" (path+query, default), "headers", "body", or
    /// "all". A location is only examined when its `inspect_*` flag above is also enabled.
    pub target: String,
}

impl Default for WafCfg {
    fn default() -> Self {
        WafCfg {
            mode: "off".into(),
            sqli: true,
            xss: true,
            path_traversal: true,
            inspect_path: true,
            inspect_headers: false,
            inspect_body: false,
            rules: vec![],
        }
    }
}

impl Default for WafRule {
    fn default() -> Self {
        WafRule {
            id: String::new(),
            pattern: String::new(),
            target: "path".into(),
        }
    }
}

impl Config {
    /// Load defaults, overlay an optional TOML file, then apply env overrides.
    pub fn load(path: Option<&str>) -> Result<Config> {
        let mut cfg = if let Some(p) = path {
            let raw =
                std::fs::read_to_string(p).with_context(|| format!("reading config file {p}"))?;
            toml::from_str::<Config>(&raw).with_context(|| format!("parsing config file {p}"))?
        } else {
            Config::default()
        };

        if let Ok(p) = env::var("PORT") {
            if let Ok(v) = p.parse() {
                cfg.server.port = v;
            }
        }
        if let Ok(p) = env::var("APP_PORT") {
            if let Ok(v) = p.parse() {
                cfg.server.app_port = v;
            }
        }
        if let Ok(p) = env::var("ADMIN_PORT") {
            if let Ok(v) = p.parse() {
                cfg.server.admin_port = v;
            }
        }
        if let Ok(u) = env::var("UPSTREAM") {
            if !u.is_empty() {
                cfg.server.upstream = u;
            }
        }
        // Keep secrets out of the config file: let the environment supply them.
        if let Ok(s) = env::var("EDGEGUARD_JWT_SECRET") {
            if !s.is_empty() {
                cfg.auth.jwt.secret = s;
            }
        }
        if let Ok(u) = env::var("EDGEGUARD_REDIS_URL") {
            if !u.is_empty() {
                cfg.ratelimit.redis_url = u;
            }
        }
        if let Ok(keys) = env::var("EDGEGUARD_API_KEYS") {
            let keys: Vec<String> = keys
                .split(',')
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .collect();
            if !keys.is_empty() {
                cfg.auth.api_keys = keys;
            }
        }
        if let Ok(t) = env::var("EDGEGUARD_CP_EDGE_TOKEN") {
            if !t.is_empty() {
                cfg.control_plane.edge_token = t;
            }
        }
        if let Ok(u) = env::var("EDGEGUARD_CP_URL") {
            if !u.is_empty() {
                cfg.control_plane.url = u;
            }
        }
        Ok(cfg)
    }

    /// Produce an effective config by overlaying a control-plane-pushed *policy* document onto
    /// this (local) config: the policy sections (`auth`/`ratelimit`/`validation`/`headers`/`waf`)
    /// come from the pushed TOML; `server`/`tls`/`control_plane` stay local (the control plane
    /// manages security policy, not this edge's listener/plumbing). The result feeds the normal
    /// `build_runtime` + hot-swap path, so a malformed policy is rejected like any bad reload.
    pub fn with_policy_from(&self, policy_toml: &str) -> Result<Config> {
        let p: Config =
            toml::from_str(policy_toml).context("parsing control-plane policy document")?;
        Ok(Config {
            server: self.server.clone(),
            tls: self.tls.clone(),
            control_plane: self.control_plane.clone(),
            auth: p.auth,
            ratelimit: p.ratelimit,
            validation: p.validation,
            headers: p.headers,
            waf: p.waf,
        })
    }

    /// The upstream base URL EdgeGuard forwards to, e.g. "http://127.0.0.1:3000".
    pub fn upstream_base(&self) -> String {
        if self.server.upstream.is_empty() {
            format!("http://127.0.0.1:{}", self.server.app_port)
        } else {
            self.server.upstream.trim_end_matches('/').to_string()
        }
    }

    /// The `(host, port)` EdgeGuard probes for readiness, mirroring [`Self::upstream_base`]:
    /// co-process mode probes `127.0.0.1:app_port`; an explicit upstream URL is parsed,
    /// defaulting the port from the scheme. Returns `None` if the URL carries no usable
    /// host, so the readiness check reports "not ready" rather than panicking.
    pub fn upstream_probe_addr(&self) -> Option<(String, u16)> {
        if self.server.upstream.is_empty() {
            Some(("127.0.0.1".to_string(), self.server.app_port))
        } else {
            parse_host_port(&self.server.upstream)
        }
    }
}

/// Extract `(host, port)` from an upstream URL like `http://host:3000/base`. Only the
/// scheme (for the default port), host, and port are needed — any path is ignored. Handles
/// bracketed IPv6 literals (`http://[::1]:3000`). This is deliberately small rather than a
/// full URL parser; the proxy itself is HTTP-only in v0.
fn parse_host_port(url: &str) -> Option<(String, u16)> {
    let (default_port, rest) = if let Some(r) = url.strip_prefix("http://") {
        (80u16, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (443u16, r)
    } else {
        (80u16, url)
    };
    // Authority is everything up to the first '/'; drop any `user:pass@` userinfo.
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    // Bracketed IPv6 literal: `[::1]` or `[::1]:port`.
    if let Some(after) = authority.strip_prefix('[') {
        let (host, tail) = after.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        // Reject an empty host (e.g. `http://:3000`) rather than deferring the failure to a
        // connect call — the "usable host" contract is checked here.
        Some((host, port)) if !host.is_empty() => Some((host.to_string(), port.parse().ok()?)),
        Some(_) => None,
        None => Some((authority.to_string(), default_port)),
    }
}

/// Parse a human size like "2MiB", "512KB", "1048576" into bytes.
pub fn parse_size(s: &str) -> Result<usize> {
    let s = s.trim();
    let (num, mult): (&str, usize) = if let Some(n) = s.strip_suffix("GiB") {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("MiB") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("KiB") {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix("GB") {
        (n, 1_000_000_000)
    } else if let Some(n) = s.strip_suffix("MB") {
        (n, 1_000_000)
    } else if let Some(n) = s.strip_suffix("KB") {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix('B') {
        (n, 1)
    } else {
        (s, 1)
    };
    let n: usize = num
        .trim()
        .parse()
        .with_context(|| format!("invalid size: {s}"))?;
    n.checked_mul(mult)
        .with_context(|| format!("size too large: {s}"))
}

/// Parse a rate like "60/min" into (count, period).
pub fn parse_rate(s: &str) -> Result<(u32, Duration)> {
    let (n, unit) = s
        .split_once('/')
        .with_context(|| format!("invalid rate (expected N/unit): {s}"))?;
    let count: u32 = n
        .trim()
        .parse()
        .with_context(|| format!("invalid rate count: {s}"))?;
    let period = match unit.trim() {
        "s" | "sec" | "second" => Duration::from_secs(1),
        "m" | "min" | "minute" => Duration::from_secs(60),
        "h" | "hour" => Duration::from_secs(3600),
        other => anyhow::bail!("unsupported rate unit: {other}"),
    };
    Ok((count, period))
}

/// Parse a timeout like "30s", "500ms", "2m", or a bare number of seconds ("45"). "0"
/// yields a zero duration, which callers treat as "disabled".
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    // Order matters: check "ms" before the single-char "s"/"m" suffixes.
    if let Some(n) = s.strip_suffix("ms") {
        let ms: u64 = n
            .trim()
            .parse()
            .with_context(|| format!("invalid duration: {s}"))?;
        Ok(Duration::from_millis(ms))
    } else if let Some(n) = s.strip_suffix('s') {
        let secs: u64 = n
            .trim()
            .parse()
            .with_context(|| format!("invalid duration: {s}"))?;
        Ok(Duration::from_secs(secs))
    } else if let Some(n) = s.strip_suffix('m') {
        let mins: u64 = n
            .trim()
            .parse()
            .with_context(|| format!("invalid duration: {s}"))?;
        let secs = mins
            .checked_mul(60)
            .with_context(|| format!("duration too large: {s}"))?;
        Ok(Duration::from_secs(secs))
    } else {
        let secs: u64 = s
            .parse()
            .with_context(|| format!("invalid duration: {s}"))?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_units_and_plain_bytes() {
        assert_eq!(parse_size("0").unwrap(), 0);
        assert_eq!(parse_size("1048576").unwrap(), 1_048_576);
        assert_eq!(parse_size("512B").unwrap(), 512);
        assert_eq!(parse_size("1KB").unwrap(), 1_000);
        assert_eq!(parse_size("1KiB").unwrap(), 1_024);
        assert_eq!(parse_size("2MiB").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size("16MiB").unwrap(), 16 * 1024 * 1024);
        assert_eq!(parse_size("1GiB").unwrap(), 1024 * 1024 * 1024);
        // surrounding / internal whitespace is tolerated
        assert_eq!(parse_size("  4 MiB ").unwrap(), 4 * 1024 * 1024);
    }

    #[test]
    fn parse_size_rejects_garbage_and_overflow() {
        assert!(parse_size("abc").is_err());
        assert!(parse_size("MiB").is_err());
        // would overflow usize -> Err, not a silent wrap
        assert!(parse_size("99999999999999999999GiB").is_err());
    }

    #[test]
    fn parse_rate_counts_and_units() {
        assert_eq!(parse_rate("60/min").unwrap(), (60, Duration::from_secs(60)));
        assert_eq!(parse_rate("10/sec").unwrap(), (10, Duration::from_secs(1)));
        assert_eq!(
            parse_rate("1000/hour").unwrap(),
            (1000, Duration::from_secs(3600))
        );
        // short and long unit spellings, plus tolerated whitespace
        assert_eq!(parse_rate(" 5 / m ").unwrap(), (5, Duration::from_secs(60)));
    }

    #[test]
    fn parse_rate_rejects_garbage() {
        assert!(parse_rate("60").is_err()); // no unit
        assert!(parse_rate("x/min").is_err()); // bad count
        assert!(parse_rate("60/year").is_err()); // bad unit
    }

    #[test]
    fn probe_addr_defaults_to_app_port_in_coprocess_mode() {
        let cfg = Config::default();
        assert_eq!(
            cfg.upstream_probe_addr(),
            Some(("127.0.0.1".to_string(), cfg.server.app_port))
        );
    }

    #[test]
    fn parse_host_port_handles_schemes_paths_and_ipv6() {
        assert_eq!(
            parse_host_port("http://127.0.0.1:3000"),
            Some(("127.0.0.1".to_string(), 3000))
        );
        // a trailing path is ignored
        assert_eq!(
            parse_host_port("http://app.internal:8080/health"),
            Some(("app.internal".to_string(), 8080))
        );
        // port defaults from the scheme
        assert_eq!(
            parse_host_port("https://example.com"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_host_port("http://example.com"),
            Some(("example.com".to_string(), 80))
        );
        // bracketed IPv6 literal, with and without an explicit port
        assert_eq!(
            parse_host_port("http://[::1]:3000"),
            Some(("::1".to_string(), 3000))
        );
        assert_eq!(
            parse_host_port("http://[2001:db8::1]"),
            Some(("2001:db8::1".to_string(), 80))
        );
    }

    #[test]
    fn parse_host_port_rejects_empty_or_unusable_host() {
        // empty host (port only) is not a usable probe target
        assert_eq!(parse_host_port("http://:3000"), None);
        // non-numeric port
        assert_eq!(parse_host_port("http://host:notaport"), None);
    }

    #[test]
    fn parse_duration_units_and_bare_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
        // "0" disables (zero duration); callers map it to "no timeout"
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("  10s ").unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn with_policy_from_keeps_local_plumbing_takes_policy() {
        let mut local = Config::default();
        local.server.port = 9999;
        local.server.upstream = "http://up:1".into();
        local.control_plane.enabled = true;
        // A pushed policy that changes auth + disables rate limiting.
        let policy = "[auth]\nmode = \"apikey\"\n\n[ratelimit]\nenabled = false\n";
        let merged = local.with_policy_from(policy).unwrap();
        // Local server / control-plane settings are preserved...
        assert_eq!(merged.server.port, 9999);
        assert_eq!(merged.server.upstream, "http://up:1");
        assert!(merged.control_plane.enabled);
        // ...while the policy sections are taken from the pushed document.
        assert_eq!(merged.auth.mode, "apikey");
        assert!(!merged.ratelimit.enabled);
    }

    #[test]
    fn with_policy_from_rejects_bad_toml() {
        assert!(Config::default()
            .with_policy_from("not = valid = toml")
            .is_err());
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("s").is_err());
    }
}
