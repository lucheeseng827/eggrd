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
    /// Optional per-path-prefix upstream overrides. Empty by default (everything goes to the
    /// single `server.upstream`/`app_port`). A common use: `/api` → a backend, everything else →
    /// a static frontend. Longest matching prefix wins; no match falls back to the default
    /// upstream. This is a static prefix map, not a service mesh — see [`UpstreamRoute`].
    pub upstreams: Vec<UpstreamRoute>,
    /// IP allow/deny lists (CIDR). Empty by default (allow all); when set, requests are gated by
    /// client IP before auth/rate-limit. See [`AccessCfg`].
    pub access: AccessCfg,
    /// Cross-Origin Resource Sharing policy. Off by default; when enabled, EdgeGuard answers
    /// browser preflights and decorates responses so a separate-origin frontend can call the
    /// app it fronts. See [`CorsCfg`].
    pub cors: CorsCfg,
    /// Optional "managed mode": pull policy from / report metrics to a remote control plane. Off
    /// by default; the edge is a standalone proxy unless this is configured.
    pub control_plane: ControlPlaneCfg,
    /// Optional LLM token metering (gateway L0). Off by default; when enabled, OpenAI-compatible
    /// traffic is parsed to meter tokens + cost (metering only — never blocks). See [`LlmCfg`].
    pub llm: LlmCfg,
    /// Optional outbound alerting (gateway L4). Off by default; when enabled with a webhook, the
    /// gateway fires a Slack-compatible alert when a hard budget nears its limit. See [`AlertsCfg`].
    pub alerts: AlertsCfg,
}

/// Outbound alerting (`[alerts]`). When `enabled` with a `webhook_url`, EdgeGuard POSTs a
/// Slack-compatible alert (`{ "text": … }`) when a hard-budget's consumed ratio (`used/limit`)
/// crosses `budget_consumed_threshold` — cost-regression alerting entirely in your own VPC (no SaaS
/// alerting plane; the confirmed Phoenix gap of gating alerting behind a paid cloud). Fire-and-forget
/// and **edge-triggered** (one alert per crossing into the alert zone, not one per request). Off by
/// default. A first cut on budget breaches; latency-percentile / error-rate / eval-drift rules follow.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AlertsCfg {
    /// Master switch. Default false.
    pub enabled: bool,
    /// Slack incoming-webhook URL (or any endpoint accepting `{ "text": … }`). Required when enabled.
    pub webhook_url: String,
    /// Fire when a budget's consumed ratio (`used/limit`) reaches this (`0.0`–`1.0+`). Default `0.9`.
    pub budget_consumed_threshold: f64,
    /// Per-emit timeout for the background POST, in milliseconds. Default 2000.
    pub timeout_ms: u64,
}

impl Default for AlertsCfg {
    fn default() -> Self {
        AlertsCfg {
            enabled: false,
            webhook_url: String::new(),
            budget_consumed_threshold: 0.9,
            timeout_ms: 2000,
        }
    }
}

/// LLM token-metering settings (`[llm]`). When `enabled`, the proxy parses OpenAI-compatible
/// request/response bodies to count tokens (from the upstream's `usage` object) and, for any model
/// listed in `[llm.models]`, the cost. Metering is observe-only: it never blocks or alters traffic.
/// An unmapped model still has its tokens counted (cost is simply omitted).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LlmCfg {
    pub enabled: bool,
    /// Wire format. Only `"openai"` is understood today (the default).
    pub api_style: String,
    /// Per-model price book, keyed by the `model` string clients send. Prices are USD per
    /// 1,000,000 tokens. Example:
    /// `[llm.models."gpt-4o"]` `input_per_1m = 2.5` / `output_per_1m = 10.0`.
    pub models: BTreeMap<String, ModelPrice>,
    /// What to do with a request whose `model` is **not** in `[llm.models]`: `"count"` (default —
    /// meter tokens, omit cost, forward the request) or `"block"` (reject `402` before it reaches the
    /// upstream, so an unpriced model is never served at a silent `$0`). `"block"` only bites when a
    /// price book is configured — a metering-only deployment (empty `[llm.models]`) never rejects.
    pub on_unpriced_model: String,
    /// Hard token/cost budgets (gateway L1). Empty by default (no enforcement — L0 metering only).
    /// Each `[[llm.budgets]]` is a ceiling enforced fail-closed via reserve→reconcile. See [`BudgetCfg`].
    pub budgets: Vec<BudgetCfg>,
    /// Budget store backend: `"memory"` (single replica / default) or `"redis"` (shared across
    /// replicas — required for a true fleet-wide cap). `"local"` is treated as `"memory"`.
    pub store: String,
    /// Redis URL when `store = "redis"`, e.g. `redis://127.0.0.1:6379`. Note: `EDGEGUARD_REDIS_URL`
    /// only overrides `ratelimit.redis_url`, not this key — set it here (or via pushed policy).
    pub redis_url: String,
    /// Key prefix for budget keys in Redis (namespacing a shared server). Defaults to `edgeguard`.
    pub redis_prefix: String,
    /// On a budget-store error, allow the request (`true`) or reject it `503` (`false`, the default
    /// — fail-closed, so an outage can't silently uncap spend).
    pub fail_open: bool,
    /// Completion tokens to assume when a request omits `max_tokens`, used only for the *reserve*
    /// estimate (the reservation is reconciled to actual usage afterward). Default 1024.
    pub default_max_tokens: u64,
    /// Request header carrying the **team / tag** a request is attributed to, for the per-team budget
    /// scope and team chargeback. Case-insensitive; default `x-edgeguard-team`. A request without it
    /// falls into the shared `_none` team bucket.
    pub team_header: String,
    /// BYO-key vault + egress governance (gateway L2). Empty by default (no vault). Each
    /// `[[llm.keys]]` maps a client-facing **virtual key** to a real **provider key** (injected
    /// upstream, never returned to the client) plus an optional per-key model egress allowlist.
    /// When any key is configured, every proxied request must present a known virtual key. See
    /// [`KeyEntryCfg`].
    pub keys: Vec<KeyEntryCfg>,
    /// Edge DLP — PII / secret detection + redaction (gateway L3). Off by default. See [`DlpCfg`].
    pub dlp: DlpCfg,
    /// OTLP span emission (gateway L4) — SDK-free tracing to an OTel-native store. Off by default.
    /// See [`TelemetryCfg`].
    pub telemetry: TelemetryCfg,
}

/// OTLP span emission (`[llm.telemetry]`). When `enabled`, the gateway emits one OpenInference/OTLP
/// span per metered LLM request to `endpoint` (an OTLP/HTTP `/v1/traces` receiver — e.g. evald),
/// carrying the model, per-tier tokens, computed cost, and server-side TTFT/TPOT/latency already
/// attached. Because the proxy sits in the request path, this needs **no** client SDK and is immune
/// to the import-order / per-framework instrumentor drift that plagues in-process instrumentation.
/// Emission is fire-and-forget — it never blocks or fails the client response. Off by default.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TelemetryCfg {
    /// Master switch. Default false.
    pub enabled: bool,
    /// OTLP/HTTP traces endpoint, e.g. `http://127.0.0.1:4318/v1/traces`. Required when `enabled`.
    pub endpoint: String,
    /// Fraction of LLM requests to emit a span for, `0.0`–`1.0` (deterministic per-trace sampling —
    /// the same trace always gets the same verdict). Default `1.0` (all).
    pub sample_rate: f64,
    /// `service.name` resource attribute on emitted spans. Default `edgeguard`.
    pub service_name: String,
    /// Capture the (DLP-redacted) prompt/response as `input.value`/`output.value` on the span. Off by
    /// default — content leaves the gateway only when this is explicitly enabled, and when an
    /// `[llm.dlp]` engine is configured the captured content is redacted before it is emitted.
    pub capture_content: bool,
    /// Cap on each captured content field in bytes (truncated past this). Default 8192.
    pub max_content_bytes: usize,
    /// Per-emit timeout for the background POST, in milliseconds. Default 2000.
    pub timeout_ms: u64,
}

impl Default for TelemetryCfg {
    fn default() -> Self {
        TelemetryCfg {
            enabled: false,
            endpoint: String::new(),
            sample_rate: 1.0,
            service_name: "edgeguard".into(),
            capture_content: false,
            max_content_bytes: 8192,
            timeout_ms: 2000,
        }
    }
}

/// Edge-DLP settings (`[llm.dlp]`). When `mode` is not `off`, request and/or response bodies are
/// scanned for PII and secrets; the `mode` decides what happens on a finding (report / block /
/// redact). See [`crate::dlp`].
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DlpCfg {
    /// `off` | `report` | `block` | `redact`. Default `off`.
    pub mode: String,
    /// How a span is rewritten in `redact` mode: `full` (`[REDACTED:<cat>]`, default) | `mask`
    /// (keep last 4) | `hash` (stable opaque token). See [`crate::dlp::RedactStyle`].
    pub redact_style: String,
    /// Scan the inbound request body (the prompt). Default true.
    pub scan_request: bool,
    /// Scan the (buffered) response body and, in report mode, streamed frames. Default true.
    pub scan_response: bool,
    /// In `redact` mode, also rewrite *streamed* SSE frames (not just buffered bodies). Deterministic
    /// detectors only — NER never runs on the stream. Off by default: streaming redaction can only
    /// rewrite spans the carry buffer fully contains, so enable it deliberately. See [`crate::dlp`].
    pub stream_redact: bool,
    /// **Reversible masking** (`redact` mode only). When on, an inbound finding is replaced with a
    /// stable placeholder token (`<edgeguard-<cat>-<n>>`) instead of an irreversible `[REDACTED]`
    /// tag, and the placeholder→original map is kept for the request so the **response is unmasked**
    /// (buffered *and* streamed) back to the original value. The provider never sees the PII; the
    /// client gets its own data back — the round-trip `litellm#22821` gets wrong. Off by default.
    /// When on, the response is unmasked rather than re-scanned/redacted (restore, not detect).
    pub reversible: bool,
    /// Built-in detectors.
    pub detect_email: bool,
    pub detect_credit_card: bool,
    /// Require the Luhn checksum before flagging a digit run as a card (cuts false positives).
    /// Default true.
    pub luhn_validate_credit_card: bool,
    /// AWS keys, provider-style `xx-…` keys, and private-key blocks.
    pub detect_secrets: bool,
    /// US SSN (`NNN-NN-NNNN`). Default true.
    pub detect_ssn: bool,
    /// Phone numbers. Off by default — false-positives on ordinary numeric runs.
    pub detect_phone: bool,
    /// IBAN account numbers. Off by default — false-positives on uppercase+digit tokens.
    pub detect_iban: bool,
    /// High-entropy token sweep (catch-all). Off by default — can false-positive.
    pub detect_high_entropy: bool,
    /// Prompt-injection / jailbreak heuristics for agent traffic (a small, high-precision built-in
    /// deny set — "ignore previous instructions", "reveal your system prompt", etc.), reported under
    /// the `prompt_injection` category. Off by default (opt-in, report-first) since instructions to a
    /// model are legitimate traffic; enable and watch the counter before moving to `block`.
    pub detect_prompt_injection: bool,
    /// Minimum token length the entropy sweep considers.
    pub entropy_min_len: usize,
    /// Per-character Shannon-entropy threshold (bits) for the entropy sweep.
    pub entropy_threshold: f64,
    /// Dictionary deny-list: literal terms matched case-insensitively (Aho-Corasick), reported under
    /// the `gazetteer` category. The fast, many-term path for known names / codenames / identifiers.
    pub gazetteer_terms: Vec<String>,
    /// Extra regexes (linear-time `regex` syntax), all reported under the `custom` category.
    pub custom_patterns: Vec<String>,
    /// Optional ML NER family (`[llm.dlp.ner]`). Requires the `ner` cargo feature; catches
    /// person/address/org spans regex can't. See [`NerCfg`].
    pub ner: NerCfg,
}

impl Default for DlpCfg {
    fn default() -> Self {
        DlpCfg {
            mode: "off".into(),
            redact_style: "full".into(),
            scan_request: true,
            scan_response: true,
            stream_redact: false,
            reversible: false,
            detect_email: true,
            detect_credit_card: true,
            luhn_validate_credit_card: true,
            detect_secrets: true,
            detect_ssn: true,
            detect_phone: false,
            detect_iban: false,
            detect_high_entropy: false,
            detect_prompt_injection: false,
            entropy_min_len: 24,
            entropy_threshold: 4.0,
            gazetteer_terms: Vec::new(),
            custom_patterns: Vec::new(),
            ner: NerCfg::default(),
        }
    }
}

/// ML NER settings (`[llm.dlp.ner]`). Off by default. When `enabled`, the proxy must be built with
/// `--features ner`; otherwise startup fails with a clear error rather than running regex-only while
/// the operator believes ML coverage is active. The model is an ONNX token-classification (BIO) NER
/// network run through the pure-Rust [`edgeguard_ner`] crate.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NerCfg {
    /// Turn the NER family on. Requires the `ner` feature.
    pub enabled: bool,
    /// Path to the ONNX model file.
    pub model_path: String,
    /// Path to the HuggingFace `tokenizer.json`.
    pub tokenizer_path: String,
    /// Per-class label list in model id order (e.g. `["O","B-PER","I-PER","B-LOC", …]`). Used to map
    /// argmax class ids back to entity labels.
    pub labels: Vec<String>,
    /// Confidence floor in `[0.0, 1.0]`; spans below it are dropped. Default 0.5.
    pub threshold: f32,
    /// Max tokens fed to the model per scan (longer inputs are truncated). Default 256.
    pub max_seq_len: usize,
}

impl Default for NerCfg {
    fn default() -> Self {
        NerCfg {
            enabled: false,
            model_path: String::new(),
            tokenizer_path: String::new(),
            labels: Vec::new(),
            threshold: 0.5,
            max_seq_len: 256,
        }
    }
}

impl Default for LlmCfg {
    fn default() -> Self {
        LlmCfg {
            enabled: false,
            api_style: "openai".into(),
            models: BTreeMap::new(),
            on_unpriced_model: "count".into(),
            budgets: Vec::new(),
            store: "memory".into(),
            redis_url: String::new(),
            redis_prefix: "edgeguard".into(),
            fail_open: false,
            default_max_tokens: 1024,
            team_header: "x-edgeguard-team".into(),
            keys: Vec::new(),
            dlp: DlpCfg::default(),
            telemetry: TelemetryCfg::default(),
        }
    }
}

/// One vault entry (`[[llm.keys]]`): a client-facing virtual key mapped to a real provider key and
/// an optional model egress allowlist. The provider key is injected into the upstream `Authorization`
/// and is **never** sent back to the client; the client only ever holds the virtual key.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KeyEntryCfg {
    /// The secret the client presents (`Authorization: Bearer <virtual_key>`). Required.
    pub virtual_key: String,
    /// The real upstream provider secret injected on the way out. Required. Prefer sourcing this
    /// from a pushed control-plane policy / secret store rather than committing it.
    pub provider_key: String,
    /// Allowed model names for this key (egress allowlist). Empty = unrestricted; non-empty = only
    /// these models may be requested (others get `403`).
    pub allowed_models: Vec<String>,
    /// Optional label for logs/metrics/audit (never the secret). Defaults to a positional id.
    pub label: String,
}

/// One hard budget (`[[llm.budgets]]`): a ceiling of `limit` (in `unit`) over `window`, keyed by
/// `scope`. Enforced fail-closed before the request reaches the upstream.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BudgetCfg {
    /// Identifier (also the metric/log label and part of the store key). Required, non-empty.
    pub name: String,
    /// Keying dimension: `"global"`, `"key"` (per authenticated principal), or `"model"`.
    pub scope: String,
    /// `"tokens"` (prompt + completion) or `"usd"` (cost via the price book).
    pub unit: String,
    /// The ceiling, in `unit`: a token count, or — for `unit = "usd"` — dollars (e.g. `25.0`).
    pub limit: f64,
    /// Reset window, e.g. `"1h"`, `"24h"`, `"30d"`. The budget resets at each window boundary.
    pub window: String,
}

impl Default for BudgetCfg {
    fn default() -> Self {
        BudgetCfg {
            name: String::new(),
            scope: "global".into(),
            unit: "tokens".into(),
            limit: 0.0,
            window: "24h".into(),
        }
    }
}

/// One model's price, in USD per 1,000,000 tokens (input and output billed separately, matching
/// provider pricing). Compiled to integer micro-dollars at load (see [`crate::llm`]).
///
/// `cached_per_1m` prices the cached-prompt subset (`prompt_tokens_details.cached_tokens`, usually a
/// steep discount) and `reasoning_per_1m` the reasoning subset (`completion_tokens_details.
/// reasoning_tokens`). Both default to `0.0`, which means **inherit the base input/output rate** —
/// so an existing book prices exactly as before; set them only to apply a provider's separate
/// cached/reasoning rate.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(default)]
pub struct ModelPrice {
    pub input_per_1m: f64,
    pub output_per_1m: f64,
    /// USD per 1M cached prompt tokens. `0.0` = inherit `input_per_1m`.
    pub cached_per_1m: f64,
    /// USD per 1M reasoning tokens. `0.0` = inherit `output_per_1m`.
    pub reasoning_per_1m: f64,
}

/// Managed-mode settings: when `enabled`, the edge pulls its policy from a remote control plane
/// (and hot-reloads it), reports metric deltas, and forwards CSP reports. The policy the control
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
    /// How often to flush a metrics delta, e.g. `"60s"`.
    pub report_interval: String,
    /// Forward received CSP reports to the control plane (default true).
    pub forward_csp: bool,
    /// Enforce the configured quota as a **hard stop**: poll the control plane's
    /// `/v3/edge/{id}/quota` and, while the edge is over its quota, reject the edge's
    /// traffic with `429` (a `Retry-After` reset hint). Off by default — opt in to turn the
    /// rate signal into a hard cap. Prefer `EDGEGUARD_CP_QUOTA_ENFORCE`.
    pub enforce_quota: bool,
    /// How often to poll the quota verdict, e.g. `"30s"`. A failed poll keeps the last verdict, so
    /// a control-plane blip neither over- nor under-enforces.
    pub quota_poll_interval: String,
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
            enforce_quota: false,
            quota_poll_interval: "30s".into(),
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
    /// Tunnel WebSocket (and other `Upgrade`) connections through to the upstream. Off by
    /// default: the normal path strips the hop-by-hop `Upgrade`/`Connection` headers, so an
    /// upgrade request would be forwarded as a plain HTTP request and the handshake would fail.
    /// When on, an authenticated, rate-limited upgrade request is forwarded *with* its upgrade
    /// headers and, on the upstream's `101 Switching Protocols`, EdgeGuard splices the two
    /// connections into a raw bidirectional tunnel. Response hardening / WAF body inspection
    /// don't apply to a tunneled connection (there is no buffered response). Non-upgrade requests
    /// are unaffected.
    pub websocket_passthrough: bool,
    /// gzip-compress responses for clients that send `Accept-Encoding: gzip`. Off by default.
    /// Skips already-compressed content types and (always) `text/event-stream`, so SSE streaming
    /// is never buffered by the compressor. Applied at the listener, so toggling it needs a
    /// restart (it is not part of the hot-reloadable policy).
    pub compress_responses: bool,
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
    /// Add `HttpOnly` to `Set-Cookie` responses that lack it. On by default. Turn off (or use
    /// `httponly_cookie_exempt`) for apps that intentionally expose a cookie to JavaScript —
    /// e.g. a double-submit CSRF token the frontend must read from `document.cookie`.
    pub httponly_cookies: bool,
    /// Cookie NAMES that must never get `HttpOnly`, even when `httponly_cookies` is on. The
    /// surgical exemption for a readable double-submit CSRF cookie, e.g. `["doneyet_csrf"]`.
    /// Names match exactly (cookies are case-sensitive).
    pub httponly_cookie_exempt: Vec<String>,
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
            websocket_passthrough: false,
            compress_responses: false,
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
            httponly_cookies: true,
            httponly_cookie_exempt: Vec::new(),
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
/// listener. Issuance runs at startup only when no certificate exists at `cert_path`;
/// there is **no automatic renewal yet** (see docs/ROADMAP.md) — delete the cert/key files
/// and restart to re-issue.
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

/// A per-path-prefix upstream override (a `[[upstreams]]` entry). Requests whose path starts with
/// `path` are forwarded to `target` instead of the default `server.upstream`; the longest matching
/// prefix wins. This is deliberately a *static prefix map* for the common "static frontend + `/api`
/// backend" shape — not a gateway: no service discovery, load balancing, health-based routing, or
/// request rewriting (the path is forwarded unchanged). For those, put EdgeGuard behind a real
/// gateway/mesh.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UpstreamRoute {
    /// Path prefix this upstream applies to, e.g. `/api/`.
    pub path: String,
    /// Upstream base URL for this prefix, e.g. `http://api.internal:4000`.
    pub target: String,
}

/// IP allow/deny lists, matched against the resolved client IP (the same IP rate limiting keys
/// on — so behind a trusted proxy, set `server.trust_forwarded_for` for this to see the real
/// client). Both lists accept plain IPs (`203.0.113.7`, `::1`) and CIDR ranges
/// (`10.0.0.0/8`, `2001:db8::/32`). `deny` wins over `allow`; a non-empty `allow` means
/// "only these may connect". Both empty (the default) = allow all. Compiled into a
/// `crate::access::AccessPolicy`; an unparseable entry fails at startup/reload.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AccessCfg {
    /// CIDRs/IPs allowed in. Empty = allow all (subject to `deny`).
    pub allow: Vec<String>,
    /// CIDRs/IPs always rejected (takes precedence over `allow`).
    pub deny: Vec<String>,
}

/// Cross-Origin Resource Sharing policy. A drop-in front door commonly sits in front of an app
/// whose browser frontend is served from a *different* origin (a separate static host, a
/// preview URL, `localhost:5173` in dev); without CORS those `fetch` calls are blocked by the
/// browser. When `enabled`, EdgeGuard answers preflight `OPTIONS` requests itself (before auth —
/// preflights carry no credentials) and adds the matching `Access-Control-*` headers to actual
/// responses. Off by default: opening cross-origin access is a deliberate choice. Compiled into
/// a `crate::cors::CorsPolicy`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CorsCfg {
    pub enabled: bool,
    /// Allowed request origins, matched exactly (scheme + host + port), e.g.
    /// `["https://app.example.com"]`. The single entry `["*"]` allows any origin — but a
    /// wildcard cannot be combined with `allow_credentials = true` (the Fetch spec forbids it),
    /// so that combination is rejected at startup.
    pub allow_origins: Vec<String>,
    /// Methods advertised in the preflight `Access-Control-Allow-Methods`. Empty = a sensible
    /// default set (`GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD`).
    pub allow_methods: Vec<String>,
    /// Request headers advertised in `Access-Control-Allow-Headers`. Empty = reflect whatever the
    /// browser asks for in `Access-Control-Request-Headers` (the common, permissive default).
    pub allow_headers: Vec<String>,
    /// Response headers the browser is allowed to read, advertised in
    /// `Access-Control-Expose-Headers`. Empty = none beyond the CORS-safelisted set.
    pub expose_headers: Vec<String>,
    /// Send `Access-Control-Allow-Credentials: true` so the browser may send cookies / HTTP auth.
    /// Requires explicit `allow_origins` (no `"*"`).
    pub allow_credentials: bool,
    /// How long a browser may cache the preflight result, e.g. `"600s"`, `"1h"`. `"0"` omits the
    /// `Access-Control-Max-Age` header (the browser uses its own short default).
    pub max_age: String,
}

impl Default for CorsCfg {
    fn default() -> Self {
        CorsCfg {
            enabled: false,
            allow_origins: vec![],
            allow_methods: vec![],
            allow_headers: vec![],
            expose_headers: vec![],
            allow_credentials: false,
            max_age: "600s".into(),
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
        // Keep secrets out of the config file: let the environment supply them, either directly
        // (`EDGEGUARD_JWT_SECRET`) or from a file (`EDGEGUARD_JWT_SECRET_FILE`) for Docker/K8s
        // secret mounts. The direct variable wins when both are set; see `env_or_file`.
        if let Some(s) = env_or_file("EDGEGUARD_JWT_SECRET")? {
            cfg.auth.jwt.secret = s;
        }
        if let Some(u) = env_or_file("EDGEGUARD_REDIS_URL")? {
            cfg.ratelimit.redis_url = u;
        }
        if let Some(keys) = env_or_file("EDGEGUARD_API_KEYS")? {
            let keys: Vec<String> = keys
                .split(',')
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .collect();
            if !keys.is_empty() {
                cfg.auth.api_keys = keys;
            }
        }
        if let Some(t) = env_or_file("EDGEGUARD_CP_EDGE_TOKEN")? {
            cfg.control_plane.edge_token = t;
        }
        if let Some(u) = env_or_file("EDGEGUARD_CP_URL")? {
            cfg.control_plane.url = u;
        }
        if let Ok(v) = env::var("EDGEGUARD_CP_QUOTA_ENFORCE") {
            // Only an explicit, recognized value overrides the file config; an empty value is a
            // no-op and a typo is a hard error rather than silently disabling a security control.
            match v.trim().to_ascii_lowercase().as_str() {
                "" => {}
                "1" | "true" | "yes" | "on" => cfg.control_plane.enforce_quota = true,
                "0" | "false" | "no" | "off" => cfg.control_plane.enforce_quota = false,
                other => anyhow::bail!(
                    "invalid EDGEGUARD_CP_QUOTA_ENFORCE value {other:?}; expected 1/true/yes/on or 0/false/no/off"
                ),
            }
        }
        Ok(cfg)
    }

    /// Produce an effective config by overlaying a control-plane-pushed *policy* document onto
    /// this (local) config: the policy sections
    /// (`auth`/`ratelimit`/`validation`/`headers`/`waf`/`access`/`cors`) come from the pushed TOML;
    /// `server`/`tls`/`upstreams`/`telemetry`/`control_plane` stay local (the control plane manages
    /// security policy, not this edge's listener/plumbing/topology). The result feeds the normal
    /// `build_runtime` + hot-swap path, so a malformed policy is rejected like any bad reload.
    pub fn with_policy_from(&self, policy_toml: &str) -> Result<Config> {
        let p: Config =
            toml::from_str(policy_toml).context("parsing control-plane policy document")?;
        Ok(Config {
            server: self.server.clone(),
            tls: self.tls.clone(),
            control_plane: self.control_plane.clone(),
            // Upstream topology is edge-local (like `server`), not pushed policy.
            upstreams: self.upstreams.clone(),
            auth: p.auth,
            ratelimit: p.ratelimit,
            validation: p.validation,
            headers: p.headers,
            waf: p.waf,
            access: p.access,
            cors: p.cors,
            // LLM metering is a policy section (the control plane can push a fleet-wide price
            // book) — except `telemetry`, which (like `alerts` below) is edge-local operational
            // config, not fleet-pushed policy: preserve it from the edge rather than letting a
            // pushed policy silently repoint `endpoint`/`capture_content`/`sample_rate`.
            llm: LlmCfg {
                telemetry: self.llm.telemetry.clone(),
                ..p.llm
            },
            // Alerting is edge-local operational config (its webhook is a local secret/endpoint), not
            // fleet-pushed policy — carry it from the edge, like `server`/`tls`.
            alerts: self.alerts.clone(),
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

/// Resolve a secret from the environment, supporting a `*_FILE` indirection for Docker/K8s
/// secret mounts (`EDGEGUARD_JWT_SECRET` *or* `EDGEGUARD_JWT_SECRET_FILE` pointing at a file
/// whose contents are the secret). The direct variable takes precedence when both are set; a
/// `*_FILE` that can't be read is a hard error (a misconfigured secret mount must fail loudly,
/// not silently fall back to no secret). A trailing newline (the common `echo`/editor artifact)
/// is trimmed. Returns `None` when neither is set / both are empty, so the caller keeps the
/// file/default value.
fn env_or_file(name: &str) -> Result<Option<String>> {
    if let Ok(v) = env::var(name) {
        if !v.is_empty() {
            return Ok(Some(v));
        }
    }
    let file_var = format!("{name}_FILE");
    if let Ok(path) = env::var(&file_var) {
        if !path.is_empty() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {file_var} ({path})"))?;
            let trimmed = content.trim_end_matches(['\n', '\r']);
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
    }
    Ok(None)
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
    } else if let Some(n) = s.strip_suffix('h') {
        let hours: u64 = n
            .trim()
            .parse()
            .with_context(|| format!("invalid duration: {s}"))?;
        let secs = hours
            .checked_mul(3_600)
            .with_context(|| format!("duration too large: {s}"))?;
        Ok(Duration::from_secs(secs))
    } else if let Some(n) = s.strip_suffix('d') {
        let days: u64 = n
            .trim()
            .parse()
            .with_context(|| format!("invalid duration: {s}"))?;
        let secs = days
            .checked_mul(86_400)
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
        assert_eq!(parse_duration("3h").unwrap(), Duration::from_secs(10_800));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
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
    fn with_policy_from_keeps_llm_telemetry_edge_local() {
        // Regression: `llm: p.llm` used to take the pushed policy's `llm.telemetry` wholesale,
        // silently repointing `endpoint`/`capture_content`/`sample_rate` even though telemetry
        // is documented as edge-local operational config (like `alerts`), not fleet-pushed
        // policy — a pushed policy could redirect span data to an attacker-controlled endpoint.
        let mut local = Config::default();
        local.llm.telemetry.enabled = true;
        local.llm.telemetry.endpoint = "http://local-collector:4318/v1/traces".into();
        local.llm.telemetry.capture_content = false;
        // A pushed policy that tries to repoint telemetry AND legitimately updates the price book.
        let policy = "[llm]\non_unpriced_model = \"block\"\n\n[llm.telemetry]\nenabled = true\nendpoint = \"http://evil:4318/v1/traces\"\ncapture_content = true\n";
        let merged = local.with_policy_from(policy).unwrap();
        // Telemetry stayed exactly as configured at the edge...
        assert_eq!(
            merged.llm.telemetry.endpoint,
            "http://local-collector:4318/v1/traces"
        );
        assert!(!merged.llm.telemetry.capture_content);
        // ...while the rest of `llm` still took the pushed policy.
        assert_eq!(merged.llm.on_unpriced_model, "block");
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

    #[test]
    fn env_or_file_reads_file_trims_newline_and_prefers_direct() {
        // A uniquely-named var so this doesn't collide with any real config key or another test.
        let name = "EDGEGUARD_TEST_SECRET_QZX";
        let file_var = format!("{name}_FILE");
        let path = std::env::temp_dir().join("edgeguard_test_secret_qzx.txt");
        std::fs::write(&path, "s3cr3t\n").unwrap();

        // No direct var, only *_FILE -> read the file (trailing newline trimmed).
        std::env::remove_var(name);
        std::env::set_var(&file_var, &path);
        assert_eq!(env_or_file(name).unwrap().as_deref(), Some("s3cr3t"));

        // Direct var set -> it wins over the file.
        std::env::set_var(name, "direct");
        assert_eq!(env_or_file(name).unwrap().as_deref(), Some("direct"));

        // Neither set -> None (caller keeps the file/default value).
        std::env::remove_var(name);
        std::env::remove_var(&file_var);
        assert_eq!(env_or_file(name).unwrap(), None);

        // A *_FILE pointing at a missing path is a hard error, not a silent fallback.
        std::env::set_var(&file_var, "/nonexistent/edgeguard/secret");
        assert!(env_or_file(name).is_err());
        std::env::remove_var(&file_var);

        let _ = std::fs::remove_file(&path);
    }
}
