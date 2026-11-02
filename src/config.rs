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
    /// TLS from EdgeGuard to `https://` upstreams: which CAs to trust, the client certificate to
    /// present (mutual TLS), and the name to verify. See [`UpstreamTlsCfg`].
    pub upstream_tls: UpstreamTlsCfg,
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
    /// What the access log records. Defaults to redacting credential-shaped query parameters —
    /// see [`LogCfg`].
    pub log: LogCfg,
    /// One OTLP SERVER span per proxied request. Off by default. See [`TracingCfg`].
    pub tracing: TracingCfg,
    /// Metrics beyond the Prometheus endpoint. See [`MetricsCfg`].
    pub metrics: MetricsCfg,
    /// A client certificate a load balancer verified and forwarded in a header, trusted only from
    /// the load balancer's addresses. Off by default. See [`TrustedClientCertHeaderCfg`].
    pub trusted_client_cert_header: TrustedClientCertHeaderCfg,
    /// Defaults for every client the edge opens itself, where its section sets nothing: an egress
    /// proxy, the edge's client certificate, CAs to trust beside the public ones. See
    /// [`OutboundDefaultsCfg`].
    pub outbound: OutboundDefaultsCfg,
}

/// `[outbound]` — how the edge reaches what it calls itself, once for every section.
///
/// Each section with a URL of its own (`[control_plane]`, `[log.ship]`, `[tracing]`,
/// `[metrics.otlp]`, `[auth.jwt]`, `[alerts]`, `[llm.telemetry]`, `[tls.acme]` (the ACME
/// directory), `[tls.acme.dns]`) takes these
/// where it leaves its own [`OutboundCfg`] keys empty, so a corporate egress proxy or the edge's
/// identity is written once. A section's own value always wins. Proxied traffic to upstreams is
/// not covered: it has `[upstream_tls]`.
///
/// There is no `ca_path` here. In a section it replaces the public roots, which is right for an
/// endpoint behind a private CA and wrong for every public one: inherited by an alert webhook on a
/// chat service or a JWKS at a SaaS identity provider, it would break them. `extra_ca_path` adds
/// CAs to the public roots instead, so private endpoints and public ones both verify. Edge-local:
/// a control-plane policy cannot change it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OutboundDefaultsCfg {
    /// CA certificates (PEM) trusted in addition to the public web PKI, by every section that sets
    /// no `ca_path` of its own: a corporate CA, or the one a TLS-inspecting egress proxy signs
    /// with. Used for `https://` URLs only. Empty (default) adds none.
    pub extra_ca_path: String,
    /// The client certificate (PEM, leaf first) every section without one of its own presents to
    /// an `https://` endpoint that asks for one. Set with `client_key_path`. Watched and re-read on
    /// change, like a section's. Empty (default) presents none.
    pub client_cert_path: String,
    /// The private key (PEM) for `client_cert_path`.
    pub client_key_path: String,
    /// The proxy for every section whose `proxy` is empty: an `http://[user:password@]host:port`
    /// CONNECT proxy, or `"none"`. Empty (default) honours `HTTPS_PROXY`/`NO_PROXY` from the
    /// environment, as before. A section opts out with its own `proxy = "none"`.
    pub proxy: String,
    /// Not a setting: read only so that `[outbound] ca_path` is refused rather than ignored. See
    /// the type's documentation.
    #[doc(hidden)]
    pub ca_path: String,
}

/// One section's outbound client, as [`Config::outbound_clients`] lists it.
#[derive(Debug, Clone, Copy)]
pub struct OutboundClient<'a> {
    /// The section, as errors name it: `log.ship`, `auth.jwt`.
    pub section: &'static str,
    /// Whether this config opens the client: the section is on, or has its URL.
    pub enabled: bool,
    pub url: &'a str,
    pub outbound: &'a OutboundCfg,
}

impl OutboundDefaultsCfg {
    /// Whether anything is set.
    pub fn is_empty(&self) -> bool {
        self.extra_ca_path.is_empty()
            && self.client_cert_path.is_empty()
            && self.client_key_path.is_empty()
            && self.proxy.trim().is_empty()
            && self.ca_path.is_empty()
    }
}

/// `[trusted_client_cert_header]` — client certificates when a load balancer, not EdgeGuard,
/// terminates the client's mutual TLS.
///
/// Behind an L7 load balancer the client's TLS ends at the balancer, so `[tls.client_auth]` never
/// sees a client certificate. Balancers that do the mTLS themselves (an ALB in verify mode,
/// Cloudflare, Envoy or Istio, nginx) forward the certificate in a header instead. With `name` set,
/// EdgeGuard reads that header, but only on a connection from `trusted_proxies`: anyone else could
/// write any certificate into it. From a trusted peer it becomes the request's client certificate,
/// exactly as if the TLS listener had verified it — `auth.mode = "mtls"`, `[auth.mtls] allowed`,
/// `forward_client_cert`, the access log and the per-consumer series all use it. The header itself
/// is always removed before the request is forwarded. Edge-local: a control-plane policy cannot
/// change it, because whoever sets it decides who may claim which identity. Read at startup.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TrustedClientCertHeaderCfg {
    /// The header the load balancer puts the client certificate in, e.g. `X-Amzn-Mtls-Clientcert`.
    /// Empty (default) turns this off.
    pub name: String,
    /// How the header carries it: `"pem"` (default; PEM, URL-encoded or not, leaf first: ALB,
    /// nginx `$ssl_client_escaped_cert`), `"der"` (base64 DER, URL-encoded or not: Cloudflare,
    /// HAProxy `ssl_c_der,base64`, Traefik), or `"xfcc"` (Envoy's `X-Forwarded-Client-Cert`: the
    /// last element's `Cert`/`Chain`, or without them its `URI`, `DNS`, `Subject` and `Hash`).
    pub format: String,
    /// The addresses the header is trusted from: the load balancer's, as CIDRs or bare IPs. Matched
    /// against the connection's own peer address, never `X-Forwarded-For` or a PROXY protocol
    /// header (which name the client, not the hop that wrote this one). This or
    /// `trusted_proxy_names` is required with `name`; a `/0` (everyone) is refused.
    pub trusted_proxies: Vec<String>,
    /// The load balancer's names: the header is trusted only from a connection whose TLS client
    /// certificate, verified by `[tls.client_auth]`, has one of them. Exact names or prefixes
    /// ending in `*`, as `[auth.mtls] allowed` (`spiffe://prod.example/ns/ingress/*`). For a
    /// balancer on a shared edge network, whose addresses other tenants share. With
    /// `trusted_proxies` too, both must match. A bare `*` (any certificate) is refused.
    pub trusted_proxy_names: Vec<String>,
    /// Also verify the forwarded certificate against these CAs (PEM), for a balancer that forwards
    /// it without verifying (an ALB in passthrough mode). Empty (default) trusts the balancer's
    /// verification. Reloaded when it changes.
    pub ca_path: String,
    /// CRLs (PEM) for that verification, as `tls.client_auth.crl_paths`. Needs `ca_path`.
    pub crl_paths: Vec<String>,
}

impl Default for TrustedClientCertHeaderCfg {
    fn default() -> Self {
        TrustedClientCertHeaderCfg {
            name: String::new(),
            format: "pem".into(),
            trusted_proxies: Vec::new(),
            trusted_proxy_names: Vec::new(),
            ca_path: String::new(),
            crl_paths: Vec::new(),
        }
    }
}

/// `[metrics]` — where metrics go besides `/__edgeguard/metrics`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MetricsCfg {
    /// Push the same metrics to an OpenTelemetry collector. See [`OtlpMetricsCfg`].
    pub otlp: OtlpMetricsCfg,
    /// Most consumers (authenticated principals: an API-key id, a Basic user, a JWT `sub`, a
    /// client certificate's name) given their own `edgeguard_consumer_*` series. Past it, new ones
    /// share one `_over_cap` series, so a large or growing user base cannot grow the scrape without
    /// bound. `0` turns per-consumer series off — for a deployment where principals are personal
    /// data (an email in `sub`) that should not leave the edge as metric labels. Read at startup.
    pub consumer_series_max: usize,
}

impl Default for MetricsCfg {
    fn default() -> Self {
        MetricsCfg {
            otlp: OtlpMetricsCfg::default(),
            consumer_series_max: crate::metrics::DEFAULT_CONSUMER_SERIES,
        }
    }
}

/// `[metrics.otlp]` — push every metric `/__edgeguard/metrics` serves to an OTLP/HTTP collector, as
/// OTLP-JSON, on an interval. The Prometheus endpoint is unchanged; this is for setups that collect
/// with an OpenTelemetry pipeline and do not scrape. Counters are cumulative, so a missed push
/// loses resolution, never counts. Off by default.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OtlpMetricsCfg {
    /// Push metrics to `endpoint`. Off by default.
    pub enabled: bool,
    /// OTLP/HTTP metrics endpoint, e.g. `http://otel-collector:4318/v1/metrics`. Empty disables
    /// export regardless of `enabled`.
    pub endpoint: String,
    /// Seconds between pushes.
    pub interval_secs: u64,
    /// `service.name` on the exported resource.
    pub service_name: String,
    /// Per-push timeout in milliseconds.
    pub timeout_ms: u64,
    /// How the edge reaches `endpoint`. See [`OutboundCfg`].
    #[serde(flatten)]
    pub outbound: OutboundCfg,
}

impl Default for OtlpMetricsCfg {
    fn default() -> Self {
        OtlpMetricsCfg {
            enabled: false,
            endpoint: String::new(),
            interval_secs: 60,
            service_name: "edgeguard".into(),
            timeout_ms: 5_000,
            outbound: OutboundCfg::default(),
        }
    }
}

/// Outbound alerting (`[alerts]`). When `enabled` with a `webhook_url`, EdgeGuard POSTs a
/// Slack-compatible alert (`{ "text": … }`) when a hard-budget's consumed ratio (`used/limit`)
/// crosses `budget_consumed_threshold` — cost-regression alerting entirely in your own VPC (no SaaS
/// alerting plane to depend on). Fire-and-forget
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
    /// How the edge reaches `webhook_url`. See [`OutboundCfg`].
    #[serde(flatten)]
    pub outbound: OutboundCfg,
}

impl Default for AlertsCfg {
    fn default() -> Self {
        AlertsCfg {
            enabled: false,
            webhook_url: String::new(),
            budget_consumed_threshold: 0.9,
            timeout_ms: 2000,
            outbound: OutboundCfg::default(),
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
    /// Turn on the LLM gateway: token metering, cost attribution, budgets, the key vault
    /// and DLP. Off by default, and irrelevant unless the upstream is an LLM API.
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
    /// How the edge reaches `endpoint`. See [`OutboundCfg`].
    #[serde(flatten)]
    pub outbound: OutboundCfg,
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
            outbound: OutboundCfg::default(),
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
    /// client gets its own data back — the round-trip an unmask keyed on shared state gets wrong.
    /// Off by default.
    /// When on, the response is unmasked rather than re-scanned/redacted (restore, not detect).
    pub reversible: bool,
    /// Built-in detectors.
    pub detect_email: bool,
    /// Detect card numbers. Pair with `luhn_validate_credit_card` to require a valid
    /// checksum, which removes most false positives from ordinary long digit strings.
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
///
/// Or, in place of a virtual key, the **claims** of the verified JWT the request was authenticated
/// with (`auth.mode = "jwt"`): a workload's own identity — a CI job's OIDC token, say — chooses the
/// entry, so the workload holds no key of any kind, and the token it presents lasts minutes.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KeyEntryCfg {
    /// The secret the client presents (`Authorization: Bearer <virtual_key>`). Required, unless
    /// `claims` is set instead.
    pub virtual_key: String,
    /// The verified JWT claims this entry is chosen by, in place of a virtual key: each claim named
    /// must be one of the values listed (a value ending in `*` matches any rest), e.g.
    /// `claims = { iss = ["https://dagron.example.com"], trust = ["agent"], repository = ["acme/*"] }`.
    /// Entries are asked in order, and the first whose every claim matches is used.
    pub claims: std::collections::BTreeMap<String, Vec<String>>,
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
    /// Keying dimension: `"global"`, `"key"` (per authenticated principal), `"model"`, `"team"`,
    /// or `"claim:<name>"` (per value of a claim of the verified JWT, e.g. `claim:run_id`).
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
    /// USD per 1,000,000 prompt (input) tokens for this model, as billed by the provider.
    pub input_per_1m: f64,
    /// USD per 1,000,000 completion (output) tokens for this model.
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
    /// Enrol this instance with a managed control plane for pushed policy and quota.
    /// Off by default; EdgeGuard is fully functional without one.
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
    /// This edge's identity in the control plane's fleet view. Empty (the default) auto-detects
    /// from the hostname.
    ///
    /// Set it explicitly where the hostname is not stable and not meaningful — a rolling Deployment
    /// replaces the pod name on every deploy, so each rollout would otherwise appear as a fresh set
    /// of edges with the previous set ageing out. A value that survives the roll (the workload's
    /// name plus an ordinal) makes the fleet view track the edge rather than the process.
    pub edge_id: String,
    /// File to keep the last policy pulled from the control plane in, so a restart while the
    /// control plane is unreachable starts on that policy instead of the local config file alone
    /// (which may be looser: no auth, WAF in report mode). Written `0600` after each policy is
    /// applied, read once at startup. It holds whatever the policy holds — API keys, provider keys
    /// — so put it where the edge's own secrets live. Empty (default) keeps nothing.
    pub cache_path: String,
    /// What to serve while no control-plane policy has been applied, at startup, before the first
    /// pull answers and with nothing in `cache_path`: `"local"` (default) runs on the local config
    /// file; `"refuse"` answers proxied requests with `503` (and `/__edgeguard/ready` with `503`)
    /// until a policy arrives. Health and metrics stay up either way.
    pub boot_without_policy: String,
    /// How the edge reaches the control plane: a private CA, the client certificate it presents
    /// (in addition to `edge_token`), a proxy. See [`OutboundCfg`].
    #[serde(flatten)]
    pub outbound: OutboundCfg,
}

/// How the edge reaches an HTTP endpoint it calls itself: the control plane, a log or OTLP
/// collector, a JWKS endpoint, an alert webhook, the ACME directory, a DNS provider's API. The
/// same four keys, with the same meaning, sit directly in each section that has such a URL
/// (`[control_plane]`, `[log.ship]`, `[tracing]`, `[metrics.otlp]`, `[auth.jwt]`, `[alerts]`,
/// `[llm.telemetry]`, `[tls.acme]`, `[tls.acme.dns]`). A key left empty takes the `[outbound]` default ([`OutboundDefaultsCfg`]).
/// Proxied traffic to upstreams has its own, `[upstream_tls]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OutboundCfg {
    /// CA certificates (PEM) that sign the endpoint's server certificate, for one behind a private
    /// CA. Set, it replaces the public web PKI for this client: only these CAs are trusted. Empty
    /// (default) trusts the public roots built into the binary. Needs an `https://` URL.
    pub ca_path: String,
    /// Client certificate (PEM, leaf first) presented to an endpoint that asks for one. Set with
    /// `client_key_path`. Watched and re-read on change, so a rotated certificate is presented on
    /// the next handshake with no restart. Empty (default) presents none. Needs an `https://` URL.
    pub client_cert_path: String,
    /// The private key (PEM) for `client_cert_path`.
    pub client_key_path: String,
    /// How to reach the endpoint: empty (default) takes `[outbound] proxy`, and with that empty
    /// too honours `HTTPS_PROXY`/`NO_PROXY` from the environment; an
    /// `http://[user:password@]host:port` URL sends this client — and only this one — through that
    /// proxy, as a `CONNECT` tunnel, so TLS stays end to end; `"none"` connects directly, whatever
    /// `[outbound]` or the environment says.
    pub proxy: String,
    /// `[outbound]`, as [`Config::load`] copies it into every section, for the keys above that are
    /// left empty. Not read from the section.
    #[serde(skip)]
    pub defaults: OutboundDefaultsCfg,
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
            edge_id: String::new(),
            cache_path: String::new(),
            boot_without_policy: "local".into(),
            outbound: OutboundCfg::default(),
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
    /// Close a connection that has not sent a complete request head within this long: a new
    /// connection that sends nothing, one that sends its headers a byte at a time, and a
    /// keep-alive connection idle between requests. It runs before auth and rate limiting, so
    /// without it a few clients can hold sockets open indefinitely. A request already being
    /// answered is not affected, however long its response takes. `"0"` disables. Applies to every
    /// listener; read at startup, not on reload.
    pub header_read_timeout: String,
    /// Most connections the public listener holds open at once. One more is closed as soon as it
    /// is accepted and counted in `edgeguard_connections_rejected_total`. `0` (default) is
    /// unlimited. The redirect listener gets its own cap of the same size; the admin listener has
    /// none, so health checks and scrapes still get through when the public port is full.
    pub max_connections: usize,
    /// After SIGTERM or Ctrl-C, keep accepting new connections for this long — with
    /// `/__edgeguard/ready` already answering `503` — before draining. A load balancer, or
    /// Kubernetes removing the pod from its endpoints, only stops routing here some time after the
    /// signal; connections that arrive in between are refused if the listener has already closed.
    /// `"0"` (default) stops accepting at once.
    pub drain_delay: String,
    /// Once the listener stops accepting, how long to wait for in-flight requests to finish before
    /// closing what is left. Idle keep-alive connections close at once. Keep `drain_delay` plus
    /// this under the platform's kill deadline (Kubernetes' `terminationGracePeriodSeconds`, 30 s
    /// by default). `"0"` closes everything at once.
    pub drain_timeout: String,
    /// Read a PROXY protocol header (v1 or v2) at the start of each connection on the public and
    /// redirect listeners, and use the client address it carries. For an L4 load balancer (AWS NLB,
    /// a GCP TCP proxy, HAProxy, F5), which passes TCP through and so adds no `X-Forwarded-For`:
    /// without it, rate limits, IP access rules and the access log see the balancer's address.
    /// The header is believed only from `proxy_protocol_trusted`; from any other peer a connection
    /// that starts with one is closed, and one that does not is served as it is. Off by default.
    pub proxy_protocol: bool,
    /// The addresses a PROXY header is believed from: the load balancer's, as CIDRs or bare IPs.
    /// Required with `proxy_protocol`; a `/0` is refused, since it would let any client choose its
    /// own address.
    pub proxy_protocol_trusted: Vec<String>,
}

/// `[tracing]` — one OpenTelemetry **SERVER** span per proxied request.
///
/// Distinct from `[llm.telemetry]`, which emits a CLIENT span only for metered LLM requests. That
/// covers the gateway deployment and leaves a plain reverse-proxy install — most of them — emitting
/// no traces at all. This is the general one.
///
/// Off by default. When on, spans are batched to any OTLP/HTTP `/v1/traces` receiver over the
/// crate's existing HTTP client: no OpenTelemetry SDK, no protobuf, still one static binary.
///
/// The request path never waits on it. A span is handed to a bounded queue and a background task
/// does the rest, so a slow or absent collector costs dropped spans rather than latency.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TracingCfg {
    /// Emit a span per request to `endpoint`. Off by default.
    pub enabled: bool,
    /// OTLP/HTTP traces endpoint, e.g. `http://otel-collector:4318/v1/traces`. Empty disables
    /// tracing regardless of `enabled` — an endpoint-less "enabled" would mint trace ids on every
    /// request and throw them away.
    pub endpoint: String,
    /// Fraction of traces to record, `0.0`–`1.0`. Deterministic per trace id, so a trace is wholly
    /// sampled or wholly not — a half-recorded trace is worse than none, because the gap looks like
    /// a missing service.
    pub sample_rate: f64,
    /// `service.name` on emitted spans.
    pub service_name: String,
    /// Spans per POST.
    pub batch: usize,
    /// Flush a partial batch after this many seconds.
    pub interval_secs: u64,
    /// In-memory queue between the request path and the shipper. Past it, spans are dropped rather
    /// than the request path blocking.
    pub queue_size: usize,
    /// Per-POST timeout in milliseconds.
    pub timeout_ms: u64,
    /// How the edge reaches `endpoint`. See [`OutboundCfg`].
    #[serde(flatten)]
    pub outbound: OutboundCfg,
}

impl Default for TracingCfg {
    fn default() -> Self {
        TracingCfg {
            enabled: false,
            endpoint: String::new(),
            sample_rate: 1.0,
            service_name: "edgeguard".into(),
            batch: 200,
            interval_secs: 5,
            queue_size: 10_000,
            timeout_ms: 2_000,
            outbound: OutboundCfg::default(),
        }
    }
}

/// `[log]` — what the access log records.
///
/// Access logs are the most-copied artifact a service produces: scraped, shipped to a SIEM, retained
/// for months, readable by people who were never meant to hold what is in them. The request line is
/// where credentials end up (`?api_key=`, OAuth `?code=`, magic links, presigned URLs), so how it is
/// rendered is a security setting, not a formatting one.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogCfg {
    /// `"redact"` (default), `"drop"`, or `"full"` — see [`QueryLogMode`](crate::accesslog::QueryLogMode).
    pub query: crate::accesslog::QueryLogMode,
    /// Extra query-parameter names to treat as sensitive, on top of the built-in list. Matched
    /// case-insensitively as substrings, so `"accountNumber"` also covers `account_number_v2`.
    pub redact_params: Vec<String>,
    /// Ship the access log to a collector. Off by default. See [`LogShipCfg`].
    pub ship: LogShipCfg,
    /// How the authenticated principal and the client certificate's name are recorded: `"full"`
    /// (default), `"hash"` or `"off"` — see
    /// [`PrincipalLogMode`](crate::accesslog::PrincipalLogMode). The per-consumer metrics are set
    /// separately, by `metrics.consumer_series_max`.
    pub principal: crate::accesslog::PrincipalLogMode,
}

/// `[log.ship]` — stream the access log off the box to a collector.
///
/// The edge writes one structured line per request to stdout and, until this existed, nowhere else:
/// an operator running a fleet had to collect logs per box with whatever their platform provided.
///
/// Any collector that accepts an NDJSON POST works — Vector, Loki, Splunk HEC, Datadog, an S3
/// writer, your own receiver. One wire shape rather than an integration per vendor, matching the
/// control plane's `[audit.ship]`.
///
/// **This is best-effort, and that is deliberate.** `[audit.ship]` is at-least-once with a cursor
/// because the audit trail is evidence. Access logs are telemetry at three to five orders of
/// magnitude more volume, and guaranteeing delivery would need an unbounded on-box buffer — whose
/// failure mode is that a collector outage takes down the proxy. Records are dropped when the queue
/// fills, and every drop is counted (`edgeguard_logship_dropped_total`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogShipCfg {
    /// Ship access-log records to `url`. Off by default.
    pub enabled: bool,
    /// Collector URL. Empty disables shipping regardless of `enabled`.
    pub url: String,
    /// Extra headers, typically the collector's API key: `Authorization: Splunk <token>`,
    /// `DD-API-KEY: <key>`. A list of pairs rather than a map so the order is stable in config.
    pub headers: Vec<(String, String)>,
    /// Records per POST.
    pub batch: usize,
    /// Flush a partial batch after this many seconds, so a low-traffic edge does not hold its last
    /// records indefinitely — a gap in the collector looks exactly like an outage.
    pub interval_secs: u64,
    /// In-memory queue between the request path and the shipper. This is the bound: past it,
    /// records are dropped rather than the request path blocking.
    ///
    /// 10k at the measured request rates is a few seconds of buffer, which covers a collector
    /// restart and not a collector outage. Raising it trades memory for a longer outage tolerated;
    /// it does not make delivery guaranteed, and nothing here should be read as if it did.
    pub queue_size: usize,
    /// How the edge reaches `url`. See [`OutboundCfg`].
    #[serde(flatten)]
    pub outbound: OutboundCfg,
}

impl Default for LogShipCfg {
    fn default() -> Self {
        LogShipCfg {
            enabled: false,
            url: String::new(),
            headers: Vec::new(),
            batch: 500,
            interval_secs: 5,
            queue_size: 10_000,
            outbound: OutboundCfg::default(),
        }
    }
}

impl Default for LogCfg {
    fn default() -> Self {
        LogCfg {
            query: crate::accesslog::QueryLogMode::Redact,
            redact_params: Vec::new(),
            ship: LogShipCfg::default(),
            principal: crate::accesslog::PrincipalLogMode::Full,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthCfg {
    /// "none" | "basic" | "apikey" | "jwt" | "mtls". Selects the gate applied to every proxied
    /// request; the internal `/__edgeguard/*` endpoints are always exempt. `mtls` authenticates
    /// by the client certificate verified on the TLS listener (`[tls.client_auth]`, which it
    /// requires) and takes the principal from it.
    pub mode: String,
    /// Realm shown in the `WWW-Authenticate` challenge on a 401, i.e. the name the browser's
    /// password prompt displays. Only used when `mode = "basic"`.
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
    /// Client-certificate policy. Used when `mode = "mtls"`.
    pub mtls: MtlsAuthCfg,
}

/// `[auth.mtls]` — which client certificates `auth.mode = "mtls"` lets through.
///
/// The TLS listener has already verified the certificate against `[tls.client_auth] ca_path` by
/// the time this runs; this narrows *which* of the certificates that CA vouches for may call the
/// app. A certificate's names are its URI alternative names (a SPIFFE ID is one), DNS names, email
/// names and subject common name; the principal is the first of them, in that order, that is
/// allowed.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct MtlsAuthCfg {
    /// Allowed names: an exact name, or a prefix ending in `*` (`spiffe://prod.example/ns/web/*`).
    /// DNS and email names are compared in lower case. Empty (default) allows any certificate the
    /// CA issued.
    pub allowed: Vec<String>,
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
    /// How the edge reaches `jwks_url`. See [`OutboundCfg`]. Edge-local: kept from this file
    /// when a control-plane policy replaces the rest of `[auth]`.
    #[serde(flatten)]
    pub outbound: OutboundCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitCfg {
    /// Master switch for rate limiting. On by default: an unlimited front door is not a
    /// front door. Turn it off only when something ahead of EdgeGuard already limits.
    pub enabled: bool,
    /// Default per-client-IP limit, e.g. "60/min", "10/sec", "1000/hour".
    pub rate: String,
    /// How many requests may arrive at once before `rate` applies. The bucket refills at
    /// `rate`, so this is the size of a legitimate spike you are willing to absorb.
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
    /// The route's rate, `N/sec`, `N/min` or `N/hour`, still keyed per client IP. Replaces the
    /// global `rate` for requests under `path`.
    pub rate: String,
    /// The route's burst: bucket depth on top of the steady rate.
    pub burst: u32,
    /// The `route` label this prefix's requests carry in the per-route metrics. Empty (default)
    /// uses `path`.
    pub name: String,
}

impl Default for RouteRateLimit {
    fn default() -> Self {
        RouteRateLimit {
            path: String::new(),
            rate: "60/min".into(),
            burst: 20,
            name: String::new(),
        }
    }
}

/// Per-principal rate limit (keyed by API-key id / JWT subject).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PerKeyRateLimit {
    /// Apply a second, per-principal limit on top of the global one. Off by default,
    /// because it only means something once requests are authenticated.
    pub enabled: bool,
    /// Sustained rate per authenticated principal, same syntax as `ratelimit.rate`
    /// (e.g. `"1000/hour"`). Applies per key, not per IP.
    pub rate: String,
    /// Burst allowance per principal. See `ratelimit.burst`.
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
    /// Max time to open the TCP connection to an upstream, e.g. "5s". "0" leaves it to
    /// `upstream_timeout`. An upstream whose packets are dropped (a partitioned network, a
    /// firewall) never refuses the connection, so without this the request waits out the whole
    /// `upstream_timeout`, and a pool cannot move on to its next target in time. Read at startup.
    pub upstream_connect_timeout: String,
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
    /// Stream (don't buffer) responses of **any** content type when nothing on the request needs
    /// the whole body: no LLM metering (`[llm]` route), no reversible DLP masking, and no outbound
    /// DLP scan (`dlp.scan_response`). Those still buffer, whatever this says. Off by default for
    /// now. When a response streams:
    /// * `max_response_body` is enforced as the bytes flow — over the cap the connection is cut
    ///   (the status and headers were already sent, so there is no clean 502 to give);
    /// * the body-read part of `upstream_timeout` does not apply (time-to-headers still does);
    /// * an upstream error mid-body truncates the response instead of becoming a 502;
    /// * egress bytes are counted per frame, as for SSE.
    ///
    /// `text/event-stream` keeps its own switch, `stream_passthrough`.
    pub stream_responses: bool,
    /// Stream (don't buffer) **request** bodies to the upstream when nothing needs the whole body:
    /// no WAF rule inspects the body, inbound DLP is off (`dlp.scan_request`), and no LLM feature
    /// reads it (`[llm]`, the virtual-key vault and budgets parse the model from the body). Those
    /// still buffer, whatever this says. Off by default for now. When a request streams:
    /// * `max_body` still holds. A `Content-Length` over it gets `413` before anything is sent
    ///   upstream; a body without one that grows past it is cut, and the client gets `413` too —
    ///   but the upstream has already seen the start of it, so it must tolerate an aborted upload;
    /// * ingress bytes are counted as the body flows.
    pub stream_requests: bool,
    /// Routes (by path prefix) whose request body may stream **and still be inspected**, on a
    /// bounded window rather than the whole body. Only takes effect with `stream_requests` on.
    /// Without an entry, a WAF body rule or inbound DLP forces the request to buffer; with one, the
    /// first `window` bytes are inspected before anything is sent upstream and the rest is
    /// scanned frame by frame with `overlap` bytes carried between frames. Weaker than whole-body
    /// inspection — see [`StreamInspectCfg`]. Inbound DLP in `redact` mode and LLM routes still
    /// buffer, whatever this says.
    pub stream_inspect: Vec<StreamInspectCfg>,
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
    /// Send `Strict-Transport-Security`, telling browsers to refuse plain HTTP for this
    /// host in future. Only meaningful once the site is genuinely HTTPS-only: a browser
    /// that has seen it cannot be talked out of it for the max-age.
    pub hsts: bool,
    /// `Content-Security-Policy` value. The default is deliberately strict and will block
    /// inline scripts and third-party assets; widen it once you know what the app loads,
    /// and use `csp_report_only` while you find out.
    pub csp: String,
    /// Send the CSP as `Content-Security-Policy-Report-Only` instead of enforcing it. Lets
    /// you roll out / tighten a policy by collecting violations first without breaking the
    /// page.
    pub csp_report_only: bool,
    /// If set, a `report-uri <value>` directive is appended to the CSP so browsers POST
    /// violation reports there. Point it at EdgeGuard's own sink ("/__edgeguard/csp-report")
    /// to have them logged, or at any external collector.
    pub csp_report_uri: String,
    /// `Referrer-Policy` value. The default sends no referrer at all, so internal URLs
    /// cannot leak to third parties through ordinary navigation.
    pub referrer_policy: String,
    /// `Permissions-Policy` value. The default denies geolocation, microphone and camera,
    /// which an app that needs them must explicitly re-enable.
    pub permissions_policy: String,
    /// `X-Frame-Options` value: `DENY`, `SAMEORIGIN`, or empty to omit the header.
    /// Clickjacking protection for browsers predating CSP `frame-ancestors`.
    pub frame_options: String,
    /// Add `Secure` to every `Set-Cookie` the upstream returns, so cookies are never sent
    /// over plain HTTP. See `httponly_cookies` for the separate `HttpOnly` control.
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
            header_read_timeout: "30s".into(),
            max_connections: 0,
            drain_delay: "0s".into(),
            drain_timeout: "25s".into(),
            proxy_protocol: false,
            proxy_protocol_trusted: Vec::new(),
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
            mtls: MtlsAuthCfg::default(),
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
            outbound: OutboundCfg::default(),
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

/// One `[[validation.stream_inspect]]` route: a streamed request body inspected on a bounded
/// window (0.6.0, A3). What it does NOT catch, compared with buffering the whole body:
///
/// * a match that starts in one frame and ends in a later one is only caught when it fits in
///   `overlap` bytes (the carry between frames);
/// * a block decided after the first `window` bytes comes too late to keep the upload from the
///   upstream: the upstream has seen the start of it, the upload is cut, and the client gets `403`;
/// * DLP in `redact` mode cannot rewrite a body that is already on its way, so it keeps buffering.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StreamInspectCfg {
    /// Path prefix this applies to, e.g. "/upload/". The longest matching prefix wins.
    pub path: String,
    /// Bytes inspected as one piece before anything is forwarded, e.g. "64KiB". A body that ends
    /// within it is inspected whole, as if buffered.
    pub window: String,
    /// Bytes of each frame's tail carried into the next frame's scan, e.g. "4KiB". The longest
    /// pattern match that can span two frames. Must be smaller than `window`.
    pub overlap: String,
}

impl Default for StreamInspectCfg {
    fn default() -> Self {
        StreamInspectCfg {
            path: String::new(),
            window: "64KiB".into(),
            overlap: "4KiB".into(),
        }
    }
}

impl Default for ValidationCfg {
    fn default() -> Self {
        ValidationCfg {
            max_body: "2MiB".into(),
            max_response_body: "0".into(),
            upstream_timeout: "30s".into(),
            upstream_connect_timeout: "5s".into(),
            max_header_bytes: "0".into(),
            allow_methods: vec![],
            stream_passthrough: false,
            stream_responses: false,
            stream_requests: false,
            stream_inspect: Vec::new(),
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
/// `self_signed_days` and `redirect_status` need non-zero defaults (a zero-day certificate and
/// a `0` status are both nonsense), so `Default` is written out rather than derived.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsCfg {
    /// Terminate TLS in EdgeGuard itself. Leave off when something upstream already does
    /// (a load balancer, a platform edge) and EdgeGuard only sees plaintext behind it.
    pub enabled: bool,
    /// PEM certificate chain (leaf first). When ACME is enabled this is where the obtained
    /// certificate is written/read.
    pub cert_path: String,
    /// PEM private key (PKCS#8/PKCS#1/SEC1).
    pub key_path: String,
    /// Generate a self-signed certificate at `cert_path`/`key_path` when none is there yet,
    /// instead of requiring one to exist before TLS can be enabled at all. It encrypts the
    /// connection — which is what makes HSTS, `Secure` cookies and the hardening headers mean
    /// anything — but proves no identity, so browsers warn and strict clients refuse. Right for
    /// localhost, a private network, or a staging box; for the public internet use `[tls.acme]`.
    /// Ignored once a certificate exists, so a restart keeps serving the same one.
    pub self_signed: bool,
    /// Hostnames/IPs to put in the generated certificate's subject-alternative names. Empty
    /// means `localhost`, `127.0.0.1` and `::1` — a client is only satisfied by a name it finds
    /// in here, so add the address you actually browse to.
    pub self_signed_hosts: Vec<String>,
    /// How long the generated certificate is valid, in days. The default is deliberately short:
    /// a self-signed certificate is meant to be a stopgap, and an expiry that arrives is a
    /// better reminder to move to `[tls.acme]` than a decade-long one nobody revisits.
    pub self_signed_days: u32,
    /// Regenerate the self-signed certificate before it expires — once two-thirds of its lifetime
    /// has passed — instead of letting it lapse. On by default: a proxy that quietly starts
    /// serving an expired certificate on day 91 is an outage nobody chose. Only a certificate
    /// that is itself self-signed is ever replaced, so a CA-issued certificate the operator put
    /// at `cert_path` is left alone.
    pub self_signed_renew: bool,
    /// Generate a new key pair at each self-signed renewal. Off by default, so a client that was
    /// told to trust this certificate by its public key keeps trusting the renewed one.
    pub self_signed_rotate_key: bool,
    /// Reload the certificate when `cert_path`/`key_path` change on disk — written by
    /// cert-manager, Vault Agent, certbot or a mounted Kubernetes secret — with no restart and no
    /// dropped connections. A pair that does not load is rejected and the current one keeps
    /// serving. On by default.
    pub watch: bool,
    /// Plain-HTTP port to run an HTTP→HTTPS redirect listener on; `0` (default) disables it.
    /// Terminating TLS only protects traffic that reaches the TLS port, and a browser given a
    /// bare hostname tries `:80` first — so without this, the first request of every visit is
    /// still plaintext. Set to `80` alongside a `[server] port = 443`. Overridden by
    /// `REDIRECT_PORT`.
    pub redirect_port: u16,
    /// Status the redirect listener answers with. `308` (default) preserves the method and body,
    /// so a `POST` arriving on the plaintext port is replayed over TLS rather than silently
    /// downgraded to a `GET`; `301` is the older browser-facing convention. Must be 3xx.
    pub redirect_status: u16,
    /// Hostnames the redirect listener will reflect into `Location`. Empty (default) accepts any
    /// syntactically valid host. `Host` is attacker-controlled, so pinning it to the names you
    /// actually serve is what stops a request with a forged `Host` from turning this listener
    /// into an open redirect that carries your domain's reputation to someone else's site.
    pub redirect_hosts: Vec<String>,
    /// Automatic certificate issuance. See `[tls.acme]`.
    pub acme: AcmeCfg,
    /// More certificates on the same listener, chosen by the hostname the client asks for (SNI):
    /// one `[[tls.certs]]` entry per pair. The pair above (`cert_path`/`key_path`, or what
    /// self-signed or ACME put there) stays the default, served to any name no entry claims and to
    /// clients that send no name. These pairs are provided by you or another tool (cert-manager,
    /// certbot, Vault Agent): they are reloaded when they change on disk, like the default pair, and
    /// warned about as they near expiry, but nothing here renews them.
    pub certs: Vec<SniCertCfg>,
    /// Verify client certificates on this listener (mutual TLS). See `[tls.client_auth]`.
    pub client_auth: ClientAuthCfg,
}

/// `[tls.client_auth]` — client certificates on the TLS listener (mutual TLS).
///
/// With `mode = "required"` a client must present a certificate signed by a CA in `ca_path` to
/// complete the handshake; with `"optional"` one is verified if presented. A verified
/// certificate's names identify the client: `auth.mode = "mtls"` authenticates by them, and
/// `forward_client_cert` passes them to the app. The CA bundle and CRLs are reloaded when they
/// change on disk; existing connections keep the verification they were opened with.
///
/// TLS session resumption is off while this is on: a resumed session skips certificate
/// verification, so a certificate revoked after the first connection would keep working.
///
/// Edge-local like the rest of `[tls]`. Needs `[tls] enabled`: a certificate only reaches the
/// process that terminates TLS.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ClientAuthCfg {
    /// `"off"` (default), `"optional"` or `"required"`.
    pub mode: String,
    /// PEM bundle of the CAs allowed to sign a client certificate. Required unless `mode = "off"`.
    pub ca_path: String,
    /// PEM certificate revocation lists. A certificate one of them revokes is refused at the
    /// handshake. Checked for the client's own certificate, which must then be covered by one of
    /// them: a certificate whose issuer has no CRL here is refused rather than assumed good.
    pub crl_paths: Vec<String>,
    /// Pass the verified certificate to the app: `"off"` (default) or `"xfcc"`, an
    /// `X-Forwarded-Client-Cert` header (`Hash=<sha256>;URI="…";DNS="…"`). Whatever this is set to,
    /// an `X-Forwarded-Client-Cert` header from the client is removed while client
    /// authentication is on, so the app never sees one the client wrote.
    pub forward_client_cert: String,
}

impl Default for ClientAuthCfg {
    fn default() -> Self {
        ClientAuthCfg {
            mode: "off".into(),
            ca_path: String::new(),
            crl_paths: Vec::new(),
            forward_client_cert: "off".into(),
        }
    }
}

/// One extra certificate, served to the hostnames in `hosts`. See [`TlsCfg::certs`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SniCertCfg {
    /// PEM certificate chain (leaf first).
    pub cert_path: String,
    /// PEM private key.
    pub key_path: String,
    /// The names this certificate is served for: exact hostnames (`api.example.com`) or a
    /// one-label wildcard (`*.example.com`, which matches `a.example.com` but not
    /// `example.com` or `a.b.example.com`). An exact name always wins over a wildcard. Required:
    /// the names are not read from the certificate, so what is served for which host is stated
    /// here, in the config, where it is reviewed.
    pub hosts: Vec<String>,
}

impl TlsCfg {
    /// SAN list for a generated certificate: the configured hosts, or the loopback defaults.
    pub fn self_signed_host_list(&self) -> Vec<String> {
        if self.self_signed_hosts.is_empty() {
            crate::selfsigned::DEFAULT_HOSTS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            self.self_signed_hosts.clone()
        }
    }
}

impl Default for TlsCfg {
    fn default() -> Self {
        TlsCfg {
            enabled: false,
            cert_path: String::new(),
            key_path: String::new(),
            self_signed: false,
            self_signed_hosts: Vec::new(),
            // 90 days, matching what a public CA issues — long enough not to be a nuisance in
            // staging, short enough that "temporary" self-signed TLS cannot quietly become
            // permanent.
            self_signed_days: 90,
            self_signed_renew: true,
            self_signed_rotate_key: false,
            watch: true,
            redirect_port: 0,
            // 308 over 301: it preserves method and body, so an API client's POST is not turned
            // into a GET by the upgrade.
            redirect_status: 308,
            redirect_hosts: Vec::new(),
            acme: AcmeCfg::default(),
            certs: Vec::new(),
            client_auth: ClientAuthCfg::default(),
        }
    }
}

/// Automatic certificate management (ACME / Let's Encrypt) via the HTTP-01 challenge. The
/// obtained certificate is written to `TlsCfg::cert_path`/`key_path` and served by the TLS
/// listener. Issuance runs at startup when no certificate exists at `cert_path`, and the running
/// proxy renews it once two-thirds of its lifetime has passed (`renew`, on by default), serving
/// the new certificate to new connections without a restart.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AcmeCfg {
    /// Obtain and renew a certificate automatically over ACME HTTP-01 instead of reading
    /// `cert_path`/`key_path` from disk. Requires port 80 to be reachable from the CA.
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
    /// Refuse to send an order the CA's published rate limits would reject, instead of finding out
    /// by being refused. On by default. See [`crate::acme_budget`].
    ///
    /// Only recognised CAs are budgeted — an unknown directory URL gets no profile and no guard,
    /// because holding a private CA to Let's Encrypt's numbers would refuse orders it would have
    /// accepted. Turn this off only if the budget is wrong about your CA and you would rather have
    /// the CA be the one that says no.
    ///
    /// This governs **this edge's own ledger only**. In managed mode the control plane still issues
    /// the fleet-wide issuance lease, because limits the CA applies across every edge under one
    /// registered domain are not this edge's to opt out of — one box turning this off would
    /// otherwise be able to spend the whole fleet's weekly allowance.
    pub budget_enabled: bool,
    /// Renew the certificate while the proxy runs, once two-thirds of its lifetime has passed
    /// (day 60 of a 90-day certificate). Each renewal goes through the same issuance budget and,
    /// in managed mode, the same control-plane lease as the first order. When the redirect
    /// listener holds port 80 it answers the HTTP-01 challenge, so renewal needs no second
    /// listener. On by default.
    pub renew: bool,
    /// Ask the CA when to renew (ACME Renewal Information, RFC 9773), on top of the two-thirds
    /// rule. When the CA offers it, its suggested window can bring a renewal **earlier** (a CA
    /// that must revoke certificates after an incident says so this way) but never later: the
    /// two-thirds point still applies. Renewal orders also tell the CA which certificate they
    /// replace, which some CAs exempt from rate limits. A CA without ARI, or one that fails to
    /// answer, leaves the two-thirds rule alone. One unauthenticated GET per certificate, as
    /// often as the CA's `Retry-After` allows. On by default.
    pub ari: bool,
    /// How the CA checks this edge controls the names: `"http-01"` (default) serves a token on
    /// port 80; `"dns-01"` publishes a TXT record through `[tls.acme.dns]` instead. DNS-01 is the
    /// only way to get a **wildcard** (`*.example.com`) and works for hosts the CA cannot reach on
    /// :80; it needs API access to the zone.
    pub challenge: String,
    /// The DNS provider for `challenge = "dns-01"`. See `[tls.acme.dns]`.
    pub dns: AcmeDnsCfg,
    /// How the edge reaches the ACME directory (`directory_url`): its CA, a client certificate, a
    /// proxy. See [`OutboundCfg`]. One difference from the other sections: with no `ca_path` (or
    /// `[outbound] extra_ca_path`), the directory is verified against the operating system's
    /// trust store, as it always was, not the roots built into the binary, so a private ACME CA
    /// whose root is installed on the host keeps working.
    #[serde(flatten)]
    pub outbound: OutboundCfg,
}

/// Where DNS-01 publishes its `_acme-challenge` TXT records.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AcmeDnsCfg {
    /// `"cloudflare"`, or `"challtestsrv"` (Pebble's test DNS server, for testing only).
    pub provider: String,
    /// Cloudflare: the zone the records go in (Zone ID, from the zone's Overview page).
    pub zone_id: String,
    /// Name of the environment variable holding the provider's API token (Cloudflare: a token with
    /// `Zone.DNS:Edit` on that zone only). The token itself is never read from this file, never
    /// logged, and `doctor` errors if the variable is unset. Default `CLOUDFLARE_API_TOKEN`.
    pub api_token_env: String,
    /// Cloudflare API base URL. Only for testing against a stub.
    pub api_base: String,
    /// `challtestsrv`: its management URL, e.g. `http://localhost:8055`.
    pub url: String,
    /// Seconds to wait after publishing a record before asking the CA to check it, so it has reached
    /// the authoritative servers. Default 30; raise it if validation fails with "no TXT record".
    pub propagation_secs: u64,
    /// How the edge reaches the provider's API. See [`OutboundCfg`].
    #[serde(flatten)]
    pub outbound: OutboundCfg,
}

impl Default for AcmeDnsCfg {
    fn default() -> Self {
        Self {
            provider: String::new(),
            zone_id: String::new(),
            api_token_env: "CLOUDFLARE_API_TOKEN".into(),
            api_base: "https://api.cloudflare.com/client/v4".into(),
            url: String::new(),
            propagation_secs: 30,
            outbound: OutboundCfg::default(),
        }
    }
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
            budget_enabled: true,
            renew: true,
            ari: true,
            challenge: "http-01".into(),
            dns: AcmeDnsCfg::default(),
            outbound: OutboundCfg::default(),
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
/// prefix wins (`path = "/"` replaces the default). The path is forwarded unchanged.
///
/// With `targets` instead of `target`, the prefix has a pool: several upstreams, for failover (an
/// on-prem primary and a cloud standby, say) or to spread load (`balance = "round_robin"`). A
/// target leaves rotation when its `health_check` fails, or when requests fail to connect to it
/// (`eject_after`), and a request that could not connect is sent to the next one. `backup` targets
/// take requests only when none of `targets` will. There is no service discovery.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UpstreamRoute {
    /// Path prefix this upstream applies to, e.g. `/api/`.
    pub path: String,
    /// Upstream base URL for this prefix, e.g. `http://api.internal:4000`.
    pub target: String,
    /// A pool instead of `target`: upstream base URLs, e.g.
    /// `["http://10.0.1.5:8080", "https://standby.example.com"]`, or with round-robin weights,
    /// `[{ url = "http://10.0.1.5:8080", weight = 3 }, "http://10.0.1.6:8080"]`. Each `https://`
    /// one takes its own `[[upstream_tls.targets]]` entry, as a `target` would.
    pub targets: Vec<TargetCfg>,
    /// How a pool picks among its targets in rotation: `"priority"` (default) sends every request
    /// to the first in the order listed, the rest standing by; `"round_robin"` takes them in turn,
    /// as many turns each as its `weight`; `"least_conn"` the one with the fewest requests in
    /// flight for its weight; `"hash"` the one `hash_on` points to. Whichever, a request that
    /// cannot connect moves on to the next.
    pub balance: String,
    /// With `balance = "hash"`, the key that picks a request's target: `"client_ip"` (default),
    /// `"path"`, `"header:<name>"`, `"cookie:<name>"` or `"query:<name>"` (a query parameter's
    /// value as sent, not percent-decoded). The same key goes to the same target, on every edge,
    /// while that target is in rotation; when it leaves, only its keys move. A request without the
    /// key is balanced in turn.
    pub hash_on: String,
    /// Keep each client on the target that first answered it: the edge sets a cookie of this name
    /// naming that target, and a request carrying it goes there while the target is in rotation.
    /// Empty (default) is off.
    pub sticky_cookie: String,
    /// How long the sticky cookie lasts, e.g. `"8h"`: its `Max-Age`, counted from when it was set
    /// (it is not refreshed while the client stays). After it, the client's next request is
    /// balanced and stuck again to whichever target answers. Empty (default): a session cookie,
    /// gone when the browser closes.
    pub sticky_cookie_max_age: String,
    /// Remove the sticky cookie from requests before they reach the upstream, which then never
    /// sees the edge's cookie (HAProxy's `indirect`). The client's other cookies are kept.
    /// Default `false`.
    pub sticky_cookie_strip: bool,
    /// A pool's standby targets: they take requests only when no target in `targets` is in
    /// rotation, or when every one of them refused the request. Balanced among themselves as
    /// `balance` says. Empty by default.
    pub backup: Vec<TargetCfg>,
    /// The `route` label this prefix's requests carry in the per-route metrics. Empty (default)
    /// uses `path`.
    pub name: String,
    /// Active checks for a pool's targets. Off unless `health_check.path` is set.
    pub health_check: HealthCheckCfg,
    /// Take a pool's target out of rotation after this many requests in a row fail to connect to
    /// it: refused, unreachable, past `validation.upstream_connect_timeout`, or a failed TLS
    /// handshake. `0` turns it off. Default `1`: the request that failed is retried on the next
    /// target, so the first failure costs nothing but that attempt.
    pub eject_after: u32,
    /// How long such a target stays out before requests try it again: this, times the number of
    /// ejections in a row, up to `eject_for_max`. Default `"30s"`.
    pub eject_for: String,
    /// The longest an ejection grows to: a target ejected again soon after coming back is out
    /// `eject_for` × 2, then × 3, up to this. One not ejected again for this long after its last
    /// ejection ends starts over.
    /// Empty (default) is 5 minutes, or `eject_for` if longer; set it to `eject_for` for every
    /// ejection to last the same.
    pub eject_for_max: String,
    /// Take a pool's target out of rotation, for `eject_for`, after this many answers in a row
    /// with a `5xx` status: a server that is up but broken. Any other answer resets the count.
    /// Never the last target in rotation: when every one answers `5xx`, rotation cannot help.
    /// `0` (default) turns it off, since a `500` may be one endpoint's bug rather than the server's.
    pub eject_after_5xx: u32,
}

impl Default for UpstreamRoute {
    fn default() -> Self {
        UpstreamRoute {
            path: String::new(),
            target: String::new(),
            targets: Vec::new(),
            balance: "priority".into(),
            hash_on: String::new(),
            sticky_cookie: String::new(),
            sticky_cookie_max_age: String::new(),
            sticky_cookie_strip: false,
            backup: Vec::new(),
            name: String::new(),
            health_check: HealthCheckCfg::default(),
            eject_after: 1,
            eject_for: "30s".into(),
            eject_after_5xx: 0,
            eject_for_max: String::new(),
        }
    }
}

/// One entry of a pool's `targets` or `backup`: a URL, or `{ url = "…", weight = 3 }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCfg {
    pub url: String,
    /// Its turns, with `balance = "round_robin"`, for each one the others with weight 1 get: a
    /// target with weight 3 takes three requests for every one theirs take. `None` for a bare
    /// URL, which counts as 1.
    pub weight: Option<u32>,
}

impl From<&str> for TargetCfg {
    fn from(url: &str) -> Self {
        TargetCfg {
            url: url.to_string(),
            weight: None,
        }
    }
}

impl From<String> for TargetCfg {
    fn from(url: String) -> Self {
        TargetCfg { url, weight: None }
    }
}

impl<'de> Deserialize<'de> for TargetCfg {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        /// The table form. Unknown keys are refused, so a misspelled `weight` is an error rather
        /// than a silent weight of 1.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Table {
            url: String,
            weight: Option<u32>,
        }
        struct Entry;
        impl<'de> serde::de::Visitor<'de> for Entry {
            type Value = TargetCfg;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a URL, or a table with url and weight")
            }
            fn visit_str<E: serde::de::Error>(
                self,
                url: &str,
            ) -> std::result::Result<TargetCfg, E> {
                Ok(url.into())
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> std::result::Result<TargetCfg, A::Error> {
                let t = Table::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(TargetCfg {
                    url: t.url,
                    weight: t.weight,
                })
            }
        }
        d.deserialize_any(Entry)
    }
}

/// `[upstreams.health_check]` — active checks of a pool's targets: a `GET` (or `method`) of `path`
/// on each target every `interval`. A target answering `2xx` or `3xx` within `timeout` passes. It leaves
/// rotation after `unhealthy_after` failures in a row and returns after `healthy_after` passes. A
/// new target starts in rotation, and is checked at once.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HealthCheckCfg {
    /// `"http"` (default): `GET path`, judged by `expect_status` and `expect_body`. `"tcp"`: a
    /// connection to the target's host and port, and nothing more, for a target that speaks no
    /// HTTP worth asking or has no health endpoint.
    #[serde(rename = "type")]
    pub kind: String,
    /// The path to check, relative to each target as a request's is, e.g. `/healthz`. Empty
    /// (default) leaves only the passive check, `eject_after`, unless `type = "tcp"`.
    pub path: String,
    /// Default `"5s"`.
    pub interval: String,
    /// Default `"2s"`.
    pub timeout: String,
    /// Default `2`.
    pub healthy_after: u32,
    /// Default `2`.
    pub unhealthy_after: u32,
    /// The statuses that pass: codes, ranges and classes, comma-separated, e.g. `"200"`,
    /// `"2xx"`, or `"200-299,304"`. Default `"200-399"`. Redirects are not followed.
    pub expect_status: String,
    /// Text the first 64 KiB of the answer's body must contain, e.g. `"\"status\":\"ok\""`, for
    /// an endpoint that answers `200` while saying it is down. Empty (default): the status alone.
    pub expect_body: String,
    /// A regular expression the body must match instead, e.g.
    /// `"\"status\":\\s*\"(ok|degraded)\""`: Rust `regex` syntax, which runs in linear time. It is
    /// searched for in the body as read to its end, or to its first 64 KiB: `^` and `$` are the
    /// start and end of that unless `(?m)` makes them lines. Set this or `expect_body`, not both.
    pub expect_body_regex: String,
    /// The check's method. Default `"GET"`. `"HEAD"` asks for the status alone, so it takes no
    /// `expect_body`. Any method but `CONNECT`; no body is sent.
    pub method: String,
    /// Headers each check sends, as `[name, value]` pairs, e.g. `[["Host", "app.internal"]]` for a
    /// target that routes by name, or a token its health endpoint wants. One that names
    /// `User-Agent` replaces the edge's. The status endpoint shows their names, not their values.
    pub headers: Vec<(String, String)>,
    /// Check each target on this port instead of the one requests go to, for an app that serves
    /// its health on a separate management port. The target's host, scheme (an `https://` target
    /// is checked over TLS on this port too, with the TLS settings its requests use) and path
    /// prefix are kept. `0` (default): the target's own port.
    pub port: u16,
}

impl Default for HealthCheckCfg {
    fn default() -> Self {
        HealthCheckCfg {
            kind: "http".into(),
            path: String::new(),
            interval: "5s".into(),
            timeout: "2s".into(),
            healthy_after: 2,
            unhealthy_after: 2,
            expect_status: "200-399".into(),
            expect_body: String::new(),
            expect_body_regex: String::new(),
            method: "GET".into(),
            headers: Vec::new(),
            port: 0,
        }
    }
}

/// `[upstream_tls]` — TLS from EdgeGuard to `https://` upstreams.
///
/// An `https://` upstream (`server.upstream` or a `[[upstreams]]` target) is reached over TLS 1.2+
/// and its certificate verified, with no configuration: by default against the public web PKI
/// (the Mozilla root set built into the binary). The settings here change who is trusted, add a
/// client certificate for upstreams that require one (mutual TLS), and set the name to verify.
/// `[[upstream_tls.targets]]` entries give one upstream its own settings; any field left empty
/// there is taken from here.
///
/// Edge-local, like `[server]` and `[tls]`: a control-plane policy never changes it. Read at
/// startup; the client certificate and key are reloaded when they change on disk.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UpstreamTlsCfg {
    /// PEM bundle of the CAs allowed to sign an upstream's certificate. Empty (default) trusts the
    /// public web PKI. When set, **only** these CAs are trusted: a certificate from a public CA for
    /// the same name is refused, which is the point of a private CA. A self-signed upstream
    /// certificate goes here too; there is no option to skip verification.
    pub ca_path: String,
    /// PEM certificate chain EdgeGuard presents to an upstream that asks for a client certificate
    /// (mutual TLS). Set together with `key_path`. Reloaded when the file changes, like the
    /// listener's certificate; new connections use the new one.
    pub cert_path: String,
    /// PEM private key for `cert_path`.
    pub key_path: String,
    /// Name to verify the upstream's certificate against and to send as SNI, instead of the host
    /// in the upstream URL. For an upstream addressed by IP, or through a name its certificate
    /// does not carry. Empty (default) uses the URL's host.
    pub server_name: String,
    /// Settings for one upstream at a time. See [`UpstreamTlsTarget`].
    pub targets: Vec<UpstreamTlsTarget>,
}

/// One `[[upstream_tls.targets]]` entry: TLS settings for a single upstream, overriding the ones
/// in `[upstream_tls]` field by field.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UpstreamTlsTarget {
    /// The upstream these settings apply to, as an `https://host[:port]` URL: the same host and
    /// port as in `server.upstream` or a `[[upstreams]] target` (any path is ignored, and the port
    /// defaults to 443). Each upstream may be listed once.
    pub target: String,
    /// See [`UpstreamTlsCfg::ca_path`]. Empty inherits it.
    pub ca_path: String,
    /// See [`UpstreamTlsCfg::cert_path`]. Set together with `key_path`; empty inherits both.
    pub cert_path: String,
    /// See [`UpstreamTlsCfg::key_path`].
    pub key_path: String,
    /// See [`UpstreamTlsCfg::server_name`]. Empty inherits it.
    pub server_name: String,
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
    /// Answer CORS preflights and decorate responses. Off by default: a proxy that adds
    /// permissive CORS headers by surprise is a security hole, not a convenience.
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
        // A platform that hands out ports by environment (and the Docker examples) can turn the
        // redirect listener on without a config edit, matching PORT/ADMIN_PORT.
        if let Ok(p) = env::var("REDIRECT_PORT") {
            if let Ok(v) = p.parse() {
                cfg.tls.redirect_port = v;
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
        cfg.inherit_outbound();
        Ok(cfg)
    }

    /// Every section that opens a client of its own, whether this config opens it, and where to.
    pub fn outbound_clients(&self) -> [OutboundClient<'_>; 9] {
        fn client<'a>(
            section: &'static str,
            enabled: bool,
            url: &'a str,
            outbound: &'a OutboundCfg,
        ) -> OutboundClient<'a> {
            OutboundClient {
                section,
                enabled,
                url: url.trim(),
                outbound,
            }
        }
        let dns = &self.tls.acme.dns;
        [
            client(
                "control_plane",
                self.control_plane.enabled,
                &self.control_plane.url,
                &self.control_plane.outbound,
            ),
            client(
                "log.ship",
                self.log.ship.enabled,
                &self.log.ship.url,
                &self.log.ship.outbound,
            ),
            client(
                "tracing",
                self.tracing.enabled,
                &self.tracing.endpoint,
                &self.tracing.outbound,
            ),
            client(
                "metrics.otlp",
                self.metrics.otlp.enabled,
                &self.metrics.otlp.endpoint,
                &self.metrics.otlp.outbound,
            ),
            client(
                "auth.jwt",
                !self.auth.jwt.jwks_url.trim().is_empty(),
                &self.auth.jwt.jwks_url,
                &self.auth.jwt.outbound,
            ),
            client(
                "alerts",
                self.alerts.enabled,
                &self.alerts.webhook_url,
                &self.alerts.outbound,
            ),
            client(
                "llm.telemetry",
                self.llm.telemetry.enabled,
                &self.llm.telemetry.endpoint,
                &self.llm.telemetry.outbound,
            ),
            client(
                "tls.acme",
                self.tls.acme.enabled,
                &self.tls.acme.directory_url,
                &self.tls.acme.outbound,
            ),
            client(
                "tls.acme.dns",
                self.tls.acme.enabled && self.tls.acme.challenge == "dns-01",
                if dns.provider == "challtestsrv" {
                    &dns.url
                } else {
                    &dns.api_base
                },
                &dns.outbound,
            ),
        ]
    }

    /// Copy `[outbound]` into every section, for the keys each leaves empty. [`Config::load`] does
    /// this; a config built another way calls it before building clients from it.
    pub fn inherit_outbound(&mut self) {
        for section in [
            &mut self.control_plane.outbound,
            &mut self.log.ship.outbound,
            &mut self.tracing.outbound,
            &mut self.metrics.otlp.outbound,
            &mut self.auth.jwt.outbound,
            &mut self.alerts.outbound,
            &mut self.llm.telemetry.outbound,
            &mut self.tls.acme.outbound,
            &mut self.tls.acme.dns.outbound,
        ] {
            section.defaults = self.outbound.clone();
        }
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
            // So is how this edge reaches its upstreams over TLS: the CA bundle and client
            // certificate are files on this box, and the trust they express is this edge's own.
            // A pushed policy that could swap the CA would let a control plane vouch for any
            // certificate the upstream connection is offered.
            upstream_tls: self.upstream_tls.clone(),
            // The policy decides who may call; how this edge reaches the JWKS endpoint (its CA,
            // its client certificate, its proxy) is edge-local, like `upstream_tls`.
            auth: AuthCfg {
                jwt: JwtCfg {
                    outbound: self.auth.jwt.outbound.clone(),
                    ..p.auth.jwt
                },
                ..p.auth
            },
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
            // Access-log redaction is edge-local and deliberately NOT pushable. A control plane
            // able to flip an edge to `query = "full"` could turn that edge's own logs into an
            // exfiltration channel for every credential its users put in a URL — without touching
            // the edge's config file or leaving a trace anywhere the edge's operator looks.
            log: self.log.clone(),
            // Same reasoning as `log` above, and the stakes are identical: the tracing endpoint is
            // where request metadata is sent. A control plane that could push `[tracing]` could
            // redirect an edge's traces — path, query, client address, user agent — to a collector
            // of its choosing. Edge-local, never pushed.
            tracing: self.tracing.clone(),
            // And the metrics endpoint: where this edge's numbers (hostnames, certificate names,
            // route labels) are pushed. Edge-local, never pushed.
            metrics: self.metrics.clone(),
            // Which addresses may assert a client certificate in a header is network trust, not
            // policy: a control plane that could widen it could mint any identity.
            trusted_client_cert_header: self.trusted_client_cert_header.clone(),
            // How this edge reaches the network — its proxy, its identity, the CAs it adds — is
            // edge-local like each section's own settings, and for the same reason: a pushed
            // proxy plus a pushed CA would let a control plane read every connection the edge
            // opens, its own included. Every section that inherits it is carried from the edge
            // too, defaults already copied in.
            outbound: self.outbound.clone(),
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

    /// A pushed policy cannot repoint where this edge sends its metrics or traces.
    #[test]
    fn with_policy_from_keeps_the_metrics_and_tracing_endpoints_edge_local() {
        let mut local = Config::default();
        local.metrics.otlp.enabled = true;
        local.metrics.otlp.endpoint = "http://local:4318/v1/metrics".into();
        local.tracing.endpoint = "http://local:4318/v1/traces".into();
        let policy = "[metrics.otlp]\nenabled = true\nendpoint = \"http://evil:4318/v1/metrics\"\n\n[tracing]\nendpoint = \"http://evil:4318/v1/traces\"\n";
        let merged = local.with_policy_from(policy).unwrap();
        assert_eq!(merged.metrics.otlp.endpoint, "http://local:4318/v1/metrics");
        assert_eq!(merged.tracing.endpoint, "http://local:4318/v1/traces");
    }

    /// A pushed policy cannot make the edge trust a client-certificate header from anyone new.
    #[test]
    fn with_policy_from_keeps_the_trusted_client_cert_header_edge_local() {
        let mut local = Config::default();
        local.trusted_client_cert_header.name = "X-Amzn-Mtls-Clientcert".into();
        local.trusted_client_cert_header.trusted_proxies = vec!["10.0.0.0/16".into()];
        let policy =
            "[trusted_client_cert_header]\nname = \"X-Evil\"\ntrusted_proxies = [\"0.0.0.0/1\"]\n";
        let merged = local.with_policy_from(policy).unwrap();
        assert_eq!(
            merged.trusted_client_cert_header.name,
            "X-Amzn-Mtls-Clientcert"
        );
        assert_eq!(
            merged.trusted_client_cert_header.trusted_proxies,
            ["10.0.0.0/16"]
        );
    }

    /// A pushed policy sets the JWKS URL but not the CA, certificate or proxy used to fetch it.
    #[test]
    fn with_policy_from_keeps_how_the_jwks_is_fetched_edge_local() {
        let mut local = Config::default();
        local.auth.jwt.outbound.ca_path = "/etc/eggrd/corp-ca.pem".into();
        local.auth.jwt.outbound.proxy = "none".into();
        let policy = "[auth]\nmode = \"jwt\"\n\n[auth.jwt]\nalgorithm = \"ES256\"\njwks_url = \"https://idp.example/jwks\"\nca_path = \"/tmp/evil-ca.pem\"\nproxy = \"http://evil:3128\"\n";
        let merged = local.with_policy_from(policy).unwrap();
        assert_eq!(merged.auth.mode, "jwt");
        assert_eq!(merged.auth.jwt.jwks_url, "https://idp.example/jwks");
        assert_eq!(merged.auth.jwt.outbound.ca_path, "/etc/eggrd/corp-ca.pem");
        assert_eq!(merged.auth.jwt.outbound.proxy, "none");
    }

    /// The four keys sit directly in each section, and reach the field they name.
    #[test]
    fn outbound_settings_parse_in_every_section() {
        let mut toml = String::new();
        for section in [
            "control_plane",
            "log.ship",
            "tracing",
            "metrics.otlp",
            "auth.jwt",
            "alerts",
            "llm.telemetry",
            "tls.acme",
            "tls.acme.dns",
        ] {
            toml.push_str(&format!(
                "[{section}]\nca_path = \"{section}-ca\"\nclient_cert_path = \"{section}-cert\"\n\
                 client_key_path = \"{section}-key\"\nproxy = \"none\"\n\n"
            ));
        }
        let cfg: Config = toml::from_str(&toml).unwrap();
        for (section, o) in [
            ("control_plane", &cfg.control_plane.outbound),
            ("log.ship", &cfg.log.ship.outbound),
            ("tracing", &cfg.tracing.outbound),
            ("metrics.otlp", &cfg.metrics.otlp.outbound),
            ("auth.jwt", &cfg.auth.jwt.outbound),
            ("alerts", &cfg.alerts.outbound),
            ("llm.telemetry", &cfg.llm.telemetry.outbound),
            ("tls.acme", &cfg.tls.acme.outbound),
            ("tls.acme.dns", &cfg.tls.acme.dns.outbound),
        ] {
            assert_eq!(o.ca_path, format!("{section}-ca"));
            assert_eq!(o.client_cert_path, format!("{section}-cert"));
            assert_eq!(o.client_key_path, format!("{section}-key"));
            assert_eq!(o.proxy, "none");
        }
        // The section's own keys still parse beside them, defaults included.
        let cfg: Config = toml::from_str(
            "[log.ship]\nenabled = true\nurl = \"https://c\"\nbatch = 7\nheaders = [[\"a\", \"b\"]]\n\
             ca_path = \"x\"\n\n[tracing]\nsample_rate = 0.25\ntimeout_ms = 900\n",
        )
        .unwrap();
        assert_eq!(cfg.log.ship.batch, 7);
        assert_eq!(cfg.log.ship.headers, [("a".to_string(), "b".to_string())]);
        assert_eq!(cfg.log.ship.outbound.ca_path, "x");
        assert_eq!(cfg.tracing.sample_rate, 0.25);
        assert_eq!(cfg.tracing.timeout_ms, 900);
        assert_eq!(cfg.tracing.queue_size, 10_000, "defaults still apply");

        // [tls.acme] reads its own keys, its [tls.acme.dns] table and the outbound ones together.
        let cfg: Config = toml::from_str(
            "[tls.acme]\nenabled = true\ndomains = [\"a.example\", \"b.example\"]\nrenew = false\n\
             proxy = \"http://egress:3128\"\n\n[tls.acme.dns]\nprovider = \"cloudflare\"\n\
             propagation_secs = 5\nproxy = \"none\"\n",
        )
        .unwrap();
        let acme = &cfg.tls.acme;
        assert!(acme.enabled && !acme.renew && acme.ari, "{acme:?}");
        assert_eq!(acme.domains, ["a.example", "b.example"]);
        assert_eq!(acme.outbound.proxy, "http://egress:3128");
        assert_eq!(acme.dns.provider, "cloudflare");
        assert_eq!(acme.dns.propagation_secs, 5);
        assert_eq!(acme.dns.outbound.proxy, "none", "each table keeps its own");
        assert_eq!(
            acme.directory_url, "https://acme-staging-v02.api.letsencrypt.org/directory",
            "defaults still apply"
        );
    }

    #[test]
    fn outbound_defaults_reach_every_section_from_load_and_stay_edge_local() {
        let path = std::env::temp_dir().join(format!("eg-outbound-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            "[outbound]\nextra_ca_path = \"/etc/eggrd/corp-ca.pem\"\n\
             client_cert_path = \"/etc/eggrd/edge.pem\"\nclient_key_path = \"/etc/eggrd/edge.key\"\n\
             proxy = \"http://egress:3128\"\n\n[log.ship]\nproxy = \"none\"\n",
        )
        .unwrap();
        let local = Config::load(path.to_str()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(local.outbound.proxy, "http://egress:3128");
        let clients = local.outbound_clients();
        let sections: Vec<&str> = clients.iter().map(|c| c.section).collect();
        assert_eq!(
            sections,
            [
                "control_plane",
                "log.ship",
                "tracing",
                "metrics.otlp",
                "auth.jwt",
                "alerts",
                "llm.telemetry",
                "tls.acme",
                "tls.acme.dns"
            ]
        );
        for c in &clients {
            assert_eq!(
                c.outbound.defaults.client_cert_path, "/etc/eggrd/edge.pem",
                "{}",
                c.section
            );
            assert_eq!(c.outbound.defaults.extra_ca_path, "/etc/eggrd/corp-ca.pem");
        }
        // The section's own key is kept beside the inherited ones; resolving it is the client's.
        assert_eq!(local.log.ship.outbound.proxy, "none");
        assert_eq!(local.log.ship.outbound.defaults.proxy, "http://egress:3128");
        assert!(
            Config::default()
                .outbound_clients()
                .iter()
                .all(|c| !c.enabled),
            "nothing is on by default"
        );

        // A pushed policy cannot repoint it: not the defaults, not the sections that take them.
        let policy =
            "[outbound]\nproxy = \"http://cp-chosen:3128\"\nextra_ca_path = \"/tmp/cp-ca.pem\"\n\n\
                      [auth.jwt]\njwks_url = \"https://idp.example/jwks\"\n";
        let merged = local.with_policy_from(policy).unwrap();
        assert_eq!(merged.outbound.proxy, "http://egress:3128");
        assert_eq!(merged.outbound.extra_ca_path, "/etc/eggrd/corp-ca.pem");
        assert_eq!(merged.auth.jwt.jwks_url, "https://idp.example/jwks");
        for c in merged.outbound_clients() {
            assert_eq!(
                c.outbound.defaults.proxy, "http://egress:3128",
                "{}",
                c.section
            );
        }
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
