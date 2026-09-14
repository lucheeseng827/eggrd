//! OTLP span emission (gateway L4 observability) — SDK-free tracing straight from the request path.
//!
//! When `[llm.telemetry]` is enabled, EdgeGuard emits one OpenInference/OTLP span per metered LLM
//! request to an OTLP/HTTP `/v1/traces` receiver (e.g. evald). Because the proxy sits in the request
//! path, the span carries the correct model, per-tier tokens, computed cost, and **server-side**
//! TTFT/TPOT/latency with no client SDK, no import-order fragility, and no per-framework instrumentor
//! drift — the exact failure class that plagues in-process instrumentation (nested usage, dropped
//! spans, async nesting breakage). Emission is **fire-and-forget**: it never blocks or fails the
//! client response.
//!
//! The wire format is **OTLP-JSON** posted with the crate's existing HTTP client, so the data plane
//! stays a single static binary (no protobuf codegen, no OpenTelemetry SDK). The span attribute keys
//! are exactly the OpenInference / `gen_ai.*` keys a downstream store normalizes (`llm.model_name`,
//! `llm.token_count.*`, `input.value`, …), so a gateway span round-trips into evald unchanged.

use std::time::Duration;

use serde_json::{json, Value};

use crate::config::TelemetryCfg;

/// W3C trace context for one emitted span. `parent_span_id` is set when an inbound `traceparent`
/// stitched this gateway span under an app-side span (so both land in one trace).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub parent_span_id: Option<[u8; 8]>,
}

impl TraceContext {
    /// Derive a context from an optional inbound W3C `traceparent`. If it is present and well-formed,
    /// reuse its trace id and make the inbound span our parent (app-side spans + this gateway span
    /// stitch into one trace); otherwise mint a fresh root trace. The span id is always freshly random.
    pub fn from_traceparent(traceparent: Option<&str>) -> TraceContext {
        let span_id = rand8();
        match traceparent.and_then(parse_traceparent) {
            Some((trace_id, parent)) => TraceContext {
                trace_id,
                span_id,
                parent_span_id: Some(parent),
            },
            None => TraceContext {
                trace_id: rand16(),
                span_id,
                parent_span_id: None,
            },
        }
    }
}

/// A metered LLM request rendered into span form. `input`/`output` stay `None` unless content capture
/// is enabled (they are populated, already DLP-redacted, at the wiring site).
#[derive(Clone, Debug)]
pub struct SpanRecord {
    pub ctx: TraceContext,
    pub name: String,
    pub model: String,
    pub provider: Option<String>,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cached_tokens: u64,
    pub reasoning_tokens: u64,
    /// Cost in micro-dollars; `None` when the model is unpriced (tokens still emitted).
    pub cost_micros: Option<u64>,
    pub start_unix_nano: u64,
    pub end_unix_nano: u64,
    pub ttft: Option<Duration>,
    pub tpot: Option<Duration>,
    /// Upstream status was 2xx.
    pub status_ok: bool,
    pub input: Option<String>,
    pub output: Option<String>,
    pub session_id: Option<String>,
}

/// The compiled telemetry runtime carried on the proxy [`Runtime`](crate::proxy::Runtime).
#[derive(Clone)]
pub struct TelemetryRuntime {
    pub enabled: bool,
    endpoint: String,
    sample_rate: f64,
    service_name: String,
    /// Whether to attach captured prompt/response content (populated at the wiring site).
    pub capture_content: bool,
    pub max_content_bytes: usize,
    client: reqwest::Client,
}

impl TelemetryRuntime {
    /// Compile from config. `enabled` folds in "has a non-empty endpoint" so a misconfigured switch
    /// (on, but no endpoint) is inert rather than erroring on every request.
    pub fn build(cfg: &TelemetryCfg) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms.max(1)))
            .build()
            .unwrap_or_default();
        let service_name = if cfg.service_name.trim().is_empty() {
            "edgeguard".to_string()
        } else {
            cfg.service_name.trim().to_string()
        };
        TelemetryRuntime {
            enabled: cfg.enabled && !cfg.endpoint.trim().is_empty(),
            endpoint: cfg.endpoint.trim().to_string(),
            sample_rate: cfg.sample_rate.clamp(0.0, 1.0),
            service_name,
            capture_content: cfg.capture_content,
            max_content_bytes: cfg.max_content_bytes,
            client,
        }
    }

    /// An inert runtime (emission off) — the default when `[llm.telemetry]` is absent.
    pub fn disabled() -> Self {
        Self::build(&TelemetryCfg::default())
    }

    /// Whether a trace id falls in the sampled fraction. Deterministic per trace (folding
    /// both 64-bit halves together is the uniform draw), so a trace is sampled consistently
    /// and sampling needs no RNG.
    fn sampled(&self, trace_id: &[u8; 16]) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }
        // XOR both halves rather than using bytes 8..16 alone: for a UUIDv4 trace id, byte 8
        // carries the RFC 4122 variant bits (fixed to `10` in the top two bits), which would
        // otherwise bias the draw to only ever cover half its intended range.
        let lo = u64::from_be_bytes(trace_id[0..8].try_into().expect("8 bytes"));
        let hi = u64::from_be_bytes(trace_id[8..16].try_into().expect("8 bytes"));
        let draw = lo ^ hi;
        (draw as f64 / u64::MAX as f64) < self.sample_rate
    }

    /// Fire-and-forget: build the OTLP-JSON and POST it on a background task. Never blocks, and any
    /// error (endpoint down, non-2xx) is swallowed at debug level — telemetry must not affect traffic.
    pub fn emit(&self, record: SpanRecord) {
        if !self.enabled || !self.sampled(&record.ctx.trace_id) {
            return;
        }
        let body = build_export_json(&record, &self.service_name);
        let client = self.client.clone();
        let endpoint = self.endpoint.clone();
        tokio::spawn(async move {
            match client.post(&endpoint).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => tracing::debug!(status = %resp.status(), "otlp span emit rejected"),
                Err(e) => tracing::debug!(error = %e, "otlp span emit failed"),
            }
        });
    }
}

/// Lossy-UTF8 a captured body and truncate it to `max_bytes` on a char boundary (with a marker), so
/// a large prompt/response can't bloat the emitted span. Used at the content-capture wiring site.
pub fn prepare_content(bytes: &[u8], max_bytes: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    if s.len() <= max_bytes {
        return s.into_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated]", &s[..end])
}

/// Build the OTLP-JSON `ExportTraceServiceRequest` for one span. The attribute keys are the
/// OpenInference / `gen_ai.*` keys a downstream OTel store normalizes, so the span round-trips.
/// Ints are encoded as strings (the protobuf int64 → JSON mapping OTLP-JSON uses).
pub fn build_export_json(r: &SpanRecord, service_name: &str) -> Value {
    let mut attrs: Vec<Value> = Vec::new();
    attrs.push(kv_str("openinference.span.kind", "LLM"));
    attrs.push(kv_str("llm.model_name", &r.model));
    if let Some(p) = &r.provider {
        attrs.push(kv_str("llm.provider", p));
    }
    attrs.push(kv_int("llm.token_count.prompt", r.prompt_tokens));
    attrs.push(kv_int("llm.token_count.completion", r.completion_tokens));
    attrs.push(kv_int(
        "llm.token_count.total",
        r.prompt_tokens.saturating_add(r.completion_tokens),
    ));
    if r.cached_tokens > 0 {
        attrs.push(kv_int(
            "llm.token_count.prompt_details.cache_read",
            r.cached_tokens,
        ));
    }
    if r.reasoning_tokens > 0 {
        attrs.push(kv_int(
            "llm.token_count.completion_details.reasoning",
            r.reasoning_tokens,
        ));
    }
    if let Some(micros) = r.cost_micros {
        attrs.push(kv_double("llm.cost.total", micros as f64 / 1_000_000.0));
    }
    if let Some(ttft) = r.ttft {
        attrs.push(kv_double("edgeguard.ttft_seconds", ttft.as_secs_f64()));
    }
    if let Some(tpot) = r.tpot {
        attrs.push(kv_double("edgeguard.tpot_seconds", tpot.as_secs_f64()));
    }
    if let Some(session) = &r.session_id {
        attrs.push(kv_str("session.id", session));
    }
    if let Some(input) = &r.input {
        attrs.push(kv_str("input.value", input));
    }
    if let Some(output) = &r.output {
        attrs.push(kv_str("output.value", output));
    }

    let mut span = json!({
        "traceId": hex(&r.ctx.trace_id),
        "spanId": hex(&r.ctx.span_id),
        "name": r.name,
        "kind": 3, // CLIENT — an outbound model call
        "startTimeUnixNano": r.start_unix_nano.to_string(),
        "endTimeUnixNano": r.end_unix_nano.to_string(),
        "status": { "code": if r.status_ok { 1 } else { 2 } }, // OK / ERROR
        "attributes": attrs,
    });
    if let Some(parent) = &r.ctx.parent_span_id {
        span["parentSpanId"] = Value::String(hex(parent));
    }

    json!({
        "resourceSpans": [{
            "resource": { "attributes": [ kv_str("service.name", service_name) ] },
            "scopeSpans": [{
                "scope": { "name": "edgeguard", "version": env!("CARGO_PKG_VERSION") },
                "spans": [ span ],
            }],
        }],
    })
}

/// Whether a trace id falls in the sampled fraction, as a free function so the HTTP server span and
/// the LLM client span reach the SAME verdict for one request. Deterministic per trace: folding both
/// 64-bit halves together is the uniform draw, so a trace is sampled consistently wherever it is
/// evaluated and a trace is never half-recorded.
pub fn trace_sampled(sample_rate: f64, trace_id: &[u8; 16]) -> bool {
    if sample_rate >= 1.0 {
        return true;
    }
    if sample_rate <= 0.0 {
        return false;
    }
    let hi = u64::from_be_bytes(trace_id[0..8].try_into().unwrap_or([0; 8]));
    let lo = u64::from_be_bytes(trace_id[8..16].try_into().unwrap_or([0; 8]));
    ((hi ^ lo) as f64 / u64::MAX as f64) < sample_rate
}

/// Render a [`TraceContext`] as the W3C `traceparent` header value to send upstream.
///
/// `01` in the flags means sampled. This is only ever built for a span we are recording, so the
/// upstream is told the trace is sampled — which is what makes the app's own spans join this trace
/// instead of being dropped by its sampler.
pub fn traceparent_header(ctx: &TraceContext) -> String {
    format!("00-{}-{}-01", hex(&ctx.trace_id), hex(&ctx.span_id))
}

/// One proxied HTTP request, rendered as an OpenTelemetry **SERVER** span.
///
/// Attribute names follow the current stable HTTP semantic conventions, which renamed nearly all of
/// them (`http.method` became `http.request.method`, `http.url` became `url.*`). Getting these wrong
/// is not cosmetic: every backend normalizes on the stable names, so an old-name span is dropped
/// from latency and error panels rather than being merely oddly labelled.
#[derive(Clone, Debug)]
pub struct ServerSpan {
    pub ctx: TraceContext,
    /// The method, or `_OTHER` when it is not one of the known set (semconv requires that).
    pub method: String,
    /// Set only when `method` was replaced by `_OTHER`.
    pub method_original: Option<String>,
    pub url_path: String,
    /// The query string, **already sanitised** by [`crate::accesslog::sanitize_target`]. `None`
    /// when the request carried none.
    ///
    /// This is the one place the HTTP semconv is deliberately not followed to the letter. The spec
    /// wants the query as received; this proxy redacts credential-shaped values everywhere else it
    /// writes them, and a span is shipped to the same class of destination as an access log. Sending
    /// the raw query here would reintroduce, in traces, exactly the leak the access log was built to
    /// prevent.
    pub url_query: Option<String>,
    pub url_scheme: String,
    pub status_code: u16,
    pub client_address: Option<String>,
    pub server_address: Option<String>,
    pub user_agent: Option<String>,
    pub protocol_version: Option<String>,
    /// EdgeGuard's own verdict (`proxied`, `rate_limited`, `waf_blocked`, …). Not a semconv
    /// attribute, so it is namespaced — it says WHY a request ended as it did, which the status code
    /// alone does not.
    pub outcome: String,
    pub request_id: String,
    pub start_unix_nano: u128,
    pub end_unix_nano: u128,
}

impl ServerSpan {
    /// Methods the semantic conventions define. Anything else must be reported as `_OTHER` with the
    /// original in `http.request.method_original`, so an attacker cannot create unbounded label
    /// cardinality by inventing methods.
    pub fn normalize_method(method: &str) -> (String, Option<String>) {
        const KNOWN: [&str; 9] = [
            "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
        ];
        if KNOWN.contains(&method) {
            (method.to_string(), None)
        } else {
            ("_OTHER".to_string(), Some(method.to_string()))
        }
    }
}

/// Build the OTLP-JSON for a batch of server spans — one POST body for many spans.
///
/// Batched because a proxy emits one span per request. One POST each would make the tracing backend
/// the busiest thing the edge talks to and would put a network round trip in the path of every
/// request's teardown.
pub fn build_server_spans_json(spans: &[ServerSpan], service_name: &str) -> Value {
    let rendered: Vec<Value> = spans.iter().map(render_server_span).collect();
    json!({
        "resourceSpans": [{
            "resource": { "attributes": [ kv_str("service.name", service_name) ] },
            "scopeSpans": [{
                "scope": { "name": "edgeguard", "version": env!("CARGO_PKG_VERSION") },
                "spans": rendered,
            }],
        }],
    })
}

fn render_server_span(r: &ServerSpan) -> Value {
    let mut attrs = vec![
        // Required by the spec for a server span.
        kv_str("http.request.method", &r.method),
        kv_str("url.path", &r.url_path),
        kv_str("url.scheme", &r.url_scheme),
        // Conditionally required: a response was sent.
        kv_int("http.response.status_code", r.status_code as u64),
    ];
    if let Some(orig) = &r.method_original {
        attrs.push(kv_str("http.request.method_original", orig));
    }
    if let Some(q) = &r.url_query {
        attrs.push(kv_str("url.query", q));
    }
    if let Some(c) = &r.client_address {
        attrs.push(kv_str("client.address", c));
    }
    if let Some(sa) = &r.server_address {
        attrs.push(kv_str("server.address", sa));
    }
    if let Some(ua) = &r.user_agent {
        attrs.push(kv_str("user_agent.original", ua));
    }
    if let Some(v) = &r.protocol_version {
        attrs.push(kv_str("network.protocol.version", v));
    }
    attrs.push(kv_str("edgeguard.outcome", &r.outcome));
    attrs.push(kv_str("edgeguard.request_id", &r.request_id));

    // Span status. The spec is explicit and counter-intuitive here: for a SERVER span a 4xx MUST be
    // left unset, because the server handled the request correctly — the client sent a bad one.
    // Only 5xx (and uninterpreted failures) are Error. Marking 4xx as Error is the common mistake
    // and it makes every error-rate panel read a 404 storm as an outage.
    let mut span = json!({
        "traceId": hex(&r.ctx.trace_id),
        "spanId": hex(&r.ctx.span_id),
        "name": r.method,   // `{method}` — a proxy has no route template to name
        "kind": 2,          // SERVER
        "startTimeUnixNano": r.start_unix_nano.to_string(),
        "endTimeUnixNano": r.end_unix_nano.to_string(),
        "attributes": attrs,
    });
    if r.status_code >= 500 {
        span["status"] = json!({ "code": 2 });
        span["attributes"]
            .as_array_mut()
            .expect("attributes is an array")
            .push(kv_str("error.type", &r.status_code.to_string()));
    }
    if let Some(parent) = &r.ctx.parent_span_id {
        span["parentSpanId"] = Value::String(hex(parent));
    }
    span
}

fn kv_str(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}
fn kv_int(key: &str, value: u64) -> Value {
    // OTLP-JSON encodes int64 as a string.
    json!({ "key": key, "value": { "intValue": value.to_string() } })
}
fn kv_double(key: &str, value: f64) -> Value {
    json!({ "key": key, "value": { "doubleValue": value } })
}

/// Parse a W3C `traceparent` (`VV-<32hex trace>-<16hex span>-FF`). Returns `(trace_id, span_id)` when
/// well-formed with non-zero ids; else `None` (a malformed header just means "start a fresh trace").
fn parse_traceparent(s: &str) -> Option<([u8; 16], [u8; 8])> {
    let mut parts = s.trim().split('-');
    let _version = parts.next()?;
    let trace_hex = parts.next()?;
    let span_hex = parts.next()?;
    let _flags = parts.next()?;
    if parts.next().is_some() || trace_hex.len() != 32 || span_hex.len() != 16 {
        return None;
    }
    let trace: [u8; 16] = hex_to_bytes::<16>(trace_hex)?;
    let span: [u8; 8] = hex_to_bytes::<8>(span_hex)?;
    if trace == [0u8; 16] || span == [0u8; 8] {
        return None; // all-zero ids are "invalid" per the spec
    }
    Some((trace, span))
}

/// Decode exactly `N` bytes from a `2N`-char lowercase/uppercase hex string; `None` on any non-hex.
fn hex_to_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let bytes = s.as_bytes();
    for i in 0..N {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Lowercase-hex-encode bytes (trace/span ids in the OTLP-JSON payload).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 16 random bytes (a fresh trace id), sourced from a v4 UUID.
fn rand16() -> [u8; 16] {
    uuid::Uuid::new_v4().into_bytes()
}
/// 8 random bytes (a fresh span id), the first half of a v4 UUID.
fn rand8() -> [u8; 8] {
    uuid::Uuid::new_v4().into_bytes()[..8]
        .try_into()
        .expect("8 bytes")
}

#[cfg(test)]
mod tests {

    fn srv(status: u16) -> ServerSpan {
        ServerSpan {
            ctx: TraceContext {
                trace_id: [1u8; 16],
                span_id: [2u8; 8],
                parent_span_id: None,
            },
            method: "GET".into(),
            method_original: None,
            url_path: "/api/thing".into(),
            url_query: Some("page=2".into()),
            url_scheme: "https".into(),
            status_code: status,
            client_address: Some("203.0.113.7".into()),
            server_address: Some("app.example.com".into()),
            user_agent: Some("curl/8".into()),
            protocol_version: Some("1.1".into()),
            outcome: "proxied".into(),
            request_id: "rid-1".into(),
            start_unix_nano: 1_000,
            end_unix_nano: 3_000,
        }
    }

    fn attrs_of(v: &Value) -> std::collections::HashMap<String, Value> {
        v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (a["key"].as_str().unwrap().to_string(), a["value"].clone()))
            .collect()
    }

    #[test]
    fn server_span_uses_the_current_stable_semconv_names() {
        // The conventions RENAMED nearly all of these (http.method -> http.request.method,
        // http.url -> url.*). An old-name span is not merely oddly labelled: every backend
        // normalizes on the stable names, so it drops out of latency and error panels entirely.
        let v = build_server_spans_json(&[srv(200)], "edgeguard");
        let a = attrs_of(&v);
        assert_eq!(a["http.request.method"]["stringValue"], "GET");
        assert_eq!(a["url.path"]["stringValue"], "/api/thing");
        assert_eq!(a["url.scheme"]["stringValue"], "https");
        assert_eq!(a["url.query"]["stringValue"], "page=2");
        // Conditionally required and the single most-used attribute in any HTTP dashboard. It was
        // missing from the first draft of this design.
        assert_eq!(a["http.response.status_code"]["intValue"], "200");
        assert_eq!(a["client.address"]["stringValue"], "203.0.113.7");
        assert_eq!(a["user_agent.original"]["stringValue"], "curl/8");
        assert_eq!(a["network.protocol.version"]["stringValue"], "1.1");
        // The old names must not appear at all.
        for dead in ["http.method", "http.url", "http.status_code", "http.target"] {
            assert!(
                !a.contains_key(dead),
                "obsolete semconv attribute {dead} emitted"
            );
        }
    }

    #[test]
    fn a_server_span_is_kind_server_and_named_for_the_method() {
        // A proxy has no route template, and the spec says the span name is `{method}` alone when
        // `http.route` is unavailable. Putting the PATH in the name is the common mistake and it
        // makes span-name cardinality unbounded.
        let v = build_server_spans_json(&[srv(200)], "edgeguard");
        let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["kind"], 2, "SERVER");
        assert_eq!(span["name"], "GET");
    }

    #[test]
    fn only_5xx_sets_span_status_to_error() {
        // The spec is explicit and counter-intuitive: for a SERVER span a 4xx MUST be left unset,
        // because the server handled a bad request correctly. Marking 4xx as Error makes every
        // error-rate panel read a 404 storm as an outage.
        for ok in [200u16, 301, 404, 429, 499] {
            let v = build_server_spans_json(&[srv(ok)], "edgeguard");
            let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
            assert!(span.get("status").is_none(), "{ok} must leave status unset");
            assert!(
                !attrs_of(&v).contains_key("error.type"),
                "{ok} is not an error"
            );
        }
        for bad in [500u16, 502, 503] {
            let v = build_server_spans_json(&[srv(bad)], "edgeguard");
            let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
            assert_eq!(span["status"]["code"], 2, "{bad} must be Error");
            assert_eq!(attrs_of(&v)["error.type"]["stringValue"], bad.to_string());
        }
    }

    #[test]
    fn an_unknown_method_is_bucketed_rather_than_labelled() {
        // Otherwise a caller invents methods and creates unbounded span-name cardinality.
        let (m, orig) = ServerSpan::normalize_method("FROBNICATE");
        assert_eq!(m, "_OTHER");
        assert_eq!(orig.as_deref(), Some("FROBNICATE"));
        let (m, orig) = ServerSpan::normalize_method("PATCH");
        assert_eq!(m, "PATCH");
        assert!(orig.is_none());
    }

    #[test]
    fn one_batch_is_one_payload_with_many_spans() {
        // A proxy emits a span per request; one POST each would make the trace backend the busiest
        // thing the edge talks to.
        let v = build_server_spans_json(&[srv(200), srv(500), srv(404)], "edgeguard");
        let spans = v["resourceSpans"][0]["scopeSpans"][0]["spans"]
            .as_array()
            .unwrap();
        assert_eq!(spans.len(), 3);
        assert_eq!(
            v["resourceSpans"][0]["resource"]["attributes"][0]["value"]["stringValue"],
            "edgeguard"
        );
    }

    #[test]
    fn sampling_is_deterministic_per_trace_and_respects_the_bounds() {
        let a = [7u8; 16];
        let b = [9u8; 16];
        assert!(trace_sampled(1.0, &a) && trace_sampled(1.0, &b));
        assert!(!trace_sampled(0.0, &a) && !trace_sampled(0.0, &b));
        // Same trace, same verdict, every time — this is what stops a half-recorded trace.
        for _ in 0..100 {
            assert_eq!(trace_sampled(0.5, &a), trace_sampled(0.5, &a));
        }
    }

    #[test]
    fn the_outbound_traceparent_names_our_span_and_says_sampled() {
        // The upstream must become a CHILD of the edge's span, and must be told the trace is
        // sampled — otherwise its own sampler drops the other half of the trace.
        let ctx = TraceContext {
            trace_id: [0xab; 16],
            span_id: [0xcd; 8],
            parent_span_id: None,
        };
        let h = traceparent_header(&ctx);
        assert_eq!(h, format!("00-{}-{}-01", "ab".repeat(16), "cd".repeat(8)));
        // And it round-trips: a downstream parsing it sees our trace and our span as its parent.
        let back = TraceContext::from_traceparent(Some(&h));
        assert_eq!(back.trace_id, ctx.trace_id);
        assert_eq!(back.parent_span_id, Some(ctx.span_id));
    }

    #[test]
    fn an_inbound_traceparent_makes_the_server_span_a_child() {
        let inbound = format!("00-{}-{}-01", "11".repeat(16), "22".repeat(8));
        let ctx = TraceContext::from_traceparent(Some(&inbound));
        let mut s = srv(200);
        s.ctx = ctx;
        let v = build_server_spans_json(&[s], "edgeguard");
        let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["traceId"], "11".repeat(16));
        assert_eq!(span["parentSpanId"], "22".repeat(8));
    }
    use super::*;

    fn record() -> SpanRecord {
        SpanRecord {
            ctx: TraceContext {
                trace_id: [0x11; 16],
                span_id: [0x22; 8],
                parent_span_id: None,
            },
            name: "llm.chat".into(),
            model: "gpt-4o".into(),
            provider: Some("openai".into()),
            prompt_tokens: 100,
            completion_tokens: 40,
            cached_tokens: 30,
            reasoning_tokens: 10,
            cost_micros: Some(2_250_000),
            start_unix_nano: 1_000,
            end_unix_nano: 4_000,
            ttft: Some(Duration::from_millis(120)),
            tpot: Some(Duration::from_millis(25)),
            status_ok: true,
            input: None,
            output: None,
            session_id: Some("sess-1".into()),
        }
    }

    /// The emitted attributes must use the exact OpenInference keys evald's normalizer reads.
    #[test]
    fn build_export_json_uses_openinference_keys() {
        let v = build_export_json(&record(), "checkout");
        let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["traceId"], "11".repeat(16));
        assert_eq!(span["spanId"], "22".repeat(8));
        assert!(span.get("parentSpanId").is_none());
        assert_eq!(span["startTimeUnixNano"], "1000");
        assert_eq!(span["status"]["code"], 1);

        let attrs = span["attributes"].as_array().unwrap();
        let get = |key: &str| attrs.iter().find(|a| a["key"] == key).map(|a| &a["value"]);
        assert_eq!(
            get("openinference.span.kind").unwrap()["stringValue"],
            "LLM"
        );
        assert_eq!(get("llm.model_name").unwrap()["stringValue"], "gpt-4o");
        assert_eq!(get("llm.provider").unwrap()["stringValue"], "openai");
        // OTLP-JSON int64 → string.
        assert_eq!(get("llm.token_count.prompt").unwrap()["intValue"], "100");
        assert_eq!(get("llm.token_count.completion").unwrap()["intValue"], "40");
        assert_eq!(get("llm.token_count.total").unwrap()["intValue"], "140");
        assert_eq!(
            get("llm.token_count.prompt_details.cache_read").unwrap()["intValue"],
            "30"
        );
        assert_eq!(
            get("llm.token_count.completion_details.reasoning").unwrap()["intValue"],
            "10"
        );
        assert_eq!(get("llm.cost.total").unwrap()["doubleValue"], 2.25);
        assert_eq!(get("session.id").unwrap()["stringValue"], "sess-1");
        assert_eq!(
            v["resourceSpans"][0]["resource"]["attributes"][0]["value"]["stringValue"],
            "checkout"
        );
    }

    #[test]
    fn zero_cache_and_reasoning_are_omitted() {
        let mut r = record();
        r.cached_tokens = 0;
        r.reasoning_tokens = 0;
        let v = build_export_json(&r, "svc");
        let attrs = v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
            .as_array()
            .unwrap()
            .clone();
        assert!(!attrs
            .iter()
            .any(|a| a["key"] == "llm.token_count.prompt_details.cache_read"));
        assert!(!attrs
            .iter()
            .any(|a| a["key"] == "llm.token_count.completion_details.reasoning"));
    }

    #[test]
    fn content_is_attached_only_when_present() {
        let mut r = record();
        r.input = Some("hello?".into());
        r.output = Some("hi!".into());
        let v = build_export_json(&r, "svc");
        let attrs = v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
            .as_array()
            .unwrap()
            .clone();
        let val = |k: &str| {
            attrs
                .iter()
                .find(|a| a["key"] == k)
                .map(|a| a["value"]["stringValue"].clone())
        };
        assert_eq!(val("input.value").unwrap(), "hello?");
        assert_eq!(val("output.value").unwrap(), "hi!");
    }

    #[test]
    fn error_status_maps_to_code_2() {
        let mut r = record();
        r.status_ok = false;
        let v = build_export_json(&r, "svc");
        assert_eq!(
            v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["status"]["code"],
            2
        );
    }

    #[test]
    fn traceparent_is_parsed_and_stitched_as_parent() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::from_traceparent(Some(tp));
        assert_eq!(hex(&ctx.trace_id), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(
            ctx.parent_span_id.map(|p| hex(&p)).as_deref(),
            Some("00f067aa0ba902b7")
        );
        // A fresh 8-byte span id was minted (not the parent's).
        assert_ne!(hex(&ctx.span_id), "00f067aa0ba902b7");
    }

    #[test]
    fn missing_or_malformed_traceparent_starts_a_fresh_root_trace() {
        for bad in [None, Some(""), Some("garbage"), Some("00-tooshort-x-01")] {
            let ctx = TraceContext::from_traceparent(bad);
            assert!(
                ctx.parent_span_id.is_none(),
                "bad traceparent {bad:?} must be a root"
            );
            assert_ne!(ctx.trace_id, [0u8; 16]);
        }
        // An all-zero trace id in an otherwise well-formed header is invalid → fresh trace.
        let zero = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        assert!(TraceContext::from_traceparent(Some(zero))
            .parent_span_id
            .is_none());
    }

    #[test]
    fn sampling_is_deterministic_and_bounded() {
        let all = TelemetryRuntime::build(&TelemetryCfg {
            enabled: true,
            endpoint: "http://x/v1/traces".into(),
            sample_rate: 1.0,
            ..TelemetryCfg::default()
        });
        assert!(all.sampled(&[0xff; 16]));
        let none = TelemetryRuntime::build(&TelemetryCfg {
            enabled: true,
            endpoint: "http://x/v1/traces".into(),
            sample_rate: 0.0,
            ..TelemetryCfg::default()
        });
        assert!(!none.sampled(&[0xff; 16]));
        // Same trace id → same verdict, whatever the rate.
        let half = TelemetryRuntime::build(&TelemetryCfg {
            enabled: true,
            endpoint: "http://x/v1/traces".into(),
            sample_rate: 0.5,
            ..TelemetryCfg::default()
        });
        let id = [0x40u8; 16];
        assert_eq!(half.sampled(&id), half.sampled(&id));
    }

    #[test]
    fn sampling_is_unbiased_for_real_uuidv4_trace_ids() {
        // Regression: `sampled()` used to draw only from trace_id[8..16], but byte 8 of a
        // UUIDv4 always has its top two bits fixed to `10` (the RFC 4122 variant), which
        // capped that byte's range to [0x80, 0xbf] and skewed the draw to only ever cover
        // roughly the [0.5, 0.75) slice of the [0,1) range — so at sample_rate=0.5, real
        // trace ids would ~always sample, not ~half the time.
        let half = TelemetryRuntime::build(&TelemetryCfg {
            enabled: true,
            endpoint: "http://x/v1/traces".into(),
            sample_rate: 0.5,
            ..TelemetryCfg::default()
        });
        let sampled_count = (0..2000)
            .filter(|_| half.sampled(uuid::Uuid::new_v4().as_bytes()))
            .count();
        // Statistical, not exact — allow generous slack around the expected ~1000/2000.
        assert!(
            (700..=1300).contains(&sampled_count),
            "expected roughly half of 2000 real UUIDv4 trace ids to sample at rate 0.5, got {sampled_count}"
        );
    }

    #[test]
    fn disabled_without_endpoint_even_if_enabled_flag_set() {
        let rt = TelemetryRuntime::build(&TelemetryCfg {
            enabled: true,
            endpoint: "   ".into(), // whitespace-only → treated as unset
            ..TelemetryCfg::default()
        });
        assert!(!rt.enabled);
    }

    #[test]
    fn prepare_content_truncates_on_a_char_boundary() {
        let s = prepare_content("abcdef".as_bytes(), 3);
        assert!(s.starts_with("abc"));
        assert!(s.contains("truncated"));
        assert_eq!(prepare_content("hi".as_bytes(), 8), "hi");
    }
}

// ─── span shipping ────────────────────────────────────────────────────────────────────────────

/// Bounded queue + background task that batches server spans into OTLP-JSON POSTs.
///
/// Same discipline as [`crate::logship`], for the same reason: this is fed from the response path of
/// every request. `record` is one non-blocking `try_send` and returns; a slow or absent collector
/// costs dropped spans, never request latency. Traces are telemetry, so the loss is bounded and
/// counted rather than buffered without limit — an unbounded buffer on a proxy turns a collector
/// outage into a proxy outage.
#[derive(Clone)]
pub struct SpanShipper {
    tx: tokio::sync::mpsc::Sender<ServerSpan>,
    stats: std::sync::Arc<SpanShipStats>,
}

/// Counters for the span shipper. A trace pipeline that drops silently reads, at the destination,
/// as an absence of traffic.
#[derive(Debug, Default)]
pub struct SpanShipStats {
    pub sent: std::sync::atomic::AtomicU64,
    pub dropped_queue_full: std::sync::atomic::AtomicU64,
    pub dropped_send_failed: std::sync::atomic::AtomicU64,
}

impl SpanShipper {
    pub fn stats(&self) -> &std::sync::Arc<SpanShipStats> {
        &self.stats
    }

    /// Hand a span to the shipper. Never blocks, never awaits, never fails the caller.
    pub fn record(&self, span: ServerSpan) {
        if self.tx.try_send(span).is_err() {
            self.stats
                .dropped_queue_full
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Build the shipper and spawn its background task. `None` when tracing is off or unconfigured.
pub fn spawn_span_shipper(
    cfg: &crate::config::TracingCfg,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<SpanShipper> {
    if !cfg.enabled || cfg.endpoint.trim().is_empty() {
        return None;
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms.max(100)))
        .build()
        .ok()?;
    let stats = std::sync::Arc::new(SpanShipStats::default());
    let (tx, rx) = tokio::sync::mpsc::channel(cfg.queue_size.max(1));
    let task = SpanShipTask {
        http,
        endpoint: cfg.endpoint.clone(),
        service_name: cfg.service_name.clone(),
        batch: cfg.batch.max(1),
        interval: std::time::Duration::from_secs(cfg.interval_secs.max(1)),
        stats: std::sync::Arc::clone(&stats),
    };
    tracing::info!(endpoint = %cfg.endpoint, batch = task.batch, "request tracing enabled");
    tokio::spawn(task.run(rx, shutdown));
    Some(SpanShipper { tx, stats })
}

struct SpanShipTask {
    http: reqwest::Client,
    endpoint: String,
    service_name: String,
    batch: usize,
    interval: std::time::Duration,
    stats: std::sync::Arc<SpanShipStats>,
}

impl SpanShipTask {
    async fn run(
        self,
        mut rx: tokio::sync::mpsc::Receiver<ServerSpan>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut buf: Vec<ServerSpan> = Vec::with_capacity(self.batch);
        let mut tick = tokio::time::interval(self.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `interval`'s first tick completes immediately; consume it so the configured interval means
        // what it says and the first batch of a process is not a batch of one.
        tick.tick().await;

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => { if *shutdown.borrow() { break } }
                got = rx.recv() => match got {
                    Some(s) => {
                        buf.push(s);
                        if buf.len() >= self.batch {
                            self.flush(&mut buf).await;
                        }
                    }
                    None => break,
                },
                _ = tick.tick() => {
                    if !buf.is_empty() {
                        self.flush(&mut buf).await;
                    }
                }
            }
        }
        // Drain on the way out: the spans around a restart are the ones most likely to explain it.
        while let Ok(s) = rx.try_recv() {
            buf.push(s);
            if buf.len() >= self.batch {
                self.flush(&mut buf).await;
            }
        }
        if !buf.is_empty() {
            self.flush(&mut buf).await;
        }
    }

    async fn flush(&self, buf: &mut Vec<ServerSpan>) {
        let n = buf.len() as u64;
        let body = build_server_spans_json(buf, &self.service_name);
        buf.clear();
        match self.http.post(&self.endpoint).json(&body).send().await {
            Ok(r) if r.status().is_success() => {
                self.stats
                    .sent
                    .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            }
            // No retry, unlike the log shipper's single retry. Spans are the most disposable
            // telemetry here and the highest volume; a retry queue behind a failing collector just
            // converts collector downtime into request-path drops sooner.
            Ok(r) => {
                tracing::debug!(status = %r.status(), spans = n, "trace collector rejected a batch");
                self.stats
                    .dropped_send_failed
                    .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                tracing::debug!(error = %e, spans = n, "shipping a span batch failed");
                self.stats
                    .dropped_send_failed
                    .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}
