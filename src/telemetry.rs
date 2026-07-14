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
