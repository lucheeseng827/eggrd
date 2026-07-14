//! LLM token metering (gateway L0).
//!
//! When `[llm]` is enabled, EdgeGuard parses OpenAI-compatible traffic to **meter tokens and
//! cost** — the substrate every later level (budgets, governance, cost accounting) builds on. L0 is
//! *metering only*: it never blocks, rewrites, or delays a request. Token counts come from the
//! upstream's own `usage` object (authoritative), so the proxy does not tokenize anything itself.
//!
//! Two response shapes are handled:
//!   * **non-streaming** — a JSON body carrying `usage.{prompt,completion}_tokens` ([`parse_response_usage`]);
//!   * **streaming (SSE)** — the terminal `data:` frame carries `usage` when the client sets
//!     `stream_options.include_usage` ([`parse_sse_usage`]); without it, no usage is emitted and the
//!     request is metered as `no_usage`.
//!
//! Pricing is a per-model book ([`LlmRuntime`]). What happens to a request for an **unmapped** model
//! is a config choice ([`UnpricedPolicy`]): `count` keeps the historical fail-open behaviour (tokens
//! counted, cost omitted — surfaced as the `unpriced` result), while `block` fails *closed* (`402`,
//! the request never reaches the upstream) so a mispriced/unknown model can't be served at a silent
//! `$0` — the LiteLLM `#24770` failure, designed out. Cost is accumulated in **micro-dollars**
//! (1e-6 USD) as an integer to avoid float drift in a monotonic counter.
//!
//! Token accounting captures four dimensions, not two: `prompt` and `completion`, plus the
//! **`cached`** prompt tokens (`prompt_tokens_details.cached_tokens`) and the **`reasoning`**
//! completion tokens (`completion_tokens_details.reasoning_tokens`) that OpenAI-compatible providers
//! bill differently. Pricing them separately is what fixes the "~7× undercount" on reasoning/cached
//! traffic; when a model leaves the cached/reasoning rate unset they inherit the input/output rate,
//! so a book that predates those knobs prices exactly as before.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};

use crate::config::LlmCfg;

/// Token usage as reported by the upstream's `usage` object. `cached_tokens` is the subset of
/// `prompt_tokens` served from the provider's prompt cache; `reasoning_tokens` is the subset of
/// `completion_tokens` spent on hidden reasoning. Both are carried separately so they can be priced
/// (and metered) at their own rate rather than folded into the base input/output totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// Cached prompt tokens (⊆ `prompt_tokens`), from `prompt_tokens_details.cached_tokens`.
    pub cached_tokens: u64,
    /// Reasoning completion tokens (⊆ `completion_tokens`), from
    /// `completion_tokens_details.reasoning_tokens`.
    pub reasoning_tokens: u64,
}

/// The raw `usage` wire shape, including the nested detail objects OpenAI added for cached/reasoning
/// accounting. Flattened into [`Usage`] on deserialize so the rest of the crate sees four flat dims.
#[derive(Deserialize)]
struct UsageWire {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    prompt_tokens_details: Option<PromptTokensDetails>,
    #[serde(default)]
    completion_tokens_details: Option<CompletionTokensDetails>,
}

#[derive(Deserialize)]
struct PromptTokensDetails {
    #[serde(default)]
    cached_tokens: u64,
}

#[derive(Deserialize)]
struct CompletionTokensDetails {
    #[serde(default)]
    reasoning_tokens: u64,
}

impl<'de> Deserialize<'de> for Usage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let w = UsageWire::deserialize(deserializer)?;
        // Clamp the sub-dimensions to their parent so a malformed upstream (cached > prompt) can't
        // make the priced "uncached" remainder underflow later.
        let cached = w
            .prompt_tokens_details
            .map(|d| d.cached_tokens)
            .unwrap_or(0)
            .min(w.prompt_tokens);
        let reasoning = w
            .completion_tokens_details
            .map(|d| d.reasoning_tokens)
            .unwrap_or(0)
            .min(w.completion_tokens);
        Ok(Usage {
            prompt_tokens: w.prompt_tokens,
            completion_tokens: w.completion_tokens,
            cached_tokens: cached,
            reasoning_tokens: reasoning,
        })
    }
}

impl Usage {
    fn is_empty(&self) -> bool {
        self.prompt_tokens == 0 && self.completion_tokens == 0
    }

    /// Total tokens across prompt + completion (the budget's `Tokens` unit basis).
    pub fn total_tokens(&self) -> u64 {
        self.prompt_tokens.saturating_add(self.completion_tokens)
    }
}

/// What to do with a request whose model is **not** in the price book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnpricedPolicy {
    /// Meter tokens, omit cost (`unpriced` result), forward the request — the historical default.
    Count,
    /// Reject the request `402` before it reaches the upstream, so an unpriced model is never served
    /// at a silent `$0` (the LiteLLM `#24770` failure). Only bites when a price book is configured.
    Block,
}

impl UnpricedPolicy {
    pub fn parse(s: &str) -> anyhow::Result<UnpricedPolicy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "count" | "" => Ok(UnpricedPolicy::Count),
            "block" | "reject" | "deny" => Ok(UnpricedPolicy::Block),
            other => {
                anyhow::bail!("invalid llm.on_unpriced_model {other:?} (expected count|block)")
            }
        }
    }
}

/// Per-model price, in **micro-dollars per 1,000,000 tokens** (compiled from the config's USD
/// floats once at load, so the hot path does integer math only). `cached`/`reasoning` default to the
/// base input/output rate when the config leaves them unset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModelRate {
    input_micros_per_m: u64,
    output_micros_per_m: u64,
    cached_micros_per_m: u64,
    reasoning_micros_per_m: u64,
}

/// The compiled LLM runtime: whether metering is on, the API style, and the price book. Built once
/// per config (re)load and carried on the proxy [`Runtime`](crate::proxy::Runtime).
#[derive(Clone, Debug)]
pub struct LlmRuntime {
    pub enabled: bool,
    /// Request/response wire format. Only `"openai"` is understood today; anything else still
    /// meters (the OpenAI shape is a superset of most), but is recorded for forward-compat.
    pub api_style: String,
    /// What to do with a request for a model absent from the price book (`count` / `block`).
    pub unpriced: UnpricedPolicy,
    prices: BTreeMap<String, ModelRate>,
}

impl LlmRuntime {
    /// Compile an [`LlmRuntime`] from config. USD-per-million floats become integer micro-dollars
    /// per million; a negative price is clamped to 0 (free) rather than rejected, so a typo never
    /// stops the proxy booting. An invalid `on_unpriced_model` falls back to `count` (never a hard
    /// boot failure) — the value is re-validated at config load where a typo is surfaced.
    pub fn build(cfg: &LlmCfg) -> Self {
        let prices = cfg
            .models
            .iter()
            .map(|(name, p)| {
                let input = usd_per_m_to_micros(p.input_per_1m);
                let output = usd_per_m_to_micros(p.output_per_1m);
                let rate = ModelRate {
                    input_micros_per_m: input,
                    output_micros_per_m: output,
                    // Cached/reasoning inherit the base input/output rate unless the book sets an
                    // explicit (positive) rate — so an existing book prices unchanged.
                    cached_micros_per_m: if p.cached_per_1m > 0.0 {
                        usd_per_m_to_micros(p.cached_per_1m)
                    } else {
                        input
                    },
                    reasoning_micros_per_m: if p.reasoning_per_1m > 0.0 {
                        usd_per_m_to_micros(p.reasoning_per_1m)
                    } else {
                        output
                    },
                };
                (name.clone(), rate)
            })
            .collect();
        LlmRuntime {
            enabled: cfg.enabled,
            api_style: if cfg.api_style.trim().is_empty() {
                "openai".to_string()
            } else {
                cfg.api_style.trim().to_ascii_lowercase()
            },
            unpriced: UnpricedPolicy::parse(&cfg.on_unpriced_model)
                .unwrap_or(UnpricedPolicy::Count),
            prices,
        }
    }

    /// An inert runtime (metering off) — the default carried when `[llm]` is absent.
    pub fn disabled() -> Self {
        LlmRuntime {
            enabled: false,
            api_style: "openai".to_string(),
            unpriced: UnpricedPolicy::Count,
            prices: BTreeMap::new(),
        }
    }

    /// Whether a price book is configured at all. `block` on an unpriced model only bites when true —
    /// a metering-only deployment (no `[llm.models]`) must not reject every request.
    pub fn has_price_book(&self) -> bool {
        !self.prices.is_empty()
    }

    /// Resolve the price for `model`: an exact book entry wins; otherwise a provider-prefixed alias
    /// (LiteLLM/OpenTelemetry-style `"openai/gpt-4o"`) falls back to the bare model name. Exact
    /// entries always take precedence, so a book that prices the prefixed name explicitly is never
    /// overridden — this only rescues a prefixed request that would otherwise read `$0`/`unpriced`
    /// (Opik #5621, Portkey #1564, LiteLLM #15329).
    fn resolve_rate(&self, model: &str) -> Option<&ModelRate> {
        if let Some(rate) = self.prices.get(model) {
            return Some(rate);
        }
        strip_provider_prefix(model).and_then(|bare| self.prices.get(bare))
    }

    /// Whether `model` carries a price (exact entry or a provider-prefixed alias of one).
    pub fn is_priced(&self, model: &str) -> bool {
        self.resolve_rate(model).is_some()
    }

    /// Whether this request must be rejected `402` for an unpriced model: policy is `block`, a price
    /// book exists, and `model` is not in it. A metering-only setup (empty book) never rejects.
    pub fn reject_unpriced(&self, model: &str) -> bool {
        self.unpriced == UnpricedPolicy::Block && self.has_price_book() && !self.is_priced(model)
    }

    /// Cost of `usage` for `model` in micro-dollars, or `None` if the model has no price (the caller
    /// still counts the tokens; whether to serve the request is governed by [`Self::reject_unpriced`]).
    /// Cached prompt tokens and reasoning completion tokens are billed at their own rate (each
    /// defaulting to the base input/output rate), and the remaining prompt/completion tokens at the
    /// base rate — so the four dimensions never double-count.
    pub fn cost_micros(&self, model: &str, usage: &Usage) -> Option<u64> {
        let rate = self.resolve_rate(model)?;
        let cached = usage.cached_tokens.min(usage.prompt_tokens);
        let uncached_input = usage.prompt_tokens - cached;
        let reasoning = usage.reasoning_tokens.min(usage.completion_tokens);
        let base_output = usage.completion_tokens - reasoning;
        let total = uncached_input as u128 * rate.input_micros_per_m as u128
            + cached as u128 * rate.cached_micros_per_m as u128
            + base_output as u128 * rate.output_micros_per_m as u128
            + reasoning as u128 * rate.reasoning_micros_per_m as u128;
        Some((total / 1_000_000).min(u64::MAX as u128) as u64)
    }
}

/// Provider prefixes used by LiteLLM/OpenTelemetry-style model ids (`"openai/gpt-4o"`). Stripping a
/// known prefix lets a price book keyed by the bare model name still price a prefixed request instead
/// of reading `$0` (Opik #5621, Portkey #1564). Deliberately a **curated** list — not "everything
/// before the first slash" — so HuggingFace/OpenRouter-style ids like `"meta-llama/Llama-3"` are left
/// intact and only unambiguous single-provider prefixes are stripped.
const PROVIDER_PREFIXES: &[&str] = &[
    "openai/",
    "anthropic/",
    "azure/",
    "azure_ai/",
    "vertex_ai/",
    "vertex/",
    "bedrock/",
    "gemini/",
    "google/",
    "mistral/",
    "codestral/",
    "cohere/",
    "groq/",
    "together_ai/",
    "together/",
    "fireworks_ai/",
    "fireworks/",
    "deepseek/",
    "xai/",
    "perplexity/",
    "replicate/",
    "anyscale/",
    "deepinfra/",
    "cloudflare/",
    "watsonx/",
    "sagemaker/",
    "ollama_chat/",
    "ollama/",
];

/// The canonical model name for **attribution** (budgets, per-model rollups): the bare name with a
/// known provider prefix stripped, else the name unchanged. So a per-model budget and its rollups
/// aggregate `"openai/gpt-4o"` and `"gpt-4o"` as one model instead of splitting spend across two
/// buckets (a prefixed request otherwise silently escaping a bare-named budget).
pub fn canonical_model(model: &str) -> &str {
    strip_provider_prefix(model).unwrap_or(model)
}

/// If `model` begins with a known [`PROVIDER_PREFIXES`] entry (case-insensitive), return the bare
/// model name after it; else `None`. Only the first prefix is stripped. Compares bytes so a
/// multi-byte model name can never panic on a non-char-boundary slice.
fn strip_provider_prefix(model: &str) -> Option<&str> {
    for p in PROVIDER_PREFIXES {
        if model.len() > p.len() && model.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes()) {
            // The matched prefix is ASCII, so `p.len()` is a valid UTF-8 boundary.
            return Some(&model[p.len()..]);
        }
    }
    None
}

/// USD-per-1M-tokens (float) → micro-dollars-per-1M-tokens (integer). `$0.50` → `500_000`.
fn usd_per_m_to_micros(usd: f64) -> u64 {
    if !usd.is_finite() || usd <= 0.0 {
        return 0;
    }
    (usd * 1_000_000.0).round() as u64
}

#[derive(Deserialize)]
struct ModelField {
    model: Option<String>,
}

/// Extract the `model` field from an OpenAI-style request body. `None` if the body isn't JSON or
/// has no `model` (then the request isn't metered as LLM traffic). Other fields are ignored, so a
/// large `messages` array is not materialized beyond what serde must scan.
pub fn parse_request_model(body: &[u8]) -> Option<String> {
    let parsed: ModelField = serde_json::from_slice(body).ok()?;
    let model = parsed.model?;
    (!model.trim().is_empty()).then_some(model)
}

#[derive(Deserialize)]
struct MaxTokensField {
    /// OpenAI's completion ceiling. The newer `max_completion_tokens` is accepted as a fallback.
    max_tokens: Option<u64>,
    max_completion_tokens: Option<u64>,
}

/// Extract the request's completion-token ceiling (`max_tokens`, or `max_completion_tokens`). Used
/// only to size the budget *reserve* estimate; the reservation is reconciled to actual usage after.
pub fn parse_request_max_tokens(body: &[u8]) -> Option<u64> {
    let parsed: MaxTokensField = serde_json::from_slice(body).ok()?;
    parsed.max_tokens.or(parsed.max_completion_tokens)
}

/// A rough prompt-token estimate from the raw request size (~4 bytes/token, the common English
/// heuristic). Deliberately an over-estimate — the JSON envelope inflates it — so the budget
/// *reserve* errs toward caution (a hard cap should never admit past the limit); the reservation is
/// reconciled down to the upstream's exact `usage` afterward.
pub fn estimate_prompt_tokens(body_len: usize) -> u64 {
    (body_len / 4) as u64
}

#[derive(Deserialize)]
struct UsageField {
    usage: Option<Usage>,
}

/// Extract `usage` from a non-streaming OpenAI-style response body. `None` if absent/zero (an error
/// response or a stream that didn't include usage).
pub fn parse_response_usage(body: &[u8]) -> Option<Usage> {
    let parsed: UsageField = serde_json::from_slice(body).ok()?;
    parsed.usage.filter(|u| !u.is_empty())
}

/// Extract the terminal `usage` from an SSE stream's bytes. OpenAI emits a final
/// `data: {…, "usage": {…}}` frame when the client sets `stream_options.include_usage`; earlier
/// frames carry `"usage": null`. Returns the **last** non-empty usage seen (the authoritative
/// totals), or `None` if the stream never reported usage.
pub fn parse_sse_usage(bytes: &[u8]) -> Option<Usage> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut last = None;
    for line in text.lines() {
        let line = line.trim_start();
        let Some(payload) = line.strip_prefix("data:") else {
            continue;
        };
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        if let Ok(parsed) = serde_json::from_str::<UsageField>(payload) {
            if let Some(u) = parsed.usage.filter(|u| !u.is_empty()) {
                last = Some(u);
            }
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ModelPrice;

    fn runtime() -> LlmRuntime {
        let mut models = BTreeMap::new();
        models.insert(
            "gpt-4o".to_string(),
            ModelPrice {
                input_per_1m: 2.50,
                output_per_1m: 10.00,
                ..Default::default()
            },
        );
        LlmRuntime::build(&LlmCfg {
            enabled: true,
            api_style: "openai".into(),
            models,
            ..Default::default()
        })
    }

    #[test]
    fn parses_request_model() {
        let body = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
        assert_eq!(parse_request_model(body), Some("gpt-4o".to_string()));
        assert_eq!(parse_request_model(b"not json"), None);
        assert_eq!(parse_request_model(br#"{"messages":[]}"#), None);
        assert_eq!(parse_request_model(br#"{"model":""}"#), None);
    }

    #[test]
    fn parses_non_streaming_usage() {
        let body = br#"{"id":"x","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":34,"total_tokens":46}}"#;
        assert_eq!(
            parse_response_usage(body),
            Some(Usage {
                prompt_tokens: 12,
                completion_tokens: 34,
                ..Default::default()
            })
        );
        // No usage / error body → None.
        assert_eq!(parse_response_usage(br#"{"error":"nope"}"#), None);
        // Zeroed usage is treated as absent.
        assert_eq!(
            parse_response_usage(br#"{"usage":{"prompt_tokens":0,"completion_tokens":0}}"#),
            None
        );
    }

    #[test]
    fn parses_terminal_sse_usage() {
        // Mid-stream frames carry usage:null; the final frame before [DONE] carries the totals.
        let stream = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n\
                      data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":5,\"total_tokens\":12}}\n\n\
                      data: [DONE]\n\n";
        assert_eq!(
            parse_sse_usage(stream.as_bytes()),
            Some(Usage {
                prompt_tokens: 7,
                completion_tokens: 5,
                ..Default::default()
            })
        );
        // A stream that never reported usage (client didn't opt in).
        let no_usage = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n";
        assert_eq!(parse_sse_usage(no_usage.as_bytes()), None);
    }

    #[test]
    fn prices_known_model_and_fails_open_on_unknown() {
        let rt = runtime();
        let usage = Usage {
            prompt_tokens: 1_000_000,
            completion_tokens: 1_000_000,
            ..Default::default()
        };
        // 1M input @ $2.50/M = $2.50 = 2_500_000 micro; 1M output @ $10/M = 10_000_000 micro.
        assert_eq!(rt.cost_micros("gpt-4o", &usage), Some(12_500_000));
        // Unknown model → None (caller still counts tokens; serving is governed by the policy).
        assert_eq!(rt.cost_micros("mystery-model", &usage), None);
    }

    #[test]
    fn cost_is_proportional_for_small_counts() {
        let rt = runtime();
        // 1000 input tokens @ $2.50/M = 1000 * 2_500_000 / 1_000_000 = 2500 micro-USD.
        let usage = Usage {
            prompt_tokens: 1_000,
            completion_tokens: 0,
            ..Default::default()
        };
        assert_eq!(rt.cost_micros("gpt-4o", &usage), Some(2_500));
    }

    #[test]
    fn parses_llm_toml_models_map() {
        // Locks the `[llm.models."name"]` table-map shape used in the example config, so the docs
        // and the serde mapping can't drift apart.
        let toml = r#"
[llm]
enabled = true
api_style = "openai"

[llm.models."gpt-4o"]
input_per_1m = 2.5
output_per_1m = 10.0
"#;
        let cfg: crate::config::Config = toml::from_str(toml).unwrap();
        assert!(cfg.llm.enabled);
        assert_eq!(cfg.llm.models.len(), 1);
        let rt = LlmRuntime::build(&cfg.llm);
        let usage = Usage {
            prompt_tokens: 1_000_000,
            completion_tokens: 0,
            ..Default::default()
        };
        assert_eq!(rt.cost_micros("gpt-4o", &usage), Some(2_500_000));
    }

    #[test]
    fn negative_or_zero_price_is_free_not_an_error() {
        assert_eq!(usd_per_m_to_micros(-1.0), 0);
        assert_eq!(usd_per_m_to_micros(0.0), 0);
        assert_eq!(usd_per_m_to_micros(0.5), 500_000);
    }

    #[test]
    fn parses_cached_and_reasoning_detail_dims() {
        // OpenAI nests the sub-dimensions under *_tokens_details; they flatten onto Usage.
        let body = br#"{"usage":{"prompt_tokens":100,"completion_tokens":80,
            "prompt_tokens_details":{"cached_tokens":40},
            "completion_tokens_details":{"reasoning_tokens":30}}}"#;
        assert_eq!(
            parse_response_usage(body),
            Some(Usage {
                prompt_tokens: 100,
                completion_tokens: 80,
                cached_tokens: 40,
                reasoning_tokens: 30,
            })
        );
        // A malformed upstream (cached > prompt) is clamped to the parent, not left to underflow.
        let bad = br#"{"usage":{"prompt_tokens":10,"completion_tokens":5,
            "prompt_tokens_details":{"cached_tokens":9999}}}"#;
        assert_eq!(parse_response_usage(bad).unwrap().cached_tokens, 10);
    }

    #[test]
    fn cached_reasoning_default_to_base_rate_so_totals_are_unchanged() {
        // With no explicit cached/reasoning rate, splitting the totals into sub-dims must not change
        // the price: a purely-cached prompt costs the same as a plain prompt of the same size.
        let rt = runtime();
        let plain = Usage {
            prompt_tokens: 1_000_000,
            completion_tokens: 1_000_000,
            ..Default::default()
        };
        let with_dims = Usage {
            prompt_tokens: 1_000_000,
            completion_tokens: 1_000_000,
            cached_tokens: 500_000,
            reasoning_tokens: 400_000,
        };
        assert_eq!(
            rt.cost_micros("gpt-4o", &plain),
            rt.cost_micros("gpt-4o", &with_dims)
        );
    }

    #[test]
    fn explicit_cached_reasoning_rates_are_applied() {
        let mut models = BTreeMap::new();
        models.insert(
            "gpt-4o".to_string(),
            ModelPrice {
                input_per_1m: 2.50,
                output_per_1m: 10.00,
                cached_per_1m: 1.25,     // half the input rate
                reasoning_per_1m: 20.00, // double the output rate
            },
        );
        let rt = LlmRuntime::build(&LlmCfg {
            enabled: true,
            models,
            ..Default::default()
        });
        let usage = Usage {
            prompt_tokens: 1_000_000,     // 600k uncached @2.50 + 400k cached @1.25
            completion_tokens: 1_000_000, // 700k base @10 + 300k reasoning @20
            cached_tokens: 400_000,
            reasoning_tokens: 300_000,
        };
        // 600k*2.5 = 1_500_000 ; 400k*1.25 = 500_000 ; 700k*10 = 7_000_000 ; 300k*20 = 6_000_000
        assert_eq!(rt.cost_micros("gpt-4o", &usage), Some(15_000_000));
    }

    #[test]
    fn unpriced_policy_block_only_bites_with_a_price_book() {
        // Default: count (fail-open) — never rejects.
        let count = runtime();
        assert!(!count.reject_unpriced("mystery"));

        // block + price book: an unknown model is rejected, a priced one is not.
        let mut models = BTreeMap::new();
        models.insert(
            "gpt-4o".to_string(),
            ModelPrice {
                input_per_1m: 2.5,
                output_per_1m: 10.0,
                ..Default::default()
            },
        );
        let block = LlmRuntime::build(&LlmCfg {
            enabled: true,
            models,
            on_unpriced_model: "block".into(),
            ..Default::default()
        });
        assert!(block.reject_unpriced("mystery"));
        assert!(!block.reject_unpriced("gpt-4o"));

        // block with an EMPTY book (metering-only) must never reject — else it breaks all traffic.
        let block_no_book = LlmRuntime::build(&LlmCfg {
            enabled: true,
            on_unpriced_model: "block".into(),
            ..Default::default()
        });
        assert!(!block_no_book.reject_unpriced("anything"));
    }

    #[test]
    fn unpriced_policy_parse_rejects_typos() {
        assert_eq!(
            UnpricedPolicy::parse("count").unwrap(),
            UnpricedPolicy::Count
        );
        assert_eq!(
            UnpricedPolicy::parse("block").unwrap(),
            UnpricedPolicy::Block
        );
        assert_eq!(UnpricedPolicy::parse("").unwrap(), UnpricedPolicy::Count);
        assert!(UnpricedPolicy::parse("banana").is_err());
    }

    // --- correctness guards for the #1 cross-competitor cost bug (top-20 QW #2) ------------
    // These lock in behaviour that is correct by construction, so a future refactor can't
    // reintroduce the token/cost inflation seen across Langfuse, Weave, OpenLLMetry, Phoenix.

    #[test]
    fn sse_usage_is_the_last_frame_never_the_sum_of_cumulative_chunks() {
        // Some providers (notably Gemini) repeat CUMULATIVE usage on every streamed chunk.
        // An accumulator that SUMS per-chunk usage then reports "massively inflated token
        // counts" (W&B Weave #5880). eggrd takes the LAST authoritative frame, never a sum.
        let stream = "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":10}}\n\n\
                      data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":25}}\n\n\
                      data: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":60,\"total_tokens\":160}}\n\n\
                      data: [DONE]\n\n";
        let u = parse_sse_usage(stream.as_bytes()).expect("terminal usage");
        assert_eq!(
            u.prompt_tokens, 100,
            "prompt must be the last frame, not 300 (summed)"
        );
        assert_eq!(
            u.completion_tokens, 60,
            "completion must be the last frame, not 95 (summed)"
        );
    }

    #[test]
    fn cached_prompt_tokens_are_never_billed_at_the_output_rate() {
        // Phoenix's ~18-20x overstatement: cached (and reasoning) tokens get folded into
        // "completion = total - prompt" and billed at the (much higher) output rate. eggrd
        // prices each of the four token tiers at its own rate, subtracted from the base, so a
        // fully-cached prompt is billed at the cached rate — never the output rate.
        let mut models = BTreeMap::new();
        models.insert(
            "m".to_string(),
            ModelPrice {
                input_per_1m: 3.00,
                output_per_1m: 60.00, // 20x the input rate — must never touch cached tokens
                cached_per_1m: 0.30,  // cached is a tenth of the input rate
                ..Default::default()
            },
        );
        let rt = LlmRuntime::build(&LlmCfg {
            enabled: true,
            models,
            ..Default::default()
        });
        // 1M prompt tokens, entirely served from cache; no completion.
        let usage = Usage {
            prompt_tokens: 1_000_000,
            completion_tokens: 0,
            cached_tokens: 1_000_000,
            reasoning_tokens: 0,
        };
        // Correct: 1M * $0.30/M = 300_000 micro. The output-rate bug would bill 60_000_000.
        assert_eq!(rt.cost_micros("m", &usage), Some(300_000));
    }

    #[test]
    fn metering_reads_the_usage_object_not_the_request_body_size() {
        // Multimodal base64 in the *request* must not inflate metered tokens (OpenLLMetry
        // #3949 counted base64 image bytes as text tokens). eggrd meters from the upstream's
        // authoritative `usage`; the body-length heuristic is only the pre-flight reserve.
        let rt = runtime();
        let resp = br#"{"usage":{"prompt_tokens":50,"completion_tokens":10}}"#;
        let usage = parse_response_usage(resp).expect("usage");
        assert_eq!(usage.prompt_tokens, 50);
        // A ~1 MB base64 image would estimate hundreds of thousands of tokens for the RESERVE…
        let huge_b64_body_len = 4_000_000usize;
        assert!(estimate_prompt_tokens(huge_b64_body_len) > usage.prompt_tokens);
        // …but the BILLED cost is the authoritative 50 in / 10 out: 125 + 100 = 225 micro.
        assert_eq!(rt.cost_micros("gpt-4o", &usage), Some(225));
    }

    // --- provider/model-alias price normalization (top-20 #15) ---------------------------

    #[test]
    fn provider_prefixed_model_resolves_to_the_bare_price() {
        // The #1 cross-competitor cost bug: "openai/gpt-4o" misses a book keyed by "gpt-4o" and
        // reads $0 (Opik #5621, Portkey #1564). We resolve the bare name as a fallback.
        let rt = runtime(); // book has "gpt-4o"
        let usage = Usage {
            prompt_tokens: 1_000,
            completion_tokens: 0,
            ..Default::default()
        };
        assert!(rt.is_priced("openai/gpt-4o"));
        assert_eq!(
            rt.cost_micros("openai/gpt-4o", &usage),
            rt.cost_micros("gpt-4o", &usage)
        );
        // Case-insensitive on the prefix.
        assert!(rt.is_priced("OpenAI/gpt-4o"));
    }

    #[test]
    fn exact_prefixed_entry_wins_over_normalization() {
        // If the book prices the prefixed id explicitly, that exact entry must win — normalization
        // is only a fallback, never an override.
        let mut models = BTreeMap::new();
        models.insert(
            "gpt-4o".to_string(),
            ModelPrice {
                input_per_1m: 2.50,
                output_per_1m: 10.00,
                ..Default::default()
            },
        );
        models.insert(
            "openai/gpt-4o".to_string(),
            ModelPrice {
                input_per_1m: 99.0, // deliberately different so we can tell which entry priced it
                output_per_1m: 99.0,
                ..Default::default()
            },
        );
        let rt = LlmRuntime::build(&LlmCfg {
            enabled: true,
            models,
            ..Default::default()
        });
        let usage = Usage {
            prompt_tokens: 1_000_000,
            completion_tokens: 0,
            ..Default::default()
        };
        assert_eq!(rt.cost_micros("openai/gpt-4o", &usage), Some(99_000_000));
        assert_eq!(rt.cost_micros("gpt-4o", &usage), Some(2_500_000));
    }

    #[test]
    fn unknown_or_huggingface_style_prefix_is_left_unpriced() {
        // A curated prefix list: an org/model id that isn't a known provider prefix (HuggingFace,
        // OpenRouter) must NOT be stripped, so it stays unpriced rather than mis-resolving.
        let rt = runtime();
        assert!(!rt.is_priced("meta-llama/Llama-3-8b"));
        assert_eq!(
            rt.cost_micros("meta-llama/Llama-3-8b", &Usage::default()),
            None
        );
        // A known prefix over an unknown bare name is still unpriced (nothing to resolve to).
        assert!(!rt.is_priced("openai/mystery-model"));
    }

    #[test]
    fn canonical_model_strips_known_prefixes_for_attribution() {
        // Budget/rollup attribution: a prefixed request maps to the bare model so it can't escape a
        // bare-named per-model budget (top-20 #19).
        assert_eq!(canonical_model("openai/gpt-4o"), "gpt-4o");
        assert_eq!(canonical_model("azure/gpt-4o"), "gpt-4o");
        assert_eq!(canonical_model("gpt-4o"), "gpt-4o"); // already bare
                                                         // An unknown / HuggingFace-style prefix is left intact (not a known provider).
        assert_eq!(canonical_model("meta-llama/Llama-3"), "meta-llama/Llama-3");
    }

    #[test]
    fn block_policy_does_not_reject_a_prefixed_priced_model() {
        // block + price book: a prefixed alias of a priced model must be served, not 402'd — the
        // whole point is that "openai/gpt-4o" IS priced under "gpt-4o".
        let mut models = BTreeMap::new();
        models.insert(
            "gpt-4o".to_string(),
            ModelPrice {
                input_per_1m: 2.5,
                output_per_1m: 10.0,
                ..Default::default()
            },
        );
        let rt = LlmRuntime::build(&LlmCfg {
            enabled: true,
            models,
            on_unpriced_model: "block".into(),
            ..Default::default()
        });
        assert!(!rt.reject_unpriced("openai/gpt-4o"));
        // A truly-unknown model (prefixed or not) is still rejected.
        assert!(rt.reject_unpriced("openai/mystery-model"));
        assert!(rt.reject_unpriced("mystery-model"));
    }
}
