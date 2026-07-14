//! `edgeguard-ner` — the optional ONNX NER layer for EdgeGuard's edge DLP (gateway L3).
//!
//! This crate is the "slow ML half" of the PII detector: the part regex can't do — `person`,
//! `address`, and `org` entities — run by a small **token-classification (BIO) ONNX model**
//! (DeBERTa / BERT-NER class; a GLiNER export can be swapped in) through the **pure-Rust
//! [`tract`](https://github.com/sonos/tract) runtime**. There is deliberately **no `ort`/
//! `libonnxruntime`** dependency: that crate links a C++ shared object and would break EdgeGuard's
//! distroless / static-musl single-binary image. `tract` is pure Rust and links nothing.
//!
//! ## Why a separate crate behind a feature
//!
//! The whole ONNX/tokenizer dependency graph is **optional** and only compiled with the crate's
//! `onnx` feature (which EdgeGuard's top-level `ner` feature enables). Without it, [`NerEngine`] is an
//! *uninhabited* type and [`NerEngine::load`] returns an error — the crate still compiles with zero ML
//! dependencies, so a default workspace build stays lean and fast. EdgeGuard's deterministic regex /
//! gazetteer / entropy fast path is what enforces by default; this is opt-in enrichment.
//!
//! ## Contract
//!
//! [`NerEngine::scan`] returns [`NerSpan`]s whose `start`/`end` are **byte offsets into the original
//! input string** (mapped back from the tokenizer's offsets), so the caller can splice them directly
//! into the same redaction pipeline the regex findings use. Special tokens (`[CLS]`/`[SEP]`/padding)
//! are skipped, and the per-span `score` is the softmax probability of the winning class so the caller
//! can threshold low-confidence spans.

use std::path::PathBuf;

/// One detected entity span. `start`/`end` are byte offsets into the original text passed to
/// [`NerEngine::scan`]; `label` is the model's raw entity label (e.g. `PER`, `B-LOC`, `ORG`); `score`
/// is the winning class probability in `[0.0, 1.0]`.
#[derive(Debug, Clone, PartialEq)]
pub struct NerSpan {
    pub label: String,
    pub start: usize,
    pub end: usize,
    pub score: f32,
}

/// What [`NerEngine::load`] needs: the ONNX model + HF tokenizer paths, the per-class label list in
/// model id order, and the max sequence length (longer inputs are truncated for the model; redaction
/// of the truncated tail still falls to the deterministic detectors).
#[derive(Debug, Clone)]
pub struct NerConfig {
    pub model_path: PathBuf,
    pub tokenizer_path: PathBuf,
    /// `labels[class_id]` → label string. Index order must match the model's output classes.
    pub labels: Vec<String>,
    pub max_seq_len: usize,
}

// ===================================================================================================
// Stub backend (no `onnx` feature): the crate compiles with zero ML deps; the type is uninhabited.
// ===================================================================================================

/// The loaded NER model. **Uninhabited** unless the `onnx` feature is built — so without it, no
/// instance can exist, [`NerEngine::load`] always errors, and [`NerEngine::scan`] is statically
/// unreachable.
#[cfg(not(feature = "onnx"))]
pub enum NerEngine {}

#[cfg(not(feature = "onnx"))]
impl NerEngine {
    /// Always an error in a build without the `onnx` feature.
    pub fn load(_cfg: NerConfig) -> anyhow::Result<NerEngine> {
        anyhow::bail!(
            "edgeguard-ner was built without the `onnx` feature; rebuild EdgeGuard with `--features ner`"
        )
    }

    /// Unreachable: `NerEngine` is uninhabited without the `onnx` feature.
    pub fn scan(&self, _text: &str) -> Vec<NerSpan> {
        match *self {}
    }
}

// ===================================================================================================
// Real backend (`onnx` feature): tract + tokenizers.
// ===================================================================================================

#[cfg(feature = "onnx")]
mod backend {
    use super::{NerConfig, NerSpan};
    use anyhow::{Context, Result};
    use tract_onnx::prelude::*;

    type Plan = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

    /// The loaded model: a runnable tract plan, the tokenizer, the id→label list, and limits.
    pub struct NerEngine {
        model: Plan,
        tokenizer: tokenizers::Tokenizer,
        labels: Vec<String>,
        max_seq_len: usize,
        /// Number of tensor inputs the model expects (2 = ids+mask, 3 = +token_type_ids).
        num_inputs: usize,
    }

    impl NerEngine {
        pub fn load(cfg: NerConfig) -> Result<NerEngine> {
            let tokenizer = tokenizers::Tokenizer::from_file(&cfg.tokenizer_path)
                .map_err(|e| anyhow::anyhow!("loading tokenizer {:?}: {e}", cfg.tokenizer_path))?;
            let model = tract_onnx::onnx()
                .model_for_path(&cfg.model_path)
                .with_context(|| format!("loading ONNX model {:?}", cfg.model_path))?
                .into_optimized()
                .context("optimizing ONNX model")?
                .into_runnable()
                .context("making ONNX model runnable")?;
            let num_inputs = model.model().inputs.len();
            anyhow::ensure!(
                cfg.max_seq_len > 2,
                "max_seq_len must leave room for special tokens (> 2)"
            );
            anyhow::ensure!(!cfg.labels.is_empty(), "labels must be non-empty");
            Ok(NerEngine {
                model,
                tokenizer,
                labels: cfg.labels,
                max_seq_len: cfg.max_seq_len,
                num_inputs,
            })
        }

        /// Run the model over `text` and return entity spans with byte offsets into `text`.
        ///
        /// On any model/tokenizer error this returns an empty vec rather than propagating — the
        /// deterministic detectors are the always-on enforcement layer, so a model fault degrades to
        /// "no ML spans this scan" instead of failing the request.
        pub fn scan(&self, text: &str) -> Vec<NerSpan> {
            self.try_scan(text).unwrap_or_default()
        }

        fn try_scan(&self, text: &str) -> Result<Vec<NerSpan>> {
            if text.trim().is_empty() {
                return Ok(Vec::new());
            }
            let enc = self
                .tokenizer
                .encode(text, true)
                .map_err(|e| anyhow::anyhow!("tokenizing: {e}"))?;

            // Truncate to the model's budget (keep room for the trailing special token).
            let ids = enc.get_ids();
            let mask = enc.get_attention_mask();
            let offsets = enc.get_offsets();
            let special = enc.get_special_tokens_mask();
            let len = ids.len().min(self.max_seq_len);
            if len == 0 {
                return Ok(Vec::new());
            }

            let input_ids: Vec<i64> = ids[..len].iter().map(|&x| x as i64).collect();
            let attn: Vec<i64> = mask[..len].iter().map(|&x| x as i64).collect();

            let ids_t = tract_ndarray::Array2::from_shape_vec((1, len), input_ids)
                .context("shaping input_ids")?
                .into_tensor();
            let mask_t = tract_ndarray::Array2::from_shape_vec((1, len), attn)
                .context("shaping attention_mask")?
                .into_tensor();

            // Feed inputs in the conventional HF order: input_ids, attention_mask, [token_type_ids].
            let mut inputs: TVec<TValue> = tvec!(ids_t.into(), mask_t.into());
            if self.num_inputs >= 3 {
                let tok_type = tract_ndarray::Array2::from_shape_vec((1, len), vec![0i64; len])
                    .context("shaping token_type_ids")?
                    .into_tensor();
                inputs.push(tok_type.into());
            }

            let result = self.model.run(inputs).context("running ONNX model")?;
            // Token-classification output: [1, seq, num_labels]. A model that returns no outputs
            // degrades to the empty-span fallback (try_scan's caller maps Err -> no spans) rather
            // than panicking on a missing index.
            let logits = result
                .first()
                .context("NER model returned no outputs")?
                .to_array_view::<f32>()
                .context("reading model logits")?;
            let shape = logits.shape();
            anyhow::ensure!(
                shape.len() == 3 && shape[0] == 1,
                "unexpected NER output shape {shape:?} (want [1, seq, labels])"
            );
            let seq = shape[1].min(len);
            let num_labels = shape[2];

            // Per token: argmax + softmax probability, mapped to (label, score), then assemble spans by
            // merging adjacent non-`O` tokens of the same entity type. Special tokens / zero-width
            // offsets are skipped so [CLS]/[SEP]/padding never become spans.
            let mut spans: Vec<NerSpan> = Vec::new();
            let mut cur: Option<NerSpan> = None;
            for t in 0..seq {
                if special.get(t).copied().unwrap_or(0) == 1 {
                    Self::flush(&mut cur, &mut spans);
                    continue;
                }
                let (s, e) = offsets.get(t).copied().unwrap_or((0, 0));
                if s == e {
                    Self::flush(&mut cur, &mut spans);
                    continue;
                }
                let row = logits.slice(tract_ndarray::s![0, t, ..]);
                let (best, score) = argmax_softmax(row.as_slice().unwrap_or(&[]), num_labels);
                let label = self.labels.get(best).map(|s| s.as_str()).unwrap_or("O");
                // A `B-` tag always starts a new entity, even when the previous token is the same
                // class — so two adjacent `B-PER` entities are not collapsed into one span. Only an
                // `I-` (continuation) tag of the same core extends the current span.
                let begins_new = label.strip_prefix("B-").is_some();
                let core = entity_core(label);
                match core {
                    None => Self::flush(&mut cur, &mut spans),
                    Some(kind) => match cur.as_mut() {
                        // Extend the current span only on a continuation tag of the same entity type.
                        Some(c) if !begins_new && entity_core(&c.label) == Some(kind) => {
                            c.end = e;
                            c.score = c.score.min(score); // weakest token bounds the span's confidence
                        }
                        _ => {
                            Self::flush(&mut cur, &mut spans);
                            cur = Some(NerSpan {
                                label: kind.to_string(),
                                start: s,
                                end: e,
                                score,
                            });
                        }
                    },
                }
            }
            Self::flush(&mut cur, &mut spans);
            Ok(spans)
        }

        fn flush(cur: &mut Option<NerSpan>, out: &mut Vec<NerSpan>) {
            if let Some(span) = cur.take() {
                out.push(span);
            }
        }
    }

    /// Argmax over `row[..num_labels]` plus the softmax probability of the winning class.
    fn argmax_softmax(row: &[f32], num_labels: usize) -> (usize, f32) {
        let row = &row[..row.len().min(num_labels)];
        if row.is_empty() {
            return (0, 0.0);
        }
        let mut best = 0usize;
        let mut max = row[0];
        for (i, &v) in row.iter().enumerate() {
            if v > max {
                max = v;
                best = i;
            }
        }
        let denom: f32 = row.iter().map(|&v| (v - max).exp()).sum();
        let score = if denom > 0.0 { 1.0 / denom } else { 0.0 };
        (best, score)
    }

    /// The entity "core" of a BIO label (`B-PER`/`I-PER` → `PER`), or `None` for the outside tag `O`.
    fn entity_core(label: &str) -> Option<&str> {
        let core = label.split_once('-').map(|(_, r)| r).unwrap_or(label);
        if core.eq_ignore_ascii_case("o") || core.is_empty() {
            None
        } else {
            Some(core)
        }
    }
}

#[cfg(feature = "onnx")]
pub use backend::NerEngine;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "onnx"))]
    #[test]
    fn load_errors_without_onnx_feature() {
        let r = NerEngine::load(NerConfig {
            model_path: "model.onnx".into(),
            tokenizer_path: "tok.json".into(),
            labels: vec!["O".into()],
            max_seq_len: 256,
        });
        assert!(r.is_err());
    }
}
