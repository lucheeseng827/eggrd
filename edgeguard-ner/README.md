# edgeguard-ner

The optional **pure-Rust ONNX NER layer** for [EdgeGuard](https://crates.io/crates/eggrd)'s
edge DLP (gateway L3). It runs a small token-classification (BIO) model to catch the PII
entities regex can't — `person`, `address`, `org` — and returns spans with **byte offsets
into the original text**, ready to splice into the same redaction pipeline as EdgeGuard's
signature / gazetteer / entropy detectors.

It exists as a **separate crate behind a feature** so that EdgeGuard's default build stays a
lean, dependency-free static binary: with the `onnx` feature off, this crate compiles with
**zero ML dependencies** and `NerEngine` is an uninhabited type. The ML graph only exists when
you explicitly opt in.

## Why `tract`, not `ort`

Inference runs on [`tract`](https://github.com/sonos/tract) — a **pure-Rust** ONNX engine that
links nothing. There is deliberately no `ort` / `libonnxruntime` dependency: that would pull a
C++ shared object and break EdgeGuard's distroless / static-musl single-binary promise. The
HuggingFace `tokenizers` dependency is likewise built C-free (no `onig`).

## Status

Alpha. The API below is small and stable; the model/tokenizer are supplied by you at load time
(no weights are bundled). Most users consume this transitively via
`cargo install eggrd --features ner` rather than depending on it directly.

## Usage

```toml
[dependencies]
edgeguard-ner = { version = "0.1", features = ["onnx"] }
```

Without the `onnx` feature the crate still compiles, but `NerEngine::load` returns an error —
so downstream code can depend on it unconditionally and gate the ML path behind a feature.

```rust
use edgeguard_ner::{NerConfig, NerEngine};

let engine = NerEngine::load(NerConfig {
    model_path: "model.onnx".into(),
    tokenizer_path: "tokenizer.json".into(),
    // labels[class_id] -> BIO label, in the model's output-class order.
    labels: vec!["O".into(), "B-PER".into(), "I-PER".into(), "B-ORG".into(), "I-ORG".into()],
    max_seq_len: 256,
})?;

for span in engine.scan("Contact Jane Doe at Acme Corp.") {
    // span.start / span.end are byte offsets into the input string.
    println!("{} [{}..{}] score={:.2}", span.label, span.start, span.end, span.score);
}
# Ok::<(), anyhow::Error>(())
```

### Contract

- **`NerConfig`** — paths to the ONNX model + HF tokenizer, the per-class `labels` list in
  model id order, and `max_seq_len` (longer inputs are truncated for the model; the tail still
  falls to EdgeGuard's deterministic detectors).
- **`NerSpan { label, start, end, score }`** — `start`/`end` are byte offsets into the original
  text; `label` is the entity core (`PER`, `ORG`, …); `score` is the winning class's softmax
  probability, so callers can threshold low-confidence spans.
- **`NerEngine::scan`** is fail-soft: any model/tokenizer error yields an empty span list rather
  than propagating, because EdgeGuard's deterministic detectors are the always-on enforcement
  layer — an ML fault degrades to "no ML spans this scan", never a failed request.

BIO decoding merges adjacent `I-` continuation tokens of the same entity into one span; a `B-`
tag always starts a new entity; `[CLS]`/`[SEP]`/padding tokens never become spans.

## Model

Bring any token-classification ONNX export (DeBERTa / BERT-NER class; a GLiNER export works
too) plus its HuggingFace `tokenizer.json`. The engine feeds `input_ids` + `attention_mask`
(and `token_type_ids` when the model has three inputs) in the conventional HF order.

## License

Apache-2.0. Part of the [EdgeGuard](https://github.com/lucheeseng827/eggrd) project.
