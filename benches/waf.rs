//! WAF-lite input-inspection micro-benchmarks.
//!
//! `WafEngine::evaluate` runs the compiled RE2 `RegexSet`s against the request path/query (and,
//! opt-in, headers/body) on every request once `[waf]` is enabled. The cost that matters for an
//! operator deciding to turn it on is two-fold:
//!   * the **clean-path** cost — what every legitimate request pays when nothing matches, and
//!   * the **decode** cost — the extra percent-decode pass taken only when the path contains `%`.
//!
//! These benches isolate both against the built-in SQLi/XSS/path-traversal rulesets so the white
//! paper can state the WAF's per-request tax rather than inferring it from end-to-end latency.

use axum::http::HeaderMap;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use edgeguard::config::WafCfg;
use edgeguard::waf::WafEngine;

/// All built-in rulesets on, in `block` mode, inspecting the path (the default surface).
fn engine_all_builtins() -> WafEngine {
    let cfg = WafCfg {
        mode: "block".into(),
        sqli: true,
        xss: true,
        path_traversal: true,
        inspect_path: true,
        ..Default::default()
    };
    WafEngine::build(&cfg).unwrap()
}

fn bench_evaluate(c: &mut Criterion) {
    let engine = engine_all_builtins();
    let headers = HeaderMap::new();
    let empty_body: &[u8] = &[];

    let mut group = c.benchmark_group("waf_evaluate");

    // The common case: a benign request that matches nothing and has no `%` to decode. This is
    // the tax every legitimate request pays with the WAF enabled.
    group.bench_function(BenchmarkId::from_parameter("clean_no_decode"), |b| {
        let path = "/api/v1/users/42/profile?fields=name,email&sort=asc";
        b.iter(|| engine.evaluate(path, &headers, empty_body));
    });

    // Benign but percent-encoded: forces the extra decode pass even though nothing matches —
    // isolates the cost of the decode branch on legitimate traffic.
    group.bench_function(BenchmarkId::from_parameter("clean_with_decode"), |b| {
        let path = "/search?q=hello%20world%20foo%20bar&page=2";
        b.iter(|| engine.evaluate(path, &headers, empty_body));
    });

    // A SQLi payload in the raw query — measures the matching cost when a rule fires (early
    // return on first match).
    group.bench_function(BenchmarkId::from_parameter("sqli_hit_raw"), |b| {
        let path = "/items?id=1%20OR%201=1%20UNION%20SELECT%20pw%20FROM%20users";
        b.iter(|| engine.evaluate(path, &headers, empty_body));
    });

    // A path-traversal payload that only matches after percent-decoding (`%2e%2e%2f` -> `../`):
    // exercises the raw-miss-then-decode-hit path.
    group.bench_function(BenchmarkId::from_parameter("traversal_hit_decoded"), |b| {
        let path = "/static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd";
        b.iter(|| engine.evaluate(path, &headers, empty_body));
    });

    group.finish();
}

criterion_group!(benches, bench_evaluate);
criterion_main!(benches);
