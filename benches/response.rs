//! Response-hardening and config-parsing micro-benchmarks.
//!
//! `security_headers` rebuilds the injected header set from the live policy; `parse_size` /
//! `parse_rate` run at startup and on every hot-reload. None of these are expected to be hot
//! enough to matter, and the point of benching them is precisely to *confirm* that — so the
//! white paper can attribute the proxy's per-request overhead to I/O and the auth/WAF stages
//! rather than to header assembly or config parsing.

use criterion::{criterion_group, criterion_main, Criterion};

use edgeguard::config::{parse_rate, parse_size, HeadersCfg};
use edgeguard::proxy::security_headers;

fn bench_security_headers(c: &mut Criterion) {
    let cfg = HeadersCfg::default();
    c.bench_function("security_headers_default", |b| {
        b.iter(|| security_headers(&cfg));
    });
}

fn bench_config_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_parse");
    group.bench_function("parse_size", |b| {
        b.iter(|| parse_size(criterion::black_box("10MB")).unwrap());
    });
    group.bench_function("parse_rate", |b| {
        b.iter(|| parse_rate(criterion::black_box("600/min")).unwrap());
    });
    group.finish();
}

criterion_group!(benches, bench_security_headers, bench_config_parsing);
criterion_main!(benches);
