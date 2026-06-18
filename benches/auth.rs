//! Auth-gate micro-benchmarks.
//!
//! Drives the real `AuthEngine::authorize` entry point — the same one `proxy::handle` calls on
//! every request — across each `auth.mode`, so the white paper can report the per-request cost
//! of the gate in isolation (the macro k6 test only sees it folded into end-to-end latency).
//!
//! The headline figure here is the **deliberate** asymmetry: a plaintext/api-key/JWT-HS256
//! check is sub-microsecond, while an Argon2id verification is intentionally in the
//! millisecond range (that cost is the password-hashing defense, not overhead to optimize
//! away). Surfacing both stops a reader from assuming "auth = argon2 cost" for token modes.

use std::collections::BTreeMap;

use axum::http::{header, HeaderMap, HeaderValue};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;

use edgeguard::auth::{AuthEngine, Decision};
use edgeguard::config::{AuthCfg, JwtCfg};
use edgeguard::hash_password;

/// One shared Tokio runtime: `authorize` is async (JWKS-capable), but the static/HS paths
/// resolve without ever yielding, so `block_on` measures CPU cost without scheduler noise.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

fn basic_headers(user: &str, pass: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    let v = format!("Basic {}", B64.encode(format!("{user}:{pass}")));
    h.insert(header::AUTHORIZATION, HeaderValue::from_str(&v).unwrap());
    h
}

fn bearer_headers(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    h
}

fn apikey_headers(key: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-api-key", HeaderValue::from_str(key).unwrap());
    h
}

fn sign_hs256(secret: &str) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        &json!({ "sub": "bench", "iss": "edgeguard-bench", "exp": 9_999_999_999u64 }),
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn bench_authorize(c: &mut Criterion) {
    let runtime = rt();
    let mut group = c.benchmark_group("auth_authorize");

    // --- mode = "none": the floor (no header inspection at all). ---
    {
        let cfg = AuthCfg {
            mode: "none".into(),
            ..Default::default()
        };
        let engine = AuthEngine::build(&cfg).unwrap();
        let headers = HeaderMap::new();
        // Untimed correctness check: guards against silently benchmarking a regressed
        // (wrong-outcome) fast path.
        assert!(matches!(
            runtime.block_on(engine.authorize(&cfg, &headers)),
            Decision::Allow(_)
        ));
        group.bench_function(BenchmarkId::from_parameter("none"), |b| {
            b.iter(|| runtime.block_on(engine.authorize(&cfg, &headers)));
        });
    }

    // --- mode = "basic", plaintext value: constant-time compare, no KDF. ---
    {
        let cfg = AuthCfg {
            mode: "basic".into(),
            users: BTreeMap::from([("admin".to_string(), "s3cret".to_string())]),
            ..Default::default()
        };
        let engine = AuthEngine::build(&cfg).unwrap();
        let headers = basic_headers("admin", "s3cret");
        assert!(matches!(
            runtime.block_on(engine.authorize(&cfg, &headers)),
            Decision::Allow(_)
        ));
        group.bench_function(BenchmarkId::from_parameter("basic_plaintext"), |b| {
            b.iter(|| runtime.block_on(engine.authorize(&cfg, &headers)));
        });
    }

    // --- mode = "basic", argon2id PHC hash: the intentionally expensive path. ---
    {
        let hash = hash_password("s3cret").unwrap();
        let cfg = AuthCfg {
            mode: "basic".into(),
            users: BTreeMap::from([("admin".to_string(), hash)]),
            ..Default::default()
        };
        let engine = AuthEngine::build(&cfg).unwrap();
        let headers = basic_headers("admin", "s3cret");
        assert!(matches!(
            runtime.block_on(engine.authorize(&cfg, &headers)),
            Decision::Allow(_)
        ));
        group.bench_function(BenchmarkId::from_parameter("basic_argon2"), |b| {
            b.iter(|| runtime.block_on(engine.authorize(&cfg, &headers)));
        });
    }

    // --- mode = "apikey": constant-time match of X-API-Key / Bearer. ---
    {
        let cfg = AuthCfg {
            mode: "apikey".into(),
            api_keys: vec!["sk_live_0".into(), "sk_live_1".into(), "sk_live_2".into()],
            ..Default::default()
        };
        let engine = AuthEngine::build(&cfg).unwrap();
        let headers = apikey_headers("sk_live_2");
        assert!(matches!(
            runtime.block_on(engine.authorize(&cfg, &headers)),
            Decision::Allow(_)
        ));
        group.bench_function(BenchmarkId::from_parameter("apikey"), |b| {
            b.iter(|| runtime.block_on(engine.authorize(&cfg, &headers)));
        });
    }

    // --- mode = "jwt", HS256 static secret: signature verify on the hot path. ---
    {
        let secret = "bench-hs256-secret";
        let cfg = AuthCfg {
            mode: "jwt".into(),
            jwt: JwtCfg {
                algorithm: "HS256".into(),
                secret: secret.into(),
                issuer: "edgeguard-bench".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let engine = AuthEngine::build(&cfg).unwrap();
        let headers = bearer_headers(&sign_hs256(secret));
        assert!(matches!(
            runtime.block_on(engine.authorize(&cfg, &headers)),
            Decision::Allow(_)
        ));
        group.bench_function(BenchmarkId::from_parameter("jwt_hs256"), |b| {
            b.iter(|| runtime.block_on(engine.authorize(&cfg, &headers)));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_authorize);
criterion_main!(benches);
