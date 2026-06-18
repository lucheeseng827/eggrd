//! Authentication gates: HTTP Basic, static API-key / bearer-token, and JWT (HS*/RS*/ES*/PS*
//! with either a static key or a fetched, cached JWKS).
//!
//! Every proxied request passes through exactly one [`AuthEngine`] (selected by
//! `auth.mode`). The engine returns a [`Decision`] carrying, on success, an optional
//! *principal* — the authenticated identity (Basic username, API-key id, or JWT `sub`) that
//! the per-key rate limiter keys on. The internal `/__edgeguard/*` endpoints never reach the
//! engine; they are separate routes outside the proxy fallback.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::http::{header, HeaderMap, HeaderName};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::warn;

use crate::config::{AuthCfg, JwtCfg};

/// The outcome of an authentication attempt.
pub enum Decision {
    /// Authenticated. Carries the principal used for per-key rate limiting (`None` when the
    /// scheme has no stable identity, e.g. `mode = "none"`).
    Allow(Option<String>),
    /// Rejected. Carries the challenge to advertise in `WWW-Authenticate` (if any).
    Deny(Challenge),
}

/// What to put in the `WWW-Authenticate` header of a `401`.
pub enum Challenge {
    Basic(String),
    Bearer,
    /// No standard challenge header (static API key).
    None,
}

/// Per-request authentication engine, built once from [`AuthCfg`] and held in the
/// hot-swappable runtime.
pub enum AuthEngine {
    /// No authentication — every request is allowed with no principal.
    Open,
    Basic,
    ApiKey {
        keys: Vec<String>,
        header: HeaderName,
    },
    Jwt(Box<JwtValidator>),
}

impl AuthEngine {
    /// Build the engine for the configured mode. Fails fast on a malformed JWT policy (bad
    /// algorithm, unparseable static key) so a misconfiguration surfaces at startup/reload
    /// rather than as a blanket `401` at request time.
    pub fn build(cfg: &AuthCfg) -> Result<AuthEngine> {
        match cfg.mode.as_str() {
            "none" => Ok(AuthEngine::Open),
            "basic" => Ok(AuthEngine::Basic),
            "apikey" => {
                let header = HeaderName::from_bytes(cfg.api_key_header.as_bytes())
                    .context("invalid auth.api_key_header")?;
                Ok(AuthEngine::ApiKey {
                    keys: cfg.api_keys.clone(),
                    header,
                })
            }
            "jwt" => Ok(AuthEngine::Jwt(Box::new(JwtValidator::build(&cfg.jwt)?))),
            other => anyhow::bail!("unknown auth.mode: {other:?} (expected none|basic|apikey|jwt)"),
        }
    }

    /// Apply the gate to a request's headers. Async because the JWT path may fetch a JWKS.
    pub async fn authorize(&self, cfg: &AuthCfg, headers: &HeaderMap) -> Decision {
        match self {
            AuthEngine::Open => Decision::Allow(None),
            AuthEngine::Basic => {
                if check_basic_auth(cfg, headers) {
                    // The principal is the username (for per-key limiting).
                    Decision::Allow(basic_username(headers))
                } else {
                    Decision::Deny(Challenge::Basic(format!("Basic realm=\"{}\"", cfg.realm)))
                }
            }
            AuthEngine::ApiKey { keys, header } => match verify_api_key(keys, header, headers) {
                Some(principal) => Decision::Allow(Some(principal)),
                None => Decision::Deny(Challenge::None),
            },
            AuthEngine::Jwt(v) => match bearer_token(headers) {
                Some(token) => match v.verify(token).await {
                    Ok(principal) => Decision::Allow(principal),
                    Err(_) => Decision::Deny(Challenge::Bearer),
                },
                None => Decision::Deny(Challenge::Bearer),
            },
        }
    }
}

/// Verify HTTP Basic credentials against the configured users. A stored value beginning with
/// `$argon2` is verified as a PHC hash; otherwise it is compared as plaintext (dev mode).
pub fn check_basic_auth(cfg: &AuthCfg, headers: &HeaderMap) -> bool {
    let Some((user, pass)) = basic_credentials(headers) else {
        return false;
    };
    let Some(stored) = cfg.users.get(&user) else {
        return false;
    };
    if stored.starts_with("$argon2") {
        match PasswordHash::new(stored) {
            Ok(parsed) => Argon2::default()
                .verify_password(pass.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        }
    } else {
        // Length-leaking but adequate for dev mode; swap to hashes for anything real.
        constant_time_eq(stored.as_bytes(), pass.as_bytes())
    }
}

/// Decode and split a `Basic` header into `(user, pass)`, or `None` if absent/malformed.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = auth.strip_prefix("Basic ")?;
    let decoded = B64.decode(b64.trim()).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pass) = creds.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

fn basic_username(headers: &HeaderMap) -> Option<String> {
    basic_credentials(headers).map(|(u, _)| u)
}

/// Extract the token from an `Authorization: Bearer <token>` header.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// Check a request against the set of accepted API keys. A key may be presented either as
/// `Authorization: Bearer <key>` or in the configured header (default `X-API-Key`). Returns
/// the principal (a stable, non-reversible id derived from the matched key) on success. The
/// comparison is constant-time and scans *all* keys so timing doesn't reveal which key — if
/// any — matched.
pub fn verify_api_key(keys: &[String], header: &HeaderName, headers: &HeaderMap) -> Option<String> {
    let presented = headers
        .get(header)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .or_else(|| bearer_token(headers))?;

    let mut matched: Option<&String> = None;
    for key in keys {
        // Don't short-circuit: always compare against every key.
        if constant_time_eq(key.as_bytes(), presented.as_bytes()) {
            matched = Some(key);
        }
    }
    matched.map(|k| format!("apikey:{}", short_id(k)))
}

/// A short, stable, non-reversible id for a secret, used only as a rate-limiter bucket key so
/// the plaintext secret isn't held as a map key or risk being logged.
fn short_id(secret: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    secret.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Hash a password into an Argon2id PHC string suitable for an `auth.users` value. Used by
/// the `--hash` CLI helper so operators can produce a hash without a separate argon2 tool.
pub fn hash_password(password: &str) -> Result<String> {
    use argon2::password_hash::rand_core::OsRng;
    use argon2::password_hash::{PasswordHasher, SaltString};

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Compare across the longer input and fold the length difference into the accumulator,
    // rather than short-circuiting on a length mismatch — an early return would let timing
    // distinguish secrets of different lengths. `usize` accumulator so a length delta that is
    // a multiple of 256 can't truncate to zero.
    let mut diff = a.len() ^ b.len();
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

// ---------------------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------------------

/// A validated JWT's principal: the `sub` claim, if present.
type Principal = Option<String>;

/// Verifies bearer JWTs against a configured key source, enforcing the configured algorithm,
/// issuer, audience, and expiry/leeway. The token's own `alg` header is never trusted to
/// pick the algorithm — [`Validation`] is pinned to the single configured algorithm, closing
/// the `alg=none`/HS-vs-RS confusion class of attacks.
pub struct JwtValidator {
    alg: Algorithm,
    validation: Validation,
    keys: KeySource,
}

enum KeySource {
    /// A single key resolved at build time (HS secret, or static RS/ES/PS PEM).
    Static(Arc<DecodingKey>),
    /// Keys fetched from a JWKS endpoint and cached, selected per-token by `kid`.
    Jwks(JwksCache),
}

impl JwtValidator {
    pub fn build(cfg: &JwtCfg) -> Result<JwtValidator> {
        let alg = parse_algorithm(&cfg.algorithm)?;

        let mut validation = Validation::new(alg);
        validation.leeway = cfg.leeway_secs;
        // `jsonwebtoken` defaults `validate_nbf` to false; enable it so a token that is not
        // yet valid ("not before" in the future) is rejected rather than accepted.
        validation.validate_nbf = true;
        if !cfg.issuer.is_empty() {
            validation.set_issuer(std::slice::from_ref(&cfg.issuer));
        }
        if cfg.audience.is_empty() {
            // No audience configured: don't reject tokens merely for carrying an `aud`.
            validation.validate_aud = false;
        } else {
            validation.set_audience(std::slice::from_ref(&cfg.audience));
        }

        let keys = if !cfg.jwks_url.is_empty() {
            KeySource::Jwks(JwksCache::new(
                cfg.jwks_url.clone(),
                Duration::from_secs(cfg.jwks_cache_secs),
            )?)
        } else {
            KeySource::Static(Arc::new(static_key(cfg, alg)?))
        };

        Ok(JwtValidator {
            alg,
            validation,
            keys,
        })
    }

    /// Verify a raw token string, returning its principal on success.
    pub async fn verify(&self, token: &str) -> Result<Principal> {
        let header = decode_header(token).context("malformed JWT header")?;
        // Guard before key selection: the header alg must be the one we're configured for.
        anyhow::ensure!(
            header.alg == self.alg,
            "token alg {:?} != configured {:?}",
            header.alg,
            self.alg
        );

        let key = match &self.keys {
            KeySource::Static(k) => k.clone(),
            KeySource::Jwks(cache) => cache.key_for(header.kid.as_deref()).await?,
        };

        let data = decode::<Value>(token, &key, &self.validation).context("JWT rejected")?;
        let principal = data
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Ok(principal)
    }
}

/// Resolve a single static [`DecodingKey`] for HS* (shared secret) or asymmetric (PEM) algs.
fn static_key(cfg: &JwtCfg, alg: Algorithm) -> Result<DecodingKey> {
    use Algorithm::*;
    match alg {
        HS256 | HS384 | HS512 => {
            anyhow::ensure!(
                !cfg.secret.is_empty(),
                "auth.jwt.secret (or $EDGEGUARD_JWT_SECRET) is required for HS* algorithms"
            );
            Ok(DecodingKey::from_secret(cfg.secret.as_bytes()))
        }
        RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => {
            anyhow::ensure!(
                !cfg.public_key_pem.is_empty(),
                "auth.jwt.public_key_pem (or jwks_url) is required for RS*/PS* algorithms"
            );
            DecodingKey::from_rsa_pem(cfg.public_key_pem.as_bytes())
                .context("parsing auth.jwt.public_key_pem as RSA")
        }
        ES256 | ES384 => {
            anyhow::ensure!(
                !cfg.public_key_pem.is_empty(),
                "auth.jwt.public_key_pem (or jwks_url) is required for ES* algorithms"
            );
            DecodingKey::from_ec_pem(cfg.public_key_pem.as_bytes())
                .context("parsing auth.jwt.public_key_pem as EC")
        }
        EdDSA => {
            anyhow::ensure!(
                !cfg.public_key_pem.is_empty(),
                "auth.jwt.public_key_pem (or jwks_url) is required for EdDSA"
            );
            DecodingKey::from_ed_pem(cfg.public_key_pem.as_bytes())
                .context("parsing auth.jwt.public_key_pem as Ed25519")
        }
    }
}

fn parse_algorithm(s: &str) -> Result<Algorithm> {
    Ok(match s.to_ascii_uppercase().as_str() {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "EDDSA" => Algorithm::EdDSA,
        other => anyhow::bail!("unsupported auth.jwt.algorithm: {other}"),
    })
}

/// A JWKS endpoint plus an in-memory cache of the decoding keys it served, refreshed lazily
/// when stale or on a `kid` miss (handling key rotation without a restart).
struct JwksCache {
    url: String,
    ttl: Duration,
    http: reqwest::Client,
    inner: RwLock<Option<CachedKeys>>,
}

struct CachedKeys {
    fetched_at: Instant,
    /// Keys by `kid`. Keys with no `kid` are stored under the empty string.
    by_kid: HashMap<String, Arc<DecodingKey>>,
}

impl JwksCache {
    fn new(url: String, ttl: Duration) -> Result<JwksCache> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .context("building JWKS HTTP client")?;
        Ok(JwksCache {
            url,
            ttl,
            http,
            inner: RwLock::new(None),
        })
    }

    /// Return the decoding key for `kid`, fetching/refreshing the JWKS if the cache is empty,
    /// stale, or missing that `kid` (a likely sign of rotation).
    async fn key_for(&self, kid: Option<&str>) -> Result<Arc<DecodingKey>> {
        if let Some(key) = self.lookup_fresh(kid).await {
            return Ok(key);
        }

        // Hold the write lock across the refresh so concurrent misses don't stampede the JWKS
        // endpoint (single-flight); the next waiter sees the just-fetched keys. Re-check under
        // the lock, and on a fetch failure keep the existing (stale) keys so a transient IdP
        // hiccup doesn't turn into a blanket auth outage.
        let mut guard = self.inner.write().await;
        let needs_fetch = match guard.as_ref() {
            Some(c) => c.fetched_at.elapsed() > self.ttl || select_key(&c.by_kid, kid).is_none(),
            None => true,
        };
        if needs_fetch {
            match self.fetch().await {
                Ok(by_kid) => {
                    *guard = Some(CachedKeys {
                        fetched_at: Instant::now(),
                        by_kid,
                    });
                }
                Err(e) if guard.is_some() => {
                    warn!(error = %format!("{e:#}"), "JWKS refresh failed; using cached keys");
                }
                Err(e) => return Err(e.context("JWKS refresh failed and no cached keys")),
            }
        }
        if let Some(c) = guard.as_ref() {
            if let Some(key) = select_key(&c.by_kid, kid) {
                return Ok(key);
            }
        }
        match kid {
            Some(k) => anyhow::bail!("no JWKS key for kid {k:?}"),
            None => anyhow::bail!("JWKS contains no usable key"),
        }
    }

    /// Look up a key only if the cache is still within its TTL.
    async fn lookup_fresh(&self, kid: Option<&str>) -> Option<Arc<DecodingKey>> {
        let guard = self.inner.read().await;
        let cached = guard.as_ref()?;
        if cached.fetched_at.elapsed() > self.ttl {
            return None;
        }
        select_key(&cached.by_kid, kid)
    }

    /// Fetch and parse the JWKS, returning the decoding keys without storing them (the caller
    /// stores under the write lock, so a failed fetch leaves the prior cache intact).
    async fn fetch(&self) -> Result<HashMap<String, Arc<DecodingKey>>> {
        let body = self
            .http
            .get(&self.url)
            .send()
            .await
            .with_context(|| format!("fetching JWKS from {}", self.url))?
            .error_for_status()
            .context("JWKS endpoint returned an error status")?
            .text()
            .await
            .context("reading JWKS body")?;
        parse_jwks(&body)
    }
}

/// Pick a key from a `kid -> key` map: by `kid` if the token names one, otherwise the sole
/// key when the set is unambiguous (a common single-key JWKS).
fn select_key(
    by_kid: &HashMap<String, Arc<DecodingKey>>,
    kid: Option<&str>,
) -> Option<Arc<DecodingKey>> {
    match kid {
        Some(k) => by_kid.get(k).cloned(),
        None if by_kid.len() == 1 => by_kid.values().next().cloned(),
        None => by_kid.get("").cloned(),
    }
}

/// Parse a JWKS JSON document into decoding keys indexed by `kid`.
fn parse_jwks(json: &str) -> Result<HashMap<String, Arc<DecodingKey>>> {
    let set: JwkSet = serde_json::from_str(json).context("parsing JWKS JSON")?;
    let mut by_kid = HashMap::new();
    for jwk in &set.keys {
        match DecodingKey::from_jwk(jwk) {
            Ok(key) => {
                let kid = jwk.common.key_id.clone().unwrap_or_default();
                by_kid.insert(kid, Arc::new(key));
            }
            Err(e) => warn!(error = %e, "skipping unusable JWKS key"),
        }
    }
    anyhow::ensure!(!by_kid.is_empty(), "JWKS contained no usable keys");
    Ok(by_kid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthCfg;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn headers_with(name: &'static str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, value.parse().unwrap());
        h
    }

    fn basic_value(user: &str, pass: &str) -> String {
        format!("Basic {}", B64.encode(format!("{user}:{pass}")))
    }

    fn cfg_with_user(user: &str, secret: &str) -> AuthCfg {
        AuthCfg {
            users: BTreeMap::from([(user.to_string(), secret.to_string())]),
            ..Default::default()
        }
    }

    // --- Basic auth (moved from proxy.rs) ---

    #[test]
    fn basic_auth_plaintext_accepts_correct_rejects_bad() {
        let cfg = cfg_with_user("admin", "s3cret");
        assert!(check_basic_auth(
            &cfg,
            &headers_with("authorization", &basic_value("admin", "s3cret"))
        ));
        assert!(!check_basic_auth(
            &cfg,
            &headers_with("authorization", &basic_value("admin", "wrong"))
        ));
        assert!(!check_basic_auth(
            &cfg,
            &headers_with("authorization", &basic_value("ghost", "s3cret"))
        ));
    }

    #[test]
    fn basic_auth_rejects_missing_and_malformed_headers() {
        let cfg = cfg_with_user("admin", "s3cret");
        assert!(!check_basic_auth(&cfg, &HeaderMap::new()));
        assert!(!check_basic_auth(
            &cfg,
            &headers_with("authorization", "Bearer token")
        ));
        assert!(!check_basic_auth(
            &cfg,
            &headers_with("authorization", "Basic !!!not-base64!!!")
        ));
    }

    #[test]
    fn basic_auth_argon2_path() {
        let phc = hash_password("hunter2").unwrap();
        assert!(phc.starts_with("$argon2"), "{phc}");
        let cfg = cfg_with_user("admin", &phc);
        assert!(check_basic_auth(
            &cfg,
            &headers_with("authorization", &basic_value("admin", "hunter2"))
        ));
        assert!(!check_basic_auth(
            &cfg,
            &headers_with("authorization", &basic_value("admin", "nope"))
        ));
    }

    #[test]
    fn constant_time_eq_handles_differing_lengths() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        // Differing lengths must compare unequal without a length-based early return.
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    // --- API key ---

    #[test]
    fn api_key_accepts_via_bearer_and_header_rejects_unknown() {
        let keys = vec!["sk_live_abc".to_string(), "sk_live_def".to_string()];
        let header = HeaderName::from_static("x-api-key");

        // Custom header.
        assert!(
            verify_api_key(&keys, &header, &headers_with("x-api-key", "sk_live_abc")).is_some()
        );
        // Authorization: Bearer.
        assert!(verify_api_key(
            &keys,
            &header,
            &headers_with("authorization", "Bearer sk_live_def")
        )
        .is_some());
        // Unknown key and no key at all.
        assert!(verify_api_key(&keys, &header, &headers_with("x-api-key", "nope")).is_none());
        assert!(verify_api_key(&keys, &header, &HeaderMap::new()).is_none());
    }

    #[test]
    fn api_key_principal_is_stable_and_not_the_raw_key() {
        let keys = vec!["super-secret-key".to_string()];
        let header = HeaderName::from_static("x-api-key");
        let p1 = verify_api_key(
            &keys,
            &header,
            &headers_with("x-api-key", "super-secret-key"),
        );
        let p2 = verify_api_key(
            &keys,
            &header,
            &headers_with("x-api-key", "super-secret-key"),
        );
        assert_eq!(p1, p2);
        assert!(!p1.unwrap().contains("super-secret-key"));
    }

    // --- JWT (HS256, no network) ---

    fn hs_validator(secret: &str) -> JwtValidator {
        JwtValidator::build(&JwtCfg {
            algorithm: "HS256".into(),
            secret: secret.into(),
            issuer: "edgeguard-test".into(),
            ..Default::default()
        })
        .unwrap()
    }

    fn hs_token(secret: &str, claims: Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn far_future() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    #[tokio::test]
    async fn jwt_hs256_accepts_valid_and_returns_sub() {
        let v = hs_validator("topsecret");
        let token = hs_token(
            "topsecret",
            json!({ "sub": "user-42", "iss": "edgeguard-test", "exp": far_future() }),
        );
        let principal = v.verify(&token).await.unwrap();
        assert_eq!(principal.as_deref(), Some("user-42"));
    }

    #[tokio::test]
    async fn jwt_hs256_rejects_bad_signature_wrong_issuer_and_expired() {
        let v = hs_validator("topsecret");

        // Signed with the wrong secret.
        let forged = hs_token(
            "WRONG",
            json!({ "sub": "x", "iss": "edgeguard-test", "exp": far_future() }),
        );
        assert!(v.verify(&forged).await.is_err());

        // Wrong issuer.
        let wrong_iss = hs_token(
            "topsecret",
            json!({ "sub": "x", "iss": "someone-else", "exp": far_future() }),
        );
        assert!(v.verify(&wrong_iss).await.is_err());

        // Expired.
        let expired = hs_token(
            "topsecret",
            json!({ "sub": "x", "iss": "edgeguard-test", "exp": 1_000 }),
        );
        assert!(v.verify(&expired).await.is_err());
    }

    #[tokio::test]
    async fn jwt_rejects_algorithm_confusion() {
        // Validator expects HS256; a token claiming a different alg must be refused before
        // any key is consulted (defends against alg-substitution).
        let v = hs_validator("topsecret");
        let mut header = Header::new(Algorithm::HS384);
        header.kid = None;
        let token = encode(
            &header,
            &json!({ "sub": "x", "iss": "edgeguard-test", "exp": far_future() }),
            &EncodingKey::from_secret(b"topsecret"),
        )
        .unwrap();
        assert!(v.verify(&token).await.is_err());
    }

    #[tokio::test]
    async fn jwt_hs256_rejects_not_yet_valid_token() {
        let v = hs_validator("topsecret");
        // `nbf` far in the future: the token is not valid yet and must be rejected.
        let token = hs_token(
            "topsecret",
            json!({ "sub": "x", "iss": "edgeguard-test", "exp": far_future(), "nbf": far_future() }),
        );
        assert!(v.verify(&token).await.is_err());
    }

    #[test]
    fn build_rejects_bad_algorithm_and_missing_secret() {
        assert!(JwtValidator::build(&JwtCfg {
            algorithm: "NOPE".into(),
            ..Default::default()
        })
        .is_err());
        // HS256 with no secret configured.
        assert!(JwtValidator::build(&JwtCfg {
            algorithm: "HS256".into(),
            secret: String::new(),
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn parse_jwks_indexes_keys_by_kid() {
        // A minimal RSA JWKS (well-formed test key material) parses into a key for its kid.
        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "kid": "key-1",
                "use": "sig",
                "alg": "RS256",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB"
            }]
        })
        .to_string();
        let keys = parse_jwks(&jwks).unwrap();
        assert!(
            keys.contains_key("key-1"),
            "kid not indexed: {:?}",
            keys.keys()
        );
    }

    #[test]
    fn parse_jwks_rejects_empty_and_garbage() {
        assert!(parse_jwks("not json").is_err());
        assert!(parse_jwks(r#"{"keys":[]}"#).is_err());
    }
}
