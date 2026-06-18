//! EdgeGuard — Cloudflare Worker edge build (Phase 5 / v2.5).
//!
//! Brings the slice of EdgeGuard that makes sense at a static/edge host to Cloudflare Workers:
//! **response-hardening** headers (mirroring `edgeguard::proxy::security_headers`), cookie
//! hardening and leaky-header stripping, plus a lightweight **edge-auth** gate (HTTP Basic or a
//! static API key, constant-time compared). The worker authenticates the request, fetches the
//! configured origin, and hardens the response on the way back.
//!
//! **Why a separate crate (not a dependency on `edgeguard`):** the main crate pulls in
//! tokio/hyper/axum/rustls/redis, none of which build for `wasm32-unknown-unknown`. So the small
//! amount of logic shared in spirit (the header set, the constant-time compare, cookie
//! hardening) is reimplemented here against the Workers API. The values are kept identical to the
//! proxy — see `../src/proxy.rs` and `../src/auth.rs`.
//!
//! **Honesty note:** like ACME and the Redis limiter in the main crate, this is implemented and
//! builds to wasm, but is **proven only against a live Cloudflare deploy** — the wasm `fetch`
//! entrypoint can't run in the in-crate test suite. The pure logic it relies on (the header set,
//! the auth decision, cookie hardening, header stripping, origin-URL joining, env parsing) IS
//! unit-tested on the native target below (`cargo test`).
//!
//! **Out of scope for the edge subset:** rate limiting (needs a stateful binding — Durable
//! Objects / KV — not a pure-WASM concern) and JWT/JWKS verification (use the full proxy).

use base64::{engine::general_purpose::STANDARD as B64, Engine};

/// The HSTS header value, identical to `edgeguard::proxy::HSTS_VALUE`: a two-year `max-age`
/// including subdomains.
pub const HSTS_VALUE: &str = "max-age=63072000; includeSubDomains";

// ---------------------------------------------------------------------------------------
// Response hardening (pure) — mirror of `edgeguard::proxy::security_headers` / `harden_cookie`.
// ---------------------------------------------------------------------------------------

/// The response-hardening policy. Defaults match `edgeguard::config::HeadersCfg::default()` so
/// the worker and the proxy harden a response identically out of the box.
#[derive(Debug, Clone)]
pub struct Hardening {
    pub hsts: bool,
    pub csp: String,
    pub csp_report_only: bool,
    pub csp_report_uri: String,
    pub referrer_policy: String,
    pub permissions_policy: String,
    pub frame_options: String,
    pub force_secure_cookies: bool,
    /// Response headers to strip (case-insensitive), e.g. `["Server", "X-Powered-By"]`.
    pub strip: Vec<String>,
}

impl Default for Hardening {
    fn default() -> Self {
        Hardening {
            hsts: true,
            csp: "default-src 'self'".into(),
            csp_report_only: false,
            csp_report_uri: String::new(),
            referrer_policy: "no-referrer".into(),
            permissions_policy: "geolocation=(), microphone=(), camera=()".into(),
            frame_options: "DENY".into(),
            force_secure_cookies: true,
            strip: vec!["Server".into(), "X-Powered-By".into()],
        }
    }
}

impl Hardening {
    /// The constant security headers to inject — a byte-for-byte mirror of
    /// `edgeguard::proxy::security_headers`, so the worker and the proxy never diverge.
    pub fn security_headers(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::with_capacity(6);
        out.push(("X-Content-Type-Options", "nosniff".to_string()));
        if !self.frame_options.is_empty() {
            out.push(("X-Frame-Options", self.frame_options.clone()));
        }
        if !self.referrer_policy.is_empty() {
            out.push(("Referrer-Policy", self.referrer_policy.clone()));
        }
        if !self.permissions_policy.is_empty() {
            out.push(("Permissions-Policy", self.permissions_policy.clone()));
        }
        if !self.csp.is_empty() {
            let mut value = self.csp.clone();
            if !self.csp_report_uri.is_empty() {
                value.push_str("; report-uri ");
                value.push_str(&self.csp_report_uri);
            }
            let name = if self.csp_report_only {
                "Content-Security-Policy-Report-Only"
            } else {
                "Content-Security-Policy"
            };
            out.push((name, value));
        }
        if self.hsts {
            out.push(("Strict-Transport-Security", HSTS_VALUE.to_string()));
        }
        out
    }
}

/// Ensure a `Set-Cookie` value carries `Secure`, `HttpOnly`, and a `SameSite` default. A mirror
/// of `harden_cookie` in `../src/proxy.rs`: it inspects attribute *names* (not the raw string)
/// so a value like `session=securetoken` isn't mistaken for already having `Secure`.
pub fn harden_cookie(cookie: &str) -> String {
    let attrs: std::collections::HashSet<String> = cookie
        .split(';')
        .skip(1)
        .filter_map(|p| p.trim().split('=').next())
        .map(|k| k.trim().to_ascii_lowercase())
        .collect();

    let mut out = cookie.trim_end_matches(';').to_string();
    if !attrs.contains("secure") {
        out.push_str("; Secure");
    }
    if !attrs.contains("httponly") {
        out.push_str("; HttpOnly");
    }
    if !attrs.contains("samesite") {
        out.push_str("; SameSite=Lax");
    }
    out
}

// ---------------------------------------------------------------------------------------
// Auth (pure) — mirror of the Basic / API-key gates in `../src/auth.rs`.
// ---------------------------------------------------------------------------------------

/// The edge-auth gate to apply. (JWT/JWKS is intentionally out of scope here — use the proxy.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    None,
    Basic,
    ApiKey,
}

impl AuthMode {
    /// Parse `EDGEGUARD_AUTH_MODE`; anything unrecognized is treated as `none`.
    pub fn parse(s: &str) -> AuthMode {
        match s.trim().to_ascii_lowercase().as_str() {
            "basic" => AuthMode::Basic,
            "apikey" => AuthMode::ApiKey,
            _ => AuthMode::None,
        }
    }
}

/// The outcome of the edge-auth check: allow, or deny with an optional `WWW-Authenticate` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Allow,
    Deny { www_authenticate: Option<String> },
}

/// Constant-time byte comparison — a copy of the `constant_time_eq` in `../src/auth.rs`. Folds
/// the length difference into the accumulator instead of returning early, so timing can't
/// distinguish secrets of different lengths.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

/// Extract the token from an `Authorization: Bearer <token>` value.
fn bearer_token(h: &str) -> Option<&str> {
    h.strip_prefix("Bearer ").map(str::trim)
}

/// Verify HTTP Basic credentials against a single configured `user`/`pass` (constant-time).
/// `header` is the raw `Authorization` value, if present. An unset credential never authenticates
/// (so a misconfigured worker fails closed). Edge credentials come from Worker *secrets*, not a
/// hashed file, so this is a plaintext constant-time compare.
pub fn check_basic(user: &str, pass: &str, header: Option<&str>) -> bool {
    if user.is_empty() && pass.is_empty() {
        return false;
    }
    let Some(h) = header else {
        return false;
    };
    let Some(b64) = h.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = B64.decode(b64.trim()) else {
        return false;
    };
    let Ok(creds) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((u, p)) = creds.split_once(':') else {
        return false;
    };
    // Evaluate both fields (bound to locals, then `&` so neither short-circuits the other).
    let ok_user = constant_time_eq(u.as_bytes(), user.as_bytes());
    let ok_pass = constant_time_eq(p.as_bytes(), pass.as_bytes());
    ok_user & ok_pass
}

/// Match a presented API key against the accepted set, constant-time, scanning *all* keys so
/// timing doesn't reveal which (if any) matched. Mirrors `verify_api_key` in `../src/auth.rs`.
pub fn match_api_key(keys: &[String], presented: Option<&str>) -> bool {
    let Some(p) = presented.map(str::trim) else {
        return false;
    };
    if p.is_empty() {
        return false;
    }
    let mut matched = false;
    for k in keys {
        matched |= constant_time_eq(k.as_bytes(), p.as_bytes());
    }
    matched
}

// ---------------------------------------------------------------------------------------
// Settings (pure) — parsed from the Worker environment (wrangler [vars] / secrets).
// ---------------------------------------------------------------------------------------

/// All worker configuration, read from the environment. Non-secret knobs come from wrangler
/// `[vars]`; credentials (`EDGEGUARD_BASIC_PASS`, `EDGEGUARD_API_KEYS`) should be set as Worker
/// *secrets* (`wrangler secret put`).
#[derive(Debug, Clone)]
pub struct Settings {
    /// Origin EdgeGuard fronts, e.g. `https://origin.example.com` (`EDGEGUARD_ORIGIN`).
    pub origin: String,
    pub auth_mode: AuthMode,
    pub realm: String,
    pub basic_user: String,
    pub basic_pass: String,
    pub api_keys: Vec<String>,
    pub api_key_header: String,
    pub hardening: Hardening,
}

impl Settings {
    /// Build [`Settings`] from a key→value getter (so it's testable without a Workers `Env`).
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Settings {
        let d = Hardening::default();
        let hardening = Hardening {
            hsts: get("EDGEGUARD_HSTS")
                .map(|v| parse_bool(&v, d.hsts))
                .unwrap_or(d.hsts),
            csp: get("EDGEGUARD_CSP").unwrap_or(d.csp),
            csp_report_only: get("EDGEGUARD_CSP_REPORT_ONLY")
                .map(|v| parse_bool(&v, d.csp_report_only))
                .unwrap_or(d.csp_report_only),
            csp_report_uri: get("EDGEGUARD_CSP_REPORT_URI").unwrap_or(d.csp_report_uri),
            referrer_policy: get("EDGEGUARD_REFERRER_POLICY").unwrap_or(d.referrer_policy),
            permissions_policy: get("EDGEGUARD_PERMISSIONS_POLICY").unwrap_or(d.permissions_policy),
            frame_options: get("EDGEGUARD_FRAME_OPTIONS").unwrap_or(d.frame_options),
            force_secure_cookies: get("EDGEGUARD_FORCE_SECURE_COOKIES")
                .map(|v| parse_bool(&v, d.force_secure_cookies))
                .unwrap_or(d.force_secure_cookies),
            strip: get("EDGEGUARD_STRIP")
                .map(|v| split_csv(&v))
                .unwrap_or(d.strip),
        };
        Settings {
            origin: get("EDGEGUARD_ORIGIN").unwrap_or_default(),
            auth_mode: get("EDGEGUARD_AUTH_MODE")
                .map(|v| AuthMode::parse(&v))
                .unwrap_or(AuthMode::None),
            realm: get("EDGEGUARD_REALM").unwrap_or_else(|| "EdgeGuard".into()),
            basic_user: get("EDGEGUARD_BASIC_USER").unwrap_or_default(),
            basic_pass: get("EDGEGUARD_BASIC_PASS").unwrap_or_default(),
            api_keys: get("EDGEGUARD_API_KEYS")
                .map(|v| split_csv(&v))
                .unwrap_or_default(),
            api_key_header: get("EDGEGUARD_API_KEY_HEADER").unwrap_or_else(|| "X-API-Key".into()),
            hardening,
        }
    }

    /// Decide whether to admit a request. `auth_header` is the raw `Authorization` value;
    /// `api_key_value` is the value of the configured API-key header (both optional).
    pub fn authorize(&self, auth_header: Option<&str>, api_key_value: Option<&str>) -> AuthOutcome {
        match self.auth_mode {
            AuthMode::None => AuthOutcome::Allow,
            AuthMode::Basic => {
                if check_basic(&self.basic_user, &self.basic_pass, auth_header) {
                    AuthOutcome::Allow
                } else {
                    AuthOutcome::Deny {
                        www_authenticate: Some(format!("Basic realm=\"{}\"", self.realm)),
                    }
                }
            }
            AuthMode::ApiKey => {
                // Accept the key in the configured header, or as `Authorization: Bearer <key>`.
                let presented = api_key_value
                    .map(str::trim)
                    .or_else(|| auth_header.and_then(bearer_token));
                if match_api_key(&self.api_keys, presented) {
                    AuthOutcome::Allow
                } else {
                    AuthOutcome::Deny {
                        www_authenticate: None,
                    }
                }
            }
        }
    }
}

/// Join an origin base with a request path+query, e.g. (`https://o.example`, `/a?b=1`) ->
/// `https://o.example/a?b=1`. Tolerates a trailing slash on the origin and a missing leading
/// slash on the path.
pub fn join_origin(origin: &str, path_and_query: &str) -> String {
    let base = origin.trim_end_matches('/');
    if path_and_query.is_empty() {
        base.to_string()
    } else if path_and_query.starts_with('/') {
        format!("{base}{path_and_query}")
    } else {
        format!("{base}/{path_and_query}")
    }
}

/// Parse a boolean-ish env value, returning `default` for anything unrecognized.
fn parse_bool(s: &str, default: bool) -> bool {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

/// Split a comma-separated env value, trimming entries and dropping empties.
fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------------------
// WASM fetch entrypoint (Cloudflare Workers). Glue only — all decisions live in the pure
// functions above. Compiled to wasm by `worker-build`; proven only against a live deploy.
// ---------------------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use js_sys::Uint8Array;
    use worker::*;

    /// Read a value from the environment, preferring a secret over a plain var.
    fn env_get(env: &Env, key: &str) -> Option<String> {
        if let Ok(s) = env.secret(key) {
            return Some(s.to_string());
        }
        if let Ok(v) = env.var(key) {
            return Some(v.to_string());
        }
        None
    }

    #[event(fetch)]
    pub async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
        let settings = Settings::from_env(|k| env_get(&env, k));

        if settings.origin.is_empty() {
            return Response::error("EdgeGuard worker: EDGEGUARD_ORIGIN is not configured", 500);
        }

        // 1) Edge-auth gate (decided by the pure `authorize`).
        let auth_header = req.headers().get("authorization").ok().flatten();
        let api_key_value = req.headers().get(&settings.api_key_header).ok().flatten();
        if let AuthOutcome::Deny { www_authenticate } =
            settings.authorize(auth_header.as_deref(), api_key_value.as_deref())
        {
            let mut resp = Response::error("Unauthorized", 401)?;
            if let Some(c) = www_authenticate {
                resp.headers_mut().set("WWW-Authenticate", &c)?;
            }
            return Ok(resp);
        }

        // 2) Forward to the origin, preserving method/headers/body.
        let method = req.method();
        let has_body = matches!(
            method,
            Method::Post | Method::Put | Method::Patch | Method::Delete
        );

        let url = req.url()?;
        let mut path_and_query = url.path().to_string();
        if let Some(q) = url.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }
        let target = join_origin(&settings.origin, &path_and_query);

        // `Headers` mutates via interior mutability (set/delete take &self), so no `mut` needed.
        let fwd_headers = req.headers().clone();
        // Drop the inbound Host so the fetch sets it from the target URL; mark the proto.
        fwd_headers.delete("host").ok();
        fwd_headers.set("x-forwarded-proto", "https").ok();

        let mut init = RequestInit::new();
        init.with_method(method).with_headers(fwd_headers);
        if has_body {
            let bytes = req.bytes().await?;
            if !bytes.is_empty() {
                // Manual bytes -> JsValue conversion (the body field is Option<JsValue>).
                let arr = Uint8Array::from(bytes.as_slice());
                init.with_body(Some(arr.into()));
            }
        }

        let outbound = Request::new_with_init(&target, &init)?;
        let mut resp = Fetch::Request(outbound).send().await?;

        // 3) Harden the response (headers + cookies + strip) using the pure helpers.
        let status = resp.status_code();
        let mut headers = resp.headers().clone();
        let body = resp.bytes().await?;
        harden_headers(&mut headers, &settings.hardening);

        Ok(Response::from_bytes(body)?
            .with_status(status)
            .with_headers(headers))
    }

    /// Apply the hardening policy to a response `Headers`: inject the security header set, strip
    /// leaky headers, and rewrite `Set-Cookie` with `Secure; HttpOnly; SameSite`.
    fn harden_headers(headers: &mut Headers, h: &Hardening) {
        for (name, value) in h.security_headers() {
            headers.set(name, &value).ok();
        }
        for name in &h.strip {
            headers.delete(name).ok();
        }
        if h.force_secure_cookies {
            // `get_all` returns each Set-Cookie separately (unlike `get`, which coalesces).
            if let Ok(cookies) = headers.get_all("set-cookie") {
                if !cookies.is_empty() {
                    headers.delete("set-cookie").ok();
                    for c in cookies {
                        headers.append("set-cookie", &harden_cookie(&c)).ok();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn b64_basic(user: &str, pass: &str) -> String {
        format!("Basic {}", B64.encode(format!("{user}:{pass}")))
    }

    #[test]
    fn security_headers_match_defaults() {
        let got = Hardening::default().security_headers();
        let map: HashMap<&str, String> = got.iter().map(|(n, v)| (*n, v.clone())).collect();
        assert_eq!(map["X-Content-Type-Options"], "nosniff");
        assert_eq!(map["X-Frame-Options"], "DENY");
        assert_eq!(map["Referrer-Policy"], "no-referrer");
        assert_eq!(map["Content-Security-Policy"], "default-src 'self'");
        assert_eq!(
            map["Strict-Transport-Security"],
            "max-age=63072000; includeSubDomains"
        );
        assert!(!map.contains_key("Content-Security-Policy-Report-Only"));
    }

    #[test]
    fn security_headers_report_only_and_toggles() {
        let h = Hardening {
            hsts: false,
            frame_options: String::new(),
            csp_report_only: true,
            csp_report_uri: "/__edgeguard/csp-report".into(),
            ..Hardening::default()
        };
        let map: HashMap<&str, String> = h
            .security_headers()
            .iter()
            .map(|(n, v)| (*n, v.clone()))
            .collect();
        assert!(!map.contains_key("Strict-Transport-Security"));
        assert!(!map.contains_key("X-Frame-Options"));
        assert!(!map.contains_key("Content-Security-Policy"));
        assert_eq!(
            map["Content-Security-Policy-Report-Only"],
            "default-src 'self'; report-uri /__edgeguard/csp-report"
        );
    }

    #[test]
    fn harden_cookie_adds_missing_flags_only() {
        let out = harden_cookie("sid=abc");
        assert!(
            out.contains("; Secure") && out.contains("; HttpOnly") && out.contains("SameSite=Lax")
        );
        // Existing attributes aren't duplicated or overridden.
        let out = harden_cookie("sid=abc; HttpOnly; SameSite=Strict");
        assert_eq!(out.matches("HttpOnly").count(), 1);
        assert!(out.contains("SameSite=Strict") && !out.contains("SameSite=Lax"));
        assert!(out.contains("; Secure"));
        // A value resembling an attribute is not mistaken for one.
        assert!(harden_cookie("session=securetoken").contains("; Secure"));
    }

    #[test]
    fn constant_time_eq_handles_lengths() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn auth_mode_parse() {
        assert_eq!(AuthMode::parse("basic"), AuthMode::Basic);
        assert_eq!(AuthMode::parse("APIKEY"), AuthMode::ApiKey);
        assert_eq!(AuthMode::parse("none"), AuthMode::None);
        assert_eq!(AuthMode::parse("bogus"), AuthMode::None);
    }

    #[test]
    fn check_basic_accepts_correct_rejects_bad() {
        assert!(check_basic(
            "admin",
            "s3cret",
            Some(&b64_basic("admin", "s3cret"))
        ));
        assert!(!check_basic(
            "admin",
            "s3cret",
            Some(&b64_basic("admin", "wrong"))
        ));
        assert!(!check_basic(
            "admin",
            "s3cret",
            Some(&b64_basic("ghost", "s3cret"))
        ));
        assert!(!check_basic("admin", "s3cret", Some("Bearer x")));
        assert!(!check_basic("admin", "s3cret", None));
        // Unconfigured credential never authenticates.
        assert!(!check_basic("", "", Some(&b64_basic("", ""))));
    }

    #[test]
    fn match_api_key_constant_set() {
        let keys = vec!["sk_live_abc".to_string(), "sk_live_def".to_string()];
        assert!(match_api_key(&keys, Some("sk_live_abc")));
        assert!(match_api_key(&keys, Some(" sk_live_def ")));
        assert!(!match_api_key(&keys, Some("nope")));
        assert!(!match_api_key(&keys, None));
        assert!(!match_api_key(&keys, Some("")));
        assert!(!match_api_key(&[], Some("anything")));
    }

    #[test]
    fn authorize_covers_each_mode() {
        // none -> always allow
        let s = Settings::from_env(|_| None);
        assert_eq!(s.authorize(None, None), AuthOutcome::Allow);

        // basic -> challenge on failure, allow on success
        let mut env = HashMap::new();
        env.insert("EDGEGUARD_AUTH_MODE", "basic");
        env.insert("EDGEGUARD_BASIC_USER", "admin");
        env.insert("EDGEGUARD_BASIC_PASS", "s3cret");
        env.insert("EDGEGUARD_REALM", "Test");
        let s = Settings::from_env(|k| env.get(k).map(|v| v.to_string()));
        assert_eq!(
            s.authorize(None, None),
            AuthOutcome::Deny {
                www_authenticate: Some("Basic realm=\"Test\"".into())
            }
        );
        assert_eq!(
            s.authorize(Some(&b64_basic("admin", "s3cret")), None),
            AuthOutcome::Allow
        );

        // apikey -> via header and via bearer; deny has no challenge
        let mut env = HashMap::new();
        env.insert("EDGEGUARD_AUTH_MODE", "apikey");
        env.insert("EDGEGUARD_API_KEYS", "k1, k2");
        let s = Settings::from_env(|k| env.get(k).map(|v| v.to_string()));
        assert_eq!(s.authorize(None, Some("k1")), AuthOutcome::Allow);
        assert_eq!(s.authorize(Some("Bearer k2"), None), AuthOutcome::Allow);
        assert_eq!(
            s.authorize(None, Some("nope")),
            AuthOutcome::Deny {
                www_authenticate: None
            }
        );
    }

    #[test]
    fn settings_from_env_defaults_and_overrides() {
        // Defaults when nothing is set.
        let s = Settings::from_env(|_| None);
        assert_eq!(s.auth_mode, AuthMode::None);
        assert_eq!(s.api_key_header, "X-API-Key");
        assert!(s.hardening.hsts);
        assert_eq!(s.hardening.strip, vec!["Server", "X-Powered-By"]);

        // Overrides applied.
        let mut env = HashMap::new();
        env.insert("EDGEGUARD_ORIGIN", "https://origin.example.com/");
        env.insert("EDGEGUARD_HSTS", "false");
        env.insert("EDGEGUARD_CSP", "default-src 'none'");
        env.insert("EDGEGUARD_STRIP", "Server, X-Powered-By, X-Aspnet-Version");
        let s = Settings::from_env(|k| env.get(k).map(|v| v.to_string()));
        assert_eq!(s.origin, "https://origin.example.com/");
        assert!(!s.hardening.hsts);
        assert_eq!(s.hardening.csp, "default-src 'none'");
        assert_eq!(s.hardening.strip.len(), 3);
    }

    #[test]
    fn join_origin_variants() {
        assert_eq!(
            join_origin("https://o.example", "/a?b=1"),
            "https://o.example/a?b=1"
        );
        // trailing slash on origin tolerated
        assert_eq!(
            join_origin("https://o.example/", "/a"),
            "https://o.example/a"
        );
        // missing leading slash tolerated
        assert_eq!(join_origin("https://o.example", "a"), "https://o.example/a");
        // empty path
        assert_eq!(join_origin("https://o.example/", ""), "https://o.example");
    }
}
