//! CORS (Cross-Origin Resource Sharing).
//!
//! A drop-in front door is frequently deployed in front of an app whose browser frontend lives
//! on a *different* origin (a separate static host, a preview deployment, `localhost:5173` during
//! development). Browsers block those cross-origin `fetch`/`XHR` calls unless the server answers
//! with the right `Access-Control-*` headers, so EdgeGuard grows a small, explicit CORS policy.
//!
//! Two responsibilities, both driven by [`CorsPolicy`] (held in the hot-swappable [`Runtime`],
//! `None` when `cors.enabled = false`):
//!   1. **Preflight** — answer a browser's `OPTIONS` preflight (`Origin` +
//!      `Access-Control-Request-Method`) directly with `204` + the allow headers. This happens
//!      *before* authentication in the request pipeline, because a preflight carries no
//!      credentials; gating it behind auth would make every cross-origin call fail.
//!   2. **Decoration** — add `Access-Control-Allow-Origin` (and friends) to the *actual*
//!      response so the browser exposes it to the calling page.
//!
//! Security note: a wildcard origin (`"*"`) cannot be combined with `allow_credentials = true`
//! — the Fetch spec forbids it and browsers ignore the combination — so [`CorsPolicy::build`]
//! rejects it at startup/reload rather than emitting a policy that silently doesn't work.

use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Response, StatusCode},
};

use crate::config::{parse_duration, CorsCfg};

/// A compiled CORS policy. Built once from [`CorsCfg`]; the string header values are
/// precomputed so the request path only does cheap lookups and inserts.
pub struct CorsPolicy {
    /// `allow_origins` contained `"*"`. With credentials this is rejected at build, so when this
    /// is true credentials are necessarily off and we can emit the cacheable literal `*`.
    any_origin: bool,
    /// Explicit allowed origins, lowercased for a case-insensitive compare.
    origins: Vec<String>,
    /// Precomputed `Access-Control-Allow-Methods` value.
    allow_methods: HeaderValue,
    /// Precomputed `Access-Control-Allow-Headers`; `None` => reflect the request's
    /// `Access-Control-Request-Headers`.
    allow_headers: Option<HeaderValue>,
    /// Precomputed `Access-Control-Expose-Headers`; `None` => don't send it.
    expose_headers: Option<HeaderValue>,
    allow_credentials: bool,
    /// `Access-Control-Max-Age` in seconds; `None` => omit the header.
    max_age: Option<HeaderValue>,
}

const DEFAULT_METHODS: &str = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD";

impl CorsPolicy {
    /// Compile the policy, or `Ok(None)` when CORS is disabled. Fails fast on an incoherent
    /// policy (credentialed wildcard, enabled-but-no-origins, bad `max_age`) so the mistake
    /// surfaces at startup/reload like any other bad config — not as silently-missing CORS
    /// headers at request time.
    pub fn build(cfg: &CorsCfg) -> Result<Option<CorsPolicy>> {
        if !cfg.enabled {
            return Ok(None);
        }
        anyhow::ensure!(
            !cfg.allow_origins.is_empty(),
            "cors.enabled = true requires at least one cors.allow_origins entry (use [\"*\"] for any)"
        );
        let any_origin = cfg.allow_origins.iter().any(|o| o.trim() == "*");
        anyhow::ensure!(
            !(any_origin && cfg.allow_credentials),
            "cors.allow_credentials = true cannot be combined with a \"*\" origin (the Fetch spec \
             forbids credentialed wildcard CORS); list explicit origins instead"
        );

        let origins = cfg
            .allow_origins
            .iter()
            .map(|o| o.trim())
            .filter(|o| *o != "*")
            .map(|o| o.to_ascii_lowercase())
            .collect();

        let methods = if cfg.allow_methods.is_empty() {
            DEFAULT_METHODS.to_string()
        } else {
            cfg.allow_methods.join(", ")
        };
        let allow_methods =
            HeaderValue::from_str(&methods).context("cors.allow_methods has an invalid value")?;

        let allow_headers = if cfg.allow_headers.is_empty() {
            None
        } else {
            Some(
                HeaderValue::from_str(&cfg.allow_headers.join(", "))
                    .context("cors.allow_headers has an invalid value")?,
            )
        };
        let expose_headers = if cfg.expose_headers.is_empty() {
            None
        } else {
            Some(
                HeaderValue::from_str(&cfg.expose_headers.join(", "))
                    .context("cors.expose_headers has an invalid value")?,
            )
        };

        let secs = parse_duration(&cfg.max_age)
            .context("cors.max_age")?
            .as_secs();
        let max_age = (secs > 0)
            .then(|| HeaderValue::from_str(&secs.to_string()).expect("digits are a valid header"));

        Ok(Some(CorsPolicy {
            any_origin,
            origins,
            allow_methods,
            allow_headers,
            expose_headers,
            allow_credentials: cfg.allow_credentials,
            max_age,
        }))
    }

    /// The `Access-Control-Allow-Origin` value to send for a request from `origin`, or `None`
    /// when the origin isn't allowed (the browser then blocks the page from reading the
    /// response, which is the desired outcome).
    fn allow_origin_value(&self, origin: &str) -> Option<HeaderValue> {
        let origin = origin.trim();
        if self.any_origin {
            return Some(HeaderValue::from_static("*"));
        }
        let lower = origin.to_ascii_lowercase();
        if self.origins.contains(&lower) {
            HeaderValue::from_str(origin).ok()
        } else {
            None
        }
    }

    /// Common to preflight and actual responses: set `Allow-Origin`, the credentials flag, and —
    /// when the allowed origin echoes the request (an explicit list, not the constant `*`) — a
    /// `Vary: Origin` so a shared cache can't serve one origin's headers to another.
    fn set_origin(&self, h: &mut HeaderMap, allow: HeaderValue) {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
        if self.allow_credentials {
            h.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        if !self.any_origin {
            append_vary_origin(h);
        }
    }

    /// If `headers` describe a CORS **preflight** (an `OPTIONS` with `Origin` +
    /// `Access-Control-Request-Method`), build the `204` response to answer it with. Returns
    /// `None` when it isn't a preflight, so the caller falls through to normal handling. When the
    /// origin isn't allowed we still return a `204`, just without the CORS headers — the browser
    /// then refuses the cross-origin call.
    ///
    /// The caller must only invoke this for `OPTIONS` requests; the `Access-Control-Request-Method`
    /// presence check distinguishes a real preflight from a plain `OPTIONS`.
    pub fn preflight_response(&self, headers: &HeaderMap) -> Option<Response<Body>> {
        let origin = headers.get(header::ORIGIN)?.to_str().ok()?;
        headers.get(header::ACCESS_CONTROL_REQUEST_METHOD)?;

        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::NO_CONTENT;

        if let Some(allow) = self.allow_origin_value(origin) {
            let h = resp.headers_mut();
            self.set_origin(h, allow);
            h.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                self.allow_methods.clone(),
            );
            // Advertised request headers: the configured list, or reflect what the browser asked
            // for (so a permissive default doesn't have to enumerate every header).
            let allow_headers = self.allow_headers.clone().or_else(|| {
                headers
                    .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
                    .filter(|v| !v.is_empty())
                    .cloned()
            });
            if let Some(v) = allow_headers {
                h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v);
            }
            if let Some(age) = &self.max_age {
                h.insert(header::ACCESS_CONTROL_MAX_AGE, age.clone());
            }
        }
        Some(resp)
    }

    /// Add the CORS headers to an *actual* (non-preflight) response, based on the request's
    /// `Origin`. A no-op when the request has no `Origin` (not a cross-origin browser request) or
    /// the origin isn't allowed.
    pub fn decorate(&self, req_headers: &HeaderMap, resp: &mut Response<Body>) {
        if let Some(origin) = req_headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        {
            self.decorate_origin(origin, resp);
        }
    }

    /// Like [`decorate`](Self::decorate), but given the request `Origin` directly. A no-op when the
    /// origin isn't allowed. Idempotent, so it's safe to call on a response that may already carry
    /// CORS headers (e.g. a preflight). Used to decorate **every** response — including
    /// EdgeGuard-generated `401`/`403`/`429` — so an allowed browser origin sees the real status
    /// rather than a generic CORS failure.
    pub fn decorate_origin(&self, origin: &str, resp: &mut Response<Body>) {
        let Some(allow) = self.allow_origin_value(origin) else {
            return;
        };
        let h = resp.headers_mut();
        self.set_origin(h, allow);
        if let Some(expose) = &self.expose_headers {
            h.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone());
        }
    }
}

/// Append `Origin` to the response `Vary` header without duplicating it. Multiple `Vary` values
/// are valid, but de-duping keeps the output tidy and avoids unbounded growth across hops.
fn append_vary_origin(h: &mut HeaderMap) {
    let already = h.get_all(header::VARY).iter().any(|v| {
        v.to_str()
            .map(|s| {
                s.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("origin"))
            })
            .unwrap_or(false)
    });
    if !already {
        h.append(header::VARY, HeaderValue::from_static("Origin"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;

    fn policy(cfg: CorsCfg) -> CorsPolicy {
        CorsPolicy::build(&cfg).unwrap().unwrap()
    }

    fn req(origin: &str, extra: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        for (n, v) in extra {
            h.insert(
                HeaderName::from_static(n),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn disabled_builds_to_none() {
        assert!(CorsPolicy::build(&CorsCfg::default()).unwrap().is_none());
    }

    #[test]
    fn enabled_without_origins_is_rejected() {
        let cfg = CorsCfg {
            enabled: true,
            ..Default::default()
        };
        assert!(CorsPolicy::build(&cfg).is_err());
    }

    #[test]
    fn credentialed_wildcard_is_rejected() {
        let cfg = CorsCfg {
            enabled: true,
            allow_origins: vec!["*".into()],
            allow_credentials: true,
            ..Default::default()
        };
        assert!(CorsPolicy::build(&cfg).is_err());
    }

    #[test]
    fn wildcard_returns_star_and_no_vary() {
        let p = policy(CorsCfg {
            enabled: true,
            allow_origins: vec!["*".into()],
            ..Default::default()
        });
        let mut resp = Response::new(Body::empty());
        p.decorate(&req("https://anything.example", &[]), &mut resp);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        assert!(resp.headers().get(header::VARY).is_none());
    }

    #[test]
    fn explicit_origin_echoes_allowed_and_blocks_others() {
        let p = policy(CorsCfg {
            enabled: true,
            allow_origins: vec!["https://app.example.com".into()],
            allow_credentials: true,
            ..Default::default()
        });
        // Allowed origin: echoed back, credentials flag set, Vary: Origin present.
        let mut ok = Response::new(Body::empty());
        p.decorate(&req("https://app.example.com", &[]), &mut ok);
        assert_eq!(
            ok.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example.com"
        );
        assert_eq!(
            ok.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );
        assert_eq!(ok.headers().get(header::VARY).unwrap(), "Origin");

        // Disallowed origin: no CORS headers, so the browser blocks it.
        let mut bad = Response::new(Body::empty());
        p.decorate(&req("https://evil.example", &[]), &mut bad);
        assert!(bad
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }

    #[test]
    fn preflight_reflects_requested_headers_when_unset() {
        let p = policy(CorsCfg {
            enabled: true,
            allow_origins: vec!["https://app.example.com".into()],
            ..Default::default()
        });
        let h = req(
            "https://app.example.com",
            &[
                ("access-control-request-method", "POST"),
                ("access-control-request-headers", "x-custom, content-type"),
            ],
        );
        let resp = p.preflight_response(&h).expect("is a preflight");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap(),
            DEFAULT_METHODS
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                .unwrap(),
            "x-custom, content-type"
        );
        assert_eq!(
            resp.headers().get(header::ACCESS_CONTROL_MAX_AGE).unwrap(),
            "600"
        );
    }

    #[test]
    fn plain_options_is_not_a_preflight() {
        let p = policy(CorsCfg {
            enabled: true,
            allow_origins: vec!["*".into()],
            ..Default::default()
        });
        // No Access-Control-Request-Method => not a preflight, fall through to normal handling.
        assert!(p
            .preflight_response(&req("https://app.example.com", &[]))
            .is_none());
    }
}
