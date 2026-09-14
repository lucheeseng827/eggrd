//! Access-log sanitisation — keeping credentials out of the request line.
//!
//! The access log records `path?query` for every request. That is the single most useful field in
//! it and the easiest place to leak a secret: password-reset links, magic-login links, presigned
//! URLs, `?api_key=…`, `?email=…` and OAuth `?code=…` all travel in the query string, and an access
//! log is the most-copied artifact a service produces — scraped, shipped to a SIEM, retained for
//! months, and readable by people who were never meant to hold the credential.
//!
//! A proxy that advertises DLP should not be the component that writes them to disk. So the request
//! target is sanitised before it reaches the log line, on two independent signals:
//!
//!   * **By name** — a parameter whose key is a known credential/PII name ([`SENSITIVE_KEYS`], plus
//!     whatever the operator adds). Catches the common cases exactly.
//!   * **By shape** — a value that looks like a credential regardless of what it is called: a JWT,
//!     or a long high-entropy token. Catches `?t=eyJhbGciOi…`, which a name list never will.
//!
//! Neither is complete on its own and the pair is not complete either; `Drop` is there for
//! deployments that would rather lose the debugging value than reason about it. What is *not*
//! sanitised is the path itself — `/reset/<token>` is indistinguishable from `/users/<id>` without
//! knowing the application's routes, and guessing would mangle ordinary paths. Applications that put
//! secrets in path segments need `Drop` plus care.

use serde::{Deserialize, Serialize};

/// What to do with the query string in the access log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryLogMode {
    /// Redact values that are sensitive by name or by shape; keep the rest. The default: an access
    /// log stays useful for debugging without carrying credentials.
    #[default]
    Redact,
    /// Log the path only. The query is replaced by `?<dropped>` when one was present, so the log
    /// still shows that parameters existed.
    Drop,
    /// Log the target verbatim. Opt-in, for a deployment that has decided its logs are as sensitive
    /// as its traffic and is protecting them accordingly.
    Full,
}

/// Query-parameter names treated as credentials or personal data.
///
/// Matched case-insensitively as a **substring**, so `api_key`, `X-Api-Key` and `apikey_v2` all hit
/// on `key`. Substring matching over-redacts (`monkey=1` is caught by `key`); in an access log that
/// is the right direction to be wrong in.
pub const SENSITIVE_KEYS: &[&str] = &[
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "credential",
    "session",
    "sig",
    "signature",
    "code",
    "state",
    "nonce",
    "assertion",
    "email",
    "phone",
    "ssn",
];

/// The replacement written in place of a redacted value. Fixed, not derived from the value, so the
/// log leaks neither the secret nor its length.
const REDACTED: &str = "<redacted>";

/// Percent- and plus-decode a query component, for **classification only**.
///
/// Query components arrive encoded, and both signals below match on the decoded meaning:
/// `?%74%6f%6b%65%6e=secret` is `?token=secret` to every recipient, but matches no entry in
/// [`SENSITIVE_KEYS`] as written. A JWT with its dots encoded as `%2E` slips past the shape check
/// the same way. Classifying on the raw text alone therefore redacts exactly the credentials that
/// were not obfuscated.
///
/// Returns borrowed when there is nothing to decode, which is the overwhelming majority of
/// components. Invalid UTF-8 in the decoded bytes is replaced rather than rejected — this feeds a
/// substring match, and a lossy character cannot make a sensitive name look innocuous.
fn decode_component(s: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    if !s.contains('%') && !s.contains('+') {
        return Cow::Borrowed(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    // A stray `%` that is not an escape: keep it literally.
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

/// Whether a parameter name is sensitive, given the operator's additions.
///
/// Checked against the raw text **and** its decoded form: either tripping is enough. Encoding is a
/// way to hide a name from a substring match, and in a log the right direction to be wrong in is
/// redacting too much.
fn key_is_sensitive(key: &str, extra: &[String]) -> bool {
    raw_key_is_sensitive(key, extra) || raw_key_is_sensitive(&decode_component(key), extra)
}

fn raw_key_is_sensitive(key: &str, extra: &[String]) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|k| lower.contains(k))
        || extra
            .iter()
            .any(|k| !k.is_empty() && lower.contains(&k.to_ascii_lowercase()))
}

/// Whether a value *looks* like a credential whatever it is called.
///
/// Two shapes, both chosen to be cheap and to have a low false-positive rate on ordinary query
/// values (page numbers, slugs, dates, sort keys):
///   * a JWT — three base64url segments separated by dots, with a plausible header segment;
///   * a long unbroken run of token alphabet — 24+ chars of base64url/hex with no separators. Real
///     query values that long are usually opaque identifiers, and redacting those costs little.
fn value_looks_like_a_credential(value: &str) -> bool {
    raw_value_looks_like_a_credential(value)
        || raw_value_looks_like_a_credential(&decode_component(value))
}

fn raw_value_looks_like_a_credential(value: &str) -> bool {
    if looks_like_jwt(value) {
        return true;
    }
    value.len() >= 24
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        // A long value with no digits is far more likely to be a slug or a sentence than a token.
        && value.bytes().any(|b| b.is_ascii_digit())
}

fn looks_like_jwt(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    // `eyJ` is base64url for `{"`, which every JWT header starts with.
    h.starts_with("eyJ")
        && h.len() >= 8
        && !p.is_empty()
        && !s.is_empty()
        && [h, p, s].iter().all(|seg| {
            seg.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Sanitise a request target (`/path?a=1&b=2`) for the access log.
///
/// Returns the path unchanged when there is no query string, so the common case allocates nothing
/// beyond the borrow it is handed.
pub fn sanitize_target<'a>(
    target: &'a str,
    mode: QueryLogMode,
    extra_keys: &[String],
) -> std::borrow::Cow<'a, str> {
    use std::borrow::Cow;
    if mode == QueryLogMode::Full {
        return Cow::Borrowed(target);
    }
    let Some((path, query)) = target.split_once('?') else {
        return Cow::Borrowed(target);
    };
    if mode == QueryLogMode::Drop {
        return Cow::Owned(format!("{path}?<dropped>"));
    }
    let mut out = String::with_capacity(target.len());
    out.push_str(path);
    out.push('?');
    for (i, pair) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            // A bare flag (`?debug`) carries no value to leak.
            None => out.push_str(pair),
            Some((k, v)) => {
                out.push_str(k);
                out.push('=');
                if v.is_empty() {
                    continue;
                }
                if key_is_sensitive(k, extra_keys) || value_looks_like_a_credential(v) {
                    out.push_str(REDACTED);
                } else {
                    out.push_str(v);
                }
            }
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red(target: &str) -> String {
        sanitize_target(target, QueryLogMode::Redact, &[]).into_owned()
    }

    #[test]
    fn a_target_without_a_query_is_untouched_and_unallocated() {
        let out = sanitize_target("/a/b/c", QueryLogMode::Redact, &[]);
        assert_eq!(out, "/a/b/c");
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn sensitive_names_are_redacted_and_ordinary_ones_kept() {
        assert_eq!(red("/x?page=2&sort=name"), "/x?page=2&sort=name");
        assert_eq!(red("/x?api_key=abc123"), "/x?api_key=<redacted>");
        assert_eq!(red("/x?token=abc"), "/x?token=<redacted>");
        assert_eq!(red("/x?email=a@b.com"), "/x?email=<redacted>");
        assert_eq!(
            red("/x?code=xyz&state=q"),
            "/x?code=<redacted>&state=<redacted>"
        );
        // Mixed: the useful half of the line survives.
        assert_eq!(
            red("/search?q=rust&session=deadbeef&page=3"),
            "/search?q=rust&session=<redacted>&page=3"
        );
    }

    #[test]
    fn name_matching_is_case_insensitive_and_substring() {
        assert_eq!(red("/x?X-Api-Key=v"), "/x?X-Api-Key=<redacted>");
        assert_eq!(red("/x?refreshToken=v"), "/x?refreshToken=<redacted>");
        assert_eq!(red("/x?ACCESS_TOKEN=v"), "/x?ACCESS_TOKEN=<redacted>");
    }

    #[test]
    fn a_jwt_is_redacted_whatever_the_parameter_is_called() {
        // The case a name list cannot catch, and the reason shape matching exists.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123";
        assert_eq!(red(&format!("/x?t={jwt}")), "/x?t=<redacted>");
    }

    #[test]
    fn a_long_opaque_value_is_redacted_but_ordinary_values_are_not() {
        assert_eq!(red("/x?ref=aB3dE5fG7hJ9kL1mN3pQ5rS7"), "/x?ref=<redacted>");
        // Prose, slugs, dates and ids stay readable — the point of not simply dropping everything.
        assert_eq!(
            red("/x?q=how-do-i-configure-the-proxy"),
            "/x?q=how-do-i-configure-the-proxy"
        );
        assert_eq!(
            red("/x?from=2026-01-01&to=2026-02-01"),
            "/x?from=2026-01-01&to=2026-02-01"
        );
        assert_eq!(red("/x?id=12345"), "/x?id=12345");
    }

    #[test]
    fn redaction_reveals_neither_the_value_nor_its_length() {
        let short = red("/x?token=a");
        let long = red(&format!("/x?token={}", "a".repeat(500)));
        assert_eq!(short, long);
    }

    #[test]
    fn empty_values_and_bare_flags_are_preserved() {
        assert_eq!(red("/x?debug"), "/x?debug");
        assert_eq!(red("/x?token="), "/x?token=");
        assert_eq!(red("/x?a=1&debug&b=2"), "/x?a=1&debug&b=2");
    }

    #[test]
    fn operator_supplied_names_are_honoured() {
        let extra = vec!["accountnumber".to_string()];
        assert_eq!(
            sanitize_target("/x?accountNumber=99", QueryLogMode::Redact, &extra),
            "/x?accountNumber=<redacted>"
        );
        // An empty entry must not match everything.
        let empty = vec![String::new()];
        assert_eq!(
            sanitize_target("/x?page=2", QueryLogMode::Redact, &empty),
            "/x?page=2"
        );
    }

    #[test]
    fn drop_keeps_the_path_and_the_fact_that_parameters_existed() {
        assert_eq!(
            sanitize_target("/x?token=a&b=2", QueryLogMode::Drop, &[]),
            "/x?<dropped>"
        );
        assert_eq!(sanitize_target("/x", QueryLogMode::Drop, &[]), "/x");
    }

    #[test]
    fn full_is_verbatim() {
        assert_eq!(
            sanitize_target("/x?token=supersecret", QueryLogMode::Full, &[]),
            "/x?token=supersecret"
        );
    }

    /// The reference config is what an operator copies; a `[log]` section it documents but the
    /// code cannot parse fails at boot, after deploy.
    #[test]
    fn the_shipped_reference_config_parses_the_log_section() {
        let cfg: crate::config::Config = toml::from_str(include_str!("../edgeguard.toml"))
            .expect("edgeguard.toml must deserialize into Config");
        assert_eq!(cfg.log.query, QueryLogMode::Redact);
        assert!(cfg.log.redact_params.is_empty());
    }

    #[test]
    fn the_default_mode_redacts() {
        // A safe default is the whole point: an operator who never reads this config still does not
        // ship credentials to their SIEM.
        assert_eq!(QueryLogMode::default(), QueryLogMode::Redact);
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::*;

    fn red(target: &str) -> String {
        sanitize_target(target, QueryLogMode::Redact, &[]).into_owned()
    }

    #[test]
    fn a_percent_encoded_name_does_not_slip_past_the_name_list() {
        // `%74%6f%6b%65%6e` is `token`. Classifying on the raw text alone would redact the
        // credentials nobody bothered to obfuscate and log the ones they did.
        assert_eq!(
            red("/x?%74%6f%6b%65%6e=secret"),
            "/x?%74%6f%6b%65%6e=<redacted>"
        );
        assert_eq!(red("/x?api%5Fkey=secret"), "/x?api%5Fkey=<redacted>");
        // Mixed case in the escape is still an escape.
        assert_eq!(
            red("/x?%50%61%73%73%77%6F%72%64=hunter2"),
            "/x?%50%61%73%73%77%6F%72%64=<redacted>"
        );
    }

    #[test]
    fn a_percent_encoded_jwt_is_still_caught_by_shape() {
        // `%2E` is `.`, so the three-segment shape only appears after decoding.
        let jwt = "eyJhbGciOiJIUzI1NiJ9%2EeyJzdWIiOiIxIn0%2Eabc-_123";
        assert_eq!(red(&format!("/x?t={jwt}")), "/x?t=<redacted>");
    }

    #[test]
    fn plus_is_treated_as_a_space_when_classifying() {
        // Form encoding: `access+token` is `access token`, which still contains "token".
        assert_eq!(red("/x?access+token=v"), "/x?access+token=<redacted>");
    }

    #[test]
    fn decoding_does_not_make_ordinary_values_look_sensitive() {
        // The redaction must still leave a usable log behind.
        assert_eq!(
            red("/x?q=hello%20world&page=2"),
            "/x?q=hello%20world&page=2"
        );
        assert_eq!(red("/x?name=Jos%C3%A9"), "/x?name=Jos%C3%A9");
    }

    #[test]
    fn a_stray_percent_is_not_an_escape_and_does_not_panic() {
        // Malformed input reaches this from the network; it must degrade, not crash.
        for t in ["/x?q=100%", "/x?q=%zz", "/x?%=1", "/x?q=%2", "/x?%GG%=v"] {
            let _ = red(t);
        }
        assert_eq!(decode_component("100%"), "100%");
        assert_eq!(decode_component("%zz"), "%zz");
    }

    #[test]
    fn the_output_keeps_the_original_encoding() {
        // Only classification decodes. Rewriting the logged text would change what the request
        // actually said, which is the one thing an access log is for.
        assert_eq!(red("/x?q=a%20b"), "/x?q=a%20b");
    }
}
