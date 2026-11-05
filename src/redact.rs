//! Credentials out of what the edge prints.
//!
//! A configured URL may carry credentials in its userinfo (`http://user:pass@app:8080`). These
//! go through [`userinfo`] or [`display`], which replace the userinfo with `***` and keep the
//! scheme and host:
//!
//! - upstream and pool target URLs in log lines (`upstream`, failover, upgrade), pool load
//!   errors, and the upstream error text (`upstream::error_chain`) that reaches logs and the
//!   `/__edgeguard/upstreams` status page; the send-failure warnings of log shipping, span
//!   shipping, the OTLP metrics push, LLM telemetry and the alert webhook go through it too;
//! - `doctor` output and the startup error `main` prints;
//! - Redis URL errors (rate limiter, budgets);
//! - the log-ship, OTLP metrics, tracing and ACME directory URLs logged at startup;
//! - the egress proxy URL in outbound-client logs and errors;
//! - the `error` field of warnings from the control plane, JWKS, ACME, certificate store,
//!   policy and reload code, whose errors may quote a URL.
//!
//! [`without_userinfo`] removes the userinfo from a pool target's URL before the upstream client
//! is built, so its own trace logs, and labels taken from the target, never hold it.

use std::borrow::Cow;
use std::fmt::Display;

/// `text` with the userinfo of every URL in it replaced by `***`: `http://user:pass@host:8080/x`
/// becomes `http://***@host:8080/x`. Works on a bare URL and on an error message quoting one.
///
/// A URL is found by its `://` and taken to run to the next whitespace (or the end). Everything
/// from the `://` up to the **last** `@` in that run is hidden. That over-redacts rather than
/// leaks: a password with unencoded sub-delims (`;`, `,`, `'`, `)`, legal in userinfo) or with
/// characters that are not legal there but get written anyway (`/`, `?`, `#`, `"`, `` ` ``, `<`,
/// `>`) is hidden whole. A run with no `@` goes on to the next `@` on the same line, if one comes
/// before another `://`, so a password with whitespace in it is hidden too. The cost is that a
/// path with an `@` in it, or a later `@` on the line (an email address after a clean URL), is
/// hidden with it. Text with no credentials comes back borrowed.
pub fn userinfo(text: &str) -> Cow<'_, str> {
    if !text.contains("://") || !text.contains('@') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut changed = false;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let mut end = tail.find(char::is_whitespace).unwrap_or(tail.len());
        if !tail[..end].contains('@') {
            // A password with whitespace in it (`redis://:pa ss@cache`): no `@` before the
            // space, but one later on the line, before any other URL. The run goes on to it.
            let line_end = tail.find('\n').unwrap_or(tail.len());
            let stop = tail[end..line_end]
                .find("://")
                .map_or(line_end, |i| end + i);
            if let Some(i) = tail[end..stop].find('@') {
                let at = end + i;
                end = tail[at..]
                    .find(char::is_whitespace)
                    .map_or(tail.len(), |j| at + j);
            }
        }
        let run = &tail[..end];
        match run.rfind('@') {
            Some(i) => {
                out.push_str("***");
                out.push_str(&run[i..]);
                changed = true;
            }
            None => out.push_str(run),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(text)
    }
}

/// `value` as text (its alternate form, so an `anyhow` error prints its chain), any URL
/// credentials in it replaced: for log fields and error text.
pub fn display(value: &impl Display) -> String {
    userinfo(&format!("{value:#}")).into_owned()
}

/// `url` with its userinfo removed altogether: `http://user:pass@app:8080/x` becomes
/// `http://app:8080/x`. For the URL an upstream request or health check is built from: that
/// client (hyper) never sends URL credentials, and its own trace logs print the URL it is given.
/// Parsed as a URI, so a path with an `@` in it is left alone; a URL that does not parse comes
/// back unchanged.
pub fn without_userinfo(url: &str) -> Cow<'_, str> {
    let Ok(uri) = url.parse::<axum::http::Uri>() else {
        return Cow::Borrowed(url);
    };
    let Some(authority) = uri.authority().map(|a| a.as_str()) else {
        return Cow::Borrowed(url);
    };
    let Some(at) = authority.rfind('@') else {
        return Cow::Borrowed(url);
    };
    let Some(start) = url.find(authority) else {
        return Cow::Borrowed(url);
    };
    Cow::Owned(format!(
        "{}{}{}",
        &url[..start],
        &authority[at + 1..],
        &url[start + authority.len()..]
    ))
}

#[cfg(test)]
mod tests {
    use super::{userinfo, without_userinfo};

    #[test]
    fn userinfo_is_replaced_and_the_rest_kept() {
        for (raw, want) in [
            (
                "http://user:pass@app:8080/x?y=1",
                "http://***@app:8080/x?y=1",
            ),
            ("http://user@app", "http://***@app"),
            (
                "https://u%40corp:p%3Aw%2F@app.internal",
                "https://***@app.internal",
            ),
            (
                "http://user:pass@[2001:db8::7]:8080",
                "http://***@[2001:db8::7]:8080",
            ),
            ("redis://:secret@cache:6379/0", "redis://***@cache:6379/0"),
            // A password with an `@` in it, unencoded: up to the last `@`.
            ("http://user:p@ss@app", "http://***@app"),
        ] {
            assert_eq!(userinfo(raw), want, "{raw}");
        }
    }

    #[test]
    fn userinfo_with_sub_delims_or_stray_delimiters_is_still_hidden() {
        for raw in [
            // RFC 3986 sub-delims, legal unencoded in userinfo.
            "http://u:p;w@h",
            "http://u:p,w@h",
            "http://u:p'w@h",
            "http://u:p)w@h",
            "redis://:a,b@cache:6379",
            "http://u:p!$&*+=w@h",
            // Not legal unencoded, but written: over-redact rather than leak.
            "http://u:p/w@h",
            "http://u:p?w@h",
            "http://u:p#w@h",
            "http://u:p\"w@h",
            "http://u:p`w@h",
            "http://u:p<w@h",
            "http://u:p>w@h",
            "redis://:a\"b`c@cache:6379",
        ] {
            let shown = userinfo(raw);
            assert!(
                shown == "http://***@h" || shown == "redis://***@cache:6379",
                "{raw} -> {shown}"
            );
        }
        // Inside an error message, a trailing `):` stays after the host.
        assert_eq!(
            userinfo("connecting (http://u:p;w@h:1): refused"),
            "connecting (http://***@h:1): refused"
        );
        // Whitespace in a password: the run goes on to the `@`.
        assert_eq!(
            userinfo("redis://:pa ss@cache:6379"),
            "redis://***@cache:6379"
        );
        assert!(!userinfo("redis://:pa ss@cache:6379").contains("pa"));
        assert_eq!(
            userinfo("connecting to http://u:a b\tc@h:1/x: refused"),
            "connecting to http://***@h:1/x: refused"
        );
        // But not past another URL, nor onto the next line.
        assert_eq!(
            userinfo("http://a:1 and http://u:p@b:1"),
            "http://a:1 and http://***@b:1"
        );
        assert_eq!(
            userinfo("http://a:1/x\nops@example.com"),
            "http://a:1/x\nops@example.com"
        );
        // A quoted URL whose password has a quote and a backtick in it: none of it is left.
        assert_eq!(
            userinfo("url \"http://u:p\"w`x@h:1/\" refused"),
            "url \"http://***@h:1/\" refused"
        );
    }

    #[test]
    fn without_userinfo_drops_it_and_leaves_a_path_alone() {
        assert_eq!(
            without_userinfo("http://user:pass@app:8080/x"),
            "http://app:8080/x"
        );
        assert_eq!(
            without_userinfo("http://u@[2001:db8::7]:1"),
            "http://[2001:db8::7]:1"
        );
        assert_eq!(without_userinfo("http://u:p;w@app"), "http://app");
        assert_eq!(without_userinfo("http://app:8080"), "http://app:8080");
        assert_eq!(without_userinfo("http://app/a@b"), "http://app/a@b");
    }

    #[test]
    fn urls_inside_messages_are_found_and_others_left_alone() {
        assert_eq!(
            userinfo("error sending request for url (http://u:pw@collector:9000/edge): refused"),
            "error sending request for url (http://***@collector:9000/edge): refused"
        );
        assert_eq!(
            userinfo("\"http://a:b@one\" and \"https://c:d@two/p\""),
            "\"http://***@one\" and \"https://***@two/p\""
        );
        for clean in [
            "http://app:8080/x",
            "mail me at ops@example.com",
            "no url here",
        ] {
            assert!(
                matches!(userinfo(clean), std::borrow::Cow::Borrowed(_)),
                "{clean}"
            );
            assert_eq!(userinfo(clean), clean);
        }
        // A path with an `@` in it is hidden too: the price of never leaking a password.
        assert_eq!(userinfo("http://app/path?next=a@b"), "http://***@b");
    }
}
