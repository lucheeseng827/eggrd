//! WAF-lite: heuristic input inspection (Phase 4 / v2).
//!
//! A small request screener that runs in the proxy pipeline after auth and the size/method
//! checks, just before a request is forwarded. It matches the request against built-in
//! heuristic rulesets (SQL-injection, cross-site-scripting, path-traversal) and any
//! operator-defined [`crate::config::WafRule`] deny patterns.
//!
//! Three things keep this honest and safe rather than a foot-gun:
//!
//! * **Off by default, report-first.** `mode = "off"` makes [`WafEngine::evaluate`] a no-op
//!   with zero per-request work. `report` evaluates rules and logs/counts matches but still
//!   forwards the request, so an operator can roll out a ruleset and watch
//!   `edgeguard_waf_hits_total` for false positives before switching to `block` (`403`).
//! * **Heuristics, acknowledged.** The built-in patterns are signatures, not a full WAF; they
//!   miss novel payloads and occasionally false-positive. That trade-off is why they default
//!   off and ship the report-first workflow.
//! * **ReDoS-safe matching.** Patterns compile to the `regex` crate's RE2 engine, which runs
//!   in linear time and rejects backreferences/lookaround, so an operator-supplied pattern
//!   can't pin a CPU with catastrophic backtracking. A pattern that fails to compile is
//!   rejected at startup/reload like any other config error.
//!
//! Like [`crate::config::parse_host_port`], the percent-decoder here is deliberately minimal:
//! the proxy doesn't need a full URL library to surface `%2e%2e%2f` as `../`.

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use regex::RegexSet;

use crate::config::WafCfg;

/// What the engine does with a request that matches a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafMode {
    /// Disabled — [`WafEngine::evaluate`] is a no-op. Default.
    Off,
    /// Evaluate rules and log/count matches, but forward the request anyway.
    Report,
    /// Reject a matching request with `403 Forbidden`.
    Block,
}

impl WafMode {
    fn parse(s: &str) -> Result<WafMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" | "" => Ok(WafMode::Off),
            "report" | "report-only" | "detect" => Ok(WafMode::Report),
            "block" | "enforce" | "deny" => Ok(WafMode::Block),
            other => anyhow::bail!("invalid waf.mode {other:?} (expected off|report|block)"),
        }
    }
}

/// A request location a rule can inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Location {
    Path,
    Headers,
    Body,
}

impl Location {
    fn as_str(self) -> &'static str {
        match self {
            Location::Path => "path",
            Location::Headers => "headers",
            Location::Body => "body",
        }
    }
}

/// The set of locations a rule applies to. Built-in rules use [`Target::ALL`]; a custom rule
/// carries the single location parsed from its `target` field.
#[derive(Debug, Clone, Copy)]
struct Target {
    path: bool,
    headers: bool,
    body: bool,
}

impl Target {
    const ALL: Target = Target {
        path: true,
        headers: true,
        body: true,
    };

    fn parse(s: &str) -> Result<Target> {
        match s.trim().to_ascii_lowercase().as_str() {
            "path" | "" => Ok(Target {
                path: true,
                headers: false,
                body: false,
            }),
            "headers" | "header" => Ok(Target {
                path: false,
                headers: true,
                body: false,
            }),
            "body" => Ok(Target {
                path: false,
                headers: false,
                body: true,
            }),
            "all" | "any" => Ok(Target::ALL),
            other => {
                anyhow::bail!("invalid waf rule target {other:?} (expected path|headers|body|all)")
            }
        }
    }

    fn includes(&self, loc: Location) -> bool {
        match loc {
            Location::Path => self.path,
            Location::Headers => self.headers,
            Location::Body => self.body,
        }
    }
}

/// A compiled rule: a reporting id + metric class, the locations it applies to, and a set of
/// patterns (any match is a hit). Built-in rulesets compile their whole category into one set.
struct CompiledRule {
    /// Reported in logs (built-in category name, or the operator's rule id).
    id: String,
    /// Coarse class for metrics: `sqli` | `xss` | `path_traversal` | `custom`.
    class: &'static str,
    target: Target,
    set: RegexSet,
}

impl CompiledRule {
    fn hit(&self, location: Location) -> WafHit {
        WafHit {
            rule_id: self.id.clone(),
            class: self.class,
            location: location.as_str(),
        }
    }
}

/// The outcome of a matching rule: which rule fired, its metric class, and where it matched.
pub struct WafHit {
    pub rule_id: String,
    pub class: &'static str,
    pub location: &'static str,
}

/// Built-in SQL-injection signatures (case-insensitive). Heuristic: tuned to catch the common
/// boolean/union/stacked/time-based shapes while not firing on prose that merely contains a
/// keyword like "union".
const SQLI: &[&str] = &[
    r"(?i)\bunion\b\s+(all\s+)?\bselect\b",
    r"(?i)\bor\b\s+\d+\s*=\s*\d+",
    r"(?i)'\s*or\s+'",
    r"(?i)\bdrop\s+table\b",
    r"(?i)\binsert\s+into\b",
    r"(?i);\s*(drop|delete|update|insert|select)\b",
    r"(?i)\b(sleep|benchmark|pg_sleep)\s*\(",
    r"(?i)\bwaitfor\s+delay\b",
    r"(?i)\binformation_schema\b",
    r"(?i)\bxp_cmdshell\b",
];

/// Built-in cross-site-scripting signatures (case-insensitive).
const XSS: &[&str] = &[
    r"(?i)<\s*script\b",
    r"(?i)<\s*/\s*script\s*>",
    r"(?i)javascript:",
    r"(?i)\bon(error|load|click|mouseover|focus|submit|toggle)\s*=",
    r"(?i)<\s*iframe\b",
    r"(?i)<\s*img\b[^>]*\bonerror\b",
    r"(?i)<\s*svg\b[^>]*\bonload\b",
    r"(?i)document\s*\.\s*cookie",
];

/// Built-in path-traversal signatures. The raw and percent-decoded path are both inspected, so
/// the encoded variants here mainly backstop double-encoding and matches in headers/body (which
/// are not decoded).
const TRAVERSAL: &[&str] = &[
    r"\.\./",
    r"\.\.\\",
    r"(?i)%2e%2e(%2f|%5c|/|\\)",
    r"(?i)\.\.%2f",
    r"(?i)\.\.%5c",
    r"(?i)/etc/passwd\b",
    r"(?i)/proc/self/",
    r"(?i)c:\\(?:windows|winnt)\b",
];

/// The compiled WAF engine, held in the hot-swappable [`crate::proxy::Runtime`].
pub struct WafEngine {
    mode: WafMode,
    inspect_path: bool,
    inspect_headers: bool,
    inspect_body: bool,
    rules: Vec<CompiledRule>,
}

impl WafEngine {
    /// Compile the engine from config. When `mode = "off"` an inert engine is returned without
    /// compiling anything (so a disabled WAF costs nothing). Otherwise every enabled built-in
    /// ruleset and every custom pattern is compiled; an empty or invalid custom pattern, or an
    /// unknown `target`, fails the build so the misconfiguration surfaces at startup/reload.
    pub fn build(cfg: &WafCfg) -> Result<WafEngine> {
        let mode = WafMode::parse(&cfg.mode).context("waf.mode")?;
        if mode == WafMode::Off {
            return Ok(WafEngine::disabled());
        }

        let mut rules = Vec::new();
        if cfg.sqli {
            rules.push(builtin("sqli", "sqli", SQLI)?);
        }
        if cfg.xss {
            rules.push(builtin("xss", "xss", XSS)?);
        }
        if cfg.path_traversal {
            rules.push(builtin("path_traversal", "path_traversal", TRAVERSAL)?);
        }
        for (i, rule) in cfg.rules.iter().enumerate() {
            anyhow::ensure!(
                !rule.pattern.trim().is_empty(),
                "waf.rules[{i}].pattern must not be empty"
            );
            let id = if rule.id.trim().is_empty() {
                format!("custom-{i}")
            } else {
                rule.id.clone()
            };
            let target =
                Target::parse(&rule.target).with_context(|| format!("waf.rules[{i}] ({id})"))?;
            let set = RegexSet::new([rule.pattern.as_str()])
                .with_context(|| format!("compiling waf.rules[{i}] ({id}) pattern"))?;
            rules.push(CompiledRule {
                id,
                class: "custom",
                target,
                set,
            });
        }

        Ok(WafEngine {
            mode,
            inspect_path: cfg.inspect_path,
            inspect_headers: cfg.inspect_headers,
            inspect_body: cfg.inspect_body,
            rules,
        })
    }

    /// An inert engine (`mode = "off"`): no rules, inspects nothing.
    fn disabled() -> WafEngine {
        WafEngine {
            mode: WafMode::Off,
            inspect_path: false,
            inspect_headers: false,
            inspect_body: false,
            rules: Vec::new(),
        }
    }

    pub fn mode(&self) -> WafMode {
        self.mode
    }

    /// Evaluate a request against the rules and return the first match, if any. Returns `None`
    /// immediately when disabled. Each enabled location's inspection text is assembled at most
    /// once, then every rule that targets that location is checked against it. The path is
    /// checked both raw and percent-decoded (so `%2e%2e%2f` is caught as `../`); headers and
    /// body are matched as-is.
    pub fn evaluate(
        &self,
        path_and_query: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<WafHit> {
        if self.mode == WafMode::Off || self.rules.is_empty() {
            return None;
        }

        // Only percent-decode when there's something to decode (the common path has no `%`).
        let decoded_path = if self.inspect_path && path_and_query.contains('%') {
            Some(percent_decode_lossy(path_and_query))
        } else {
            None
        };
        let header_text = if self.inspect_headers {
            Some(join_header_values(headers))
        } else {
            None
        };
        let body_text = if self.inspect_body && !body.is_empty() {
            Some(String::from_utf8_lossy(body))
        } else {
            None
        };

        for rule in &self.rules {
            if self.inspect_path && rule.target.includes(Location::Path) {
                let decoded_hit = decoded_path
                    .as_deref()
                    .is_some_and(|d| rule.set.is_match(d));
                if rule.set.is_match(path_and_query) || decoded_hit {
                    return Some(rule.hit(Location::Path));
                }
            }
            if let Some(ht) = &header_text {
                if rule.target.includes(Location::Headers) && rule.set.is_match(ht) {
                    return Some(rule.hit(Location::Headers));
                }
            }
            if let Some(bt) = &body_text {
                if rule.target.includes(Location::Body) && rule.set.is_match(bt) {
                    return Some(rule.hit(Location::Body));
                }
            }
        }
        None
    }
}

/// Compile a built-in ruleset (a whole category) into one [`CompiledRule`] applying to every
/// location.
fn builtin(id: &str, class: &'static str, patterns: &[&str]) -> Result<CompiledRule> {
    let set =
        RegexSet::new(patterns).with_context(|| format!("compiling built-in {id} ruleset"))?;
    Ok(CompiledRule {
        id: id.to_string(),
        class,
        target: Target::ALL,
        set,
    })
}

/// Minimal, lossy percent-decoder for the request path/query: decodes `%XX` escapes and leaves
/// a malformed or truncated escape as the literal bytes. Decoded bytes are interpreted as UTF-8
/// lossily. Single-pass — it does not chase double-encoding (the built-in encoded patterns
/// backstop that), staying deliberately small in the spirit of `config::parse_host_port`.
fn percent_decode_lossy(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Join header `name: value` lines into one string for inspection. Names are included so a rule
/// can target a specific header; values that aren't valid UTF-8 are skipped (they can't carry a
/// textual signature we'd match).
fn join_header_values(headers: &HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            out.push_str(name.as_str());
            out.push_str(": ");
            out.push_str(v);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WafRule;
    use axum::http::{HeaderMap, HeaderValue};

    fn engine(cfg: WafCfg) -> WafEngine {
        WafEngine::build(&cfg).unwrap()
    }

    fn block_cfg() -> WafCfg {
        WafCfg {
            mode: "block".into(),
            ..Default::default()
        }
    }

    fn eval_path(e: &WafEngine, p: &str) -> Option<WafHit> {
        e.evaluate(p, &HeaderMap::new(), b"")
    }

    #[test]
    fn mode_parses_known_and_rejects_unknown() {
        assert_eq!(WafMode::parse("off").unwrap(), WafMode::Off);
        assert_eq!(WafMode::parse("").unwrap(), WafMode::Off);
        assert_eq!(WafMode::parse("REPORT").unwrap(), WafMode::Report);
        assert_eq!(WafMode::parse(" block ").unwrap(), WafMode::Block);
        assert!(WafMode::parse("banana").is_err());
    }

    #[test]
    fn off_by_default_is_inert() {
        let e = engine(WafCfg::default()); // mode "off"
        assert_eq!(e.mode(), WafMode::Off);
        // Even blatant payloads are ignored when the engine is off.
        assert!(eval_path(&e, "/?q=' OR '1'='1").is_none());
        assert!(eval_path(&e, "/../../etc/passwd").is_none());
    }

    #[test]
    fn detects_sqli_in_path() {
        let e = engine(block_cfg());
        assert_eq!(
            eval_path(&e, "/items?q=1 UNION SELECT password FROM users")
                .unwrap()
                .class,
            "sqli"
        );
        assert!(eval_path(&e, "/login?u=admin&p=x' OR '1'='1").is_some());
        // Prose that merely contains "union" must not trip the union/select rule.
        assert!(eval_path(&e, "/articles/the-european-union-explained").is_none());
    }

    #[test]
    fn detects_xss_in_path_raw_and_encoded() {
        let e = engine(block_cfg());
        assert_eq!(
            eval_path(&e, "/p?c=<script>alert(1)</script>")
                .unwrap()
                .class,
            "xss"
        );
        // Percent-encoded `<script>` is decoded before matching.
        assert!(eval_path(&e, "/p?c=%3Cscript%3E").is_some());
        assert!(eval_path(&e, "/go?to=javascript:alert(1)").is_some());
        assert!(eval_path(&e, "/search?q=hello world").is_none());
    }

    #[test]
    fn detects_path_traversal_raw_and_encoded() {
        let e = engine(block_cfg());
        assert_eq!(
            eval_path(&e, "/static/../../etc/passwd").unwrap().class,
            "path_traversal"
        );
        assert!(eval_path(&e, "/static/%2e%2e%2f%2e%2e%2fsecret").is_some());
        assert!(eval_path(&e, "/static/app.bundle.js").is_none());
    }

    #[test]
    fn categories_can_be_disabled_individually() {
        let cfg = WafCfg {
            mode: "block".into(),
            sqli: false,
            ..Default::default()
        };
        let e = engine(cfg);
        // SQLi disabled -> not detected; XSS still on.
        assert!(eval_path(&e, "/?q=1 UNION SELECT 1").is_none());
        assert!(eval_path(&e, "/?q=<script>x</script>").is_some());
    }

    #[test]
    fn custom_rule_matches_only_its_target_location() {
        let cfg = WafCfg {
            mode: "block".into(),
            sqli: false,
            xss: false,
            path_traversal: false,
            inspect_headers: true,
            rules: vec![WafRule {
                id: "wp".into(),
                pattern: r"(?i)/wp-admin".into(),
                target: "path".into(),
            }],
            ..Default::default()
        };
        let e = engine(cfg);

        let hit = eval_path(&e, "/wp-admin/index.php").unwrap();
        assert_eq!(hit.rule_id, "wp");
        assert_eq!(hit.class, "custom");
        assert_eq!(hit.location, "path");

        // The same string in a header is not matched — the rule targets the path only.
        let mut h = HeaderMap::new();
        h.insert("x-test", HeaderValue::from_static("/wp-admin"));
        assert!(e.evaluate("/safe", &h, b"").is_none());
    }

    #[test]
    fn headers_and_body_only_inspected_when_enabled() {
        // Defaults: inspect_headers/body off -> a header/body payload is ignored.
        let e = engine(block_cfg());
        let mut h = HeaderMap::new();
        h.insert("user-agent", HeaderValue::from_static("<script>x</script>"));
        assert!(e.evaluate("/", &h, b"<script>x</script>").is_none());

        // With both enabled, the same payloads are caught and the location is reported.
        let e2 = engine(WafCfg {
            mode: "block".into(),
            inspect_headers: true,
            inspect_body: true,
            ..Default::default()
        });
        assert_eq!(e2.evaluate("/", &h, b"").unwrap().location, "headers");
        assert_eq!(
            e2.evaluate("/", &HeaderMap::new(), b"<script>x</script>")
                .unwrap()
                .location,
            "body"
        );
    }

    #[test]
    fn build_rejects_bad_custom_pattern_empty_pattern_and_target() {
        // Uncompilable regex.
        assert!(WafEngine::build(&WafCfg {
            mode: "block".into(),
            rules: vec![WafRule {
                id: "bad".into(),
                pattern: "(".into(),
                target: "path".into(),
            }],
            ..Default::default()
        })
        .is_err());

        // Empty pattern.
        assert!(WafEngine::build(&WafCfg {
            mode: "report".into(),
            rules: vec![WafRule {
                pattern: "   ".into(),
                ..Default::default()
            }],
            ..Default::default()
        })
        .is_err());

        // Unknown target.
        assert!(WafEngine::build(&WafCfg {
            mode: "block".into(),
            rules: vec![WafRule {
                pattern: "a".into(),
                target: "cookie".into(),
                ..Default::default()
            }],
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn build_rejects_invalid_mode() {
        assert!(WafEngine::build(&WafCfg {
            mode: "audit".into(),
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn percent_decode_handles_escapes_and_malformed() {
        assert_eq!(percent_decode_lossy("%2e%2e%2f"), "../");
        assert_eq!(percent_decode_lossy("a%2Fb"), "a/b");
        // Malformed/truncated escapes are left literal.
        assert_eq!(percent_decode_lossy("100%"), "100%");
        assert_eq!(percent_decode_lossy("%zz"), "%zz");
        assert_eq!(percent_decode_lossy("ab%2"), "ab%2");
    }

    #[test]
    fn report_mode_still_returns_hits() {
        let e = engine(WafCfg {
            mode: "report".into(),
            ..Default::default()
        });
        assert_eq!(e.mode(), WafMode::Report);
        assert!(eval_path(&e, "/?c=<script>").is_some());
    }
}
