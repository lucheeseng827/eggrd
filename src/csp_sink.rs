//! Protections for the browser-facing CSP report sink (`POST /__edgeguard/csp-report`).
//!
//! The sink is public by necessity: browsers send violation reports with no credentials. In
//! managed mode each report used to become one request to the control plane, sent from a task
//! spawned per report, before the body was even parsed — so anyone on the internet could drive an
//! unbounded number of outbound requests, and tasks, through any managed edge. Now:
//!
//! * **Each client address has a budget** ([`PER_CLIENT_PER_MINUTE`], [`PER_CLIENT_BURST`]),
//!   resolved the same way the proxy resolves its client (`server.trust_forwarded_for` and
//!   friends). Past it the sink answers `429`.
//! * **A body that is not a CSP report is counted and dropped**, never forwarded.
//! * **Reports are folded** by `(directive, blocked URI)` and sent every [`FLUSH_INTERVAL`] as one
//!   request per distinct pair carrying a `count` — at most [`MAX_PENDING`] pairs per interval, so
//!   the requests an edge sends are bounded whatever arrives at its sink.
//!
//! Query strings and fragments are stripped from the URIs before anything is kept: a report's
//! `document-uri` is the page the browser was on, query string and all, and the counts are about
//! *which* resource was blocked, not which session saw it. It also folds `/x.js?v=1` and
//! `/x.js?v=2` into one pair.

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Mutex;
use std::time::Duration;

use governor::{Quota, RateLimiter};
use serde_json::Value;

use crate::proxy::KeyedLimiter;

/// Reports accepted per client address per minute. A page with a broken policy can send one
/// report per blocked resource on every view, so this is generous for a person browsing and
/// still turns a single-address flood into a trickle.
pub const PER_CLIENT_PER_MINUTE: u32 = 120;

/// Reports a client address may send at once.
pub const PER_CLIENT_BURST: u32 = 60;

/// How often folded reports are sent to the control plane.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(10);

/// Distinct `(directive, blocked URI)` pairs kept per interval. Past it, new pairs are dropped and
/// counted; pairs already kept keep counting.
pub const MAX_PENDING: usize = 64;

/// Longest field kept, in bytes. Longer values are cut on a character boundary.
const MAX_FIELD: usize = 256;

/// Client addresses tracked before idle ones are pruned.
const MAX_TRACKED_CLIENTS: usize = 10_000;

/// Least time between two prunes. A prune scans every tracked address, so it must not run per
/// request: an attacker keeping more than [`MAX_TRACKED_CLIENTS`] addresses busy would otherwise
/// turn every request to the sink into a full scan.
const PRUNE_INTERVAL: Duration = Duration::from_secs(10);

/// Tracked addresses at which the sink refuses reports until a prune makes room. Bounds the
/// limiter's memory under a flood from more addresses than pruning can keep up with; CSP reports
/// are telemetry, so refusing them for a few seconds costs nothing that matters.
const HARD_CAP_CLIENTS: usize = 100_000;

/// The most identical reports one `(directive, blocked URI)` pair carries per interval — the
/// control plane's per-request cap. Past it the reports are counted as dropped (`overflow`) rather
/// than sent and silently clamped, and not split across requests either: splitting would let a
/// large enough flood multiply the requests this sink exists to bound. Keep it no higher than the
/// control plane's cap, or the difference is clamped away there unseen.
pub const MAX_COUNT_PER_PAIR: u64 = 10_000;

/// The parts of a CSP report the edge keeps and forwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspViolation {
    pub directive: String,
    pub blocked_uri: String,
    pub document_uri: String,
}

/// Read a `report-uri` style report: the `{"csp-report": {…}}` envelope browsers send, or the bare
/// object. `None` when the body is not JSON, not an object, or names no directive — nothing worth
/// counting or forwarding.
pub fn parse_report(body: &[u8]) -> Option<CspViolation> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let report = value.get("csp-report").unwrap_or(&value).as_object()?;
    let text = |key: &str| report.get(key).and_then(Value::as_str);
    let directive = text("violated-directive")
        .or_else(|| text("effective-directive"))
        .filter(|d| !d.trim().is_empty())?;
    Some(CspViolation {
        directive: clamp(directive.trim()),
        blocked_uri: clamp(without_query(text("blocked-uri").unwrap_or(""))),
        document_uri: clamp(without_query(text("document-uri").unwrap_or(""))),
    })
}

/// `s` up to its first `?` or `#`.
fn without_query(s: &str) -> &str {
    s.split(['?', '#']).next().unwrap_or("")
}

/// `s` cut to [`MAX_FIELD`] bytes on a character boundary.
fn clamp(s: &str) -> String {
    if s.len() <= MAX_FIELD {
        return s.to_string();
    }
    let mut end = MAX_FIELD;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Why the sink did not keep a report: `edgeguard_csp_reports_dropped_total{reason}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspDrop {
    /// The client address had spent its budget.
    RateLimited,
    /// The body was not a CSP report.
    Invalid,
    /// [`MAX_PENDING`] pairs were already waiting, or this pair already counted
    /// [`MAX_COUNT_PER_PAIR`] this interval.
    Overflow,
}

impl CspDrop {
    /// Every reason, in the order the metric renders them.
    pub const ALL: [CspDrop; 3] = [CspDrop::RateLimited, CspDrop::Invalid, CspDrop::Overflow];

    /// The `reason` label value.
    pub fn label(self) -> &'static str {
        match self {
            CspDrop::RateLimited => "rate_limited",
            CspDrop::Invalid => "invalid",
            CspDrop::Overflow => "overflow",
        }
    }
}

/// What [`CspSink::queue`] did with a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fold {
    /// A new pair, now pending.
    Added,
    /// Counted against a pair already pending.
    Counted,
    /// A new pair with [`MAX_PENDING`] already pending, or a pair already at
    /// [`MAX_COUNT_PER_PAIR`]: dropped.
    Overflow,
}

/// The sink's per-client limiter and the reports waiting to be sent.
pub struct CspSink {
    limiter: KeyedLimiter,
    /// `(directive, blocked URI) → (a document URI it was seen on, count)`.
    pending: Mutex<HashMap<(String, String), (String, u64)>>,
    /// The clock [`Self::last_prune_ms`] is measured on.
    started: std::time::Instant,
    /// When the limiter was last pruned, in ms since `started`. See [`PRUNE_INTERVAL`].
    last_prune_ms: std::sync::atomic::AtomicU64,
}

impl Default for CspSink {
    fn default() -> Self {
        Self::new()
    }
}

impl CspSink {
    pub fn new() -> Self {
        let per_minute = NonZeroU32::new(PER_CLIENT_PER_MINUTE).expect("non-zero");
        let burst = NonZeroU32::new(PER_CLIENT_BURST).expect("non-zero");
        CspSink {
            limiter: RateLimiter::keyed(Quota::per_minute(per_minute).allow_burst(burst)),
            pending: Mutex::new(HashMap::new()),
            started: std::time::Instant::now(),
            last_prune_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Spend one report from `client`'s budget. `false` past it, and while the limiter tracks
    /// [`HARD_CAP_CLIENTS`] addresses.
    pub fn admit(&self, client: IpAddr) -> bool {
        if self.limiter.len() > MAX_TRACKED_CLIENTS {
            self.maybe_prune();
            if self.limiter.len() >= HARD_CAP_CLIENTS {
                return false;
            }
        }
        self.limiter.check_key(&client).is_ok()
    }

    /// Drop addresses whose budget has refilled — they carry no state worth keeping — at most once
    /// per [`PRUNE_INTERVAL`], by whichever request wins the race to do it.
    fn maybe_prune(&self) {
        use std::sync::atomic::Ordering;
        let now = self.started.elapsed().as_millis() as u64;
        let last = self.last_prune_ms.load(Ordering::Acquire);
        if now.saturating_sub(last) < PRUNE_INTERVAL.as_millis() as u64 {
            return;
        }
        if self
            .last_prune_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.limiter.retain_recent();
        }
    }

    /// Fold a report into the pending set.
    pub fn queue(&self, v: CspViolation) -> Fold {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let key = (v.directive, v.blocked_uri);
        if let Some((_, count)) = pending.get_mut(&key) {
            if *count >= MAX_COUNT_PER_PAIR {
                return Fold::Overflow;
            }
            *count += 1;
            return Fold::Counted;
        }
        if pending.len() >= MAX_PENDING {
            return Fold::Overflow;
        }
        pending.insert(key, (v.document_uri, 1));
        Fold::Added
    }

    /// Take everything pending, leaving the set empty for the next interval.
    pub fn take(&self) -> Vec<(CspViolation, u64)> {
        let drained = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()));
        drained
            .into_iter()
            .map(|((directive, blocked_uri), (document_uri, count))| {
                (
                    CspViolation {
                        directive,
                        blocked_uri,
                        document_uri,
                    },
                    count,
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(directive: &str, blocked: &str) -> Vec<u8> {
        format!(
            r#"{{"csp-report":{{"violated-directive":"{directive}","blocked-uri":"{blocked}","document-uri":"https://app.example/page?session=secret#frag"}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn a_report_is_read_from_the_envelope_or_bare_and_loses_its_query_strings() {
        let v = parse_report(&report("script-src", "https://cdn.example/x.js?v=2")).unwrap();
        assert_eq!(v.directive, "script-src");
        assert_eq!(v.blocked_uri, "https://cdn.example/x.js");
        assert_eq!(
            v.document_uri, "https://app.example/page",
            "no session id kept"
        );

        let bare = br#"{"effective-directive":"img-src","blocked-uri":"data"}"#;
        assert_eq!(parse_report(bare).unwrap().directive, "img-src");
    }

    #[test]
    fn anything_that_is_not_a_report_is_refused() {
        for body in [
            &b""[..],
            b"not json",
            b"{}",
            b"[]",
            br#"{"csp-report":{}}"#,
            br#"{"csp-report":"x"}"#,
            br#"{"violated-directive":"   "}"#,
            br#"[{"type":"csp-violation"}]"#,
        ] {
            assert_eq!(
                parse_report(body),
                None,
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn long_fields_are_cut_on_a_character_boundary() {
        let long = "é".repeat(400);
        let body = format!(r#"{{"violated-directive":"script-src","blocked-uri":"{long}"}}"#);
        let v = parse_report(body.as_bytes()).unwrap();
        assert!(v.blocked_uri.len() <= MAX_FIELD);
        assert!(v.blocked_uri.chars().all(|c| c == 'é'));
    }

    #[test]
    fn identical_reports_fold_into_one_pending_pair_with_a_count() {
        let sink = CspSink::new();
        let v = parse_report(&report("script-src", "https://cdn.example/x.js")).unwrap();
        assert_eq!(sink.queue(v.clone()), Fold::Added);
        for _ in 0..49 {
            assert_eq!(sink.queue(v.clone()), Fold::Counted);
        }
        let other = parse_report(&report("img-src", "https://img.example/")).unwrap();
        assert_eq!(sink.queue(other), Fold::Added);

        let mut taken = sink.take();
        taken.sort_by(|a, b| a.0.directive.cmp(&b.0.directive));
        assert_eq!(taken.len(), 2);
        assert_eq!((taken[0].0.directive.as_str(), taken[0].1), ("img-src", 1));
        assert_eq!(
            (taken[1].0.directive.as_str(), taken[1].1),
            ("script-src", 50)
        );
        assert!(sink.take().is_empty(), "taking empties the set");
    }

    #[test]
    fn new_pairs_past_the_cap_are_dropped_and_kept_pairs_keep_counting() {
        let sink = CspSink::new();
        for i in 0..MAX_PENDING {
            let v =
                parse_report(&report("script-src", &format!("https://cdn{i}.example/"))).unwrap();
            assert_eq!(sink.queue(v), Fold::Added);
        }
        let new = parse_report(&report("script-src", "https://one-too-many.example/")).unwrap();
        assert_eq!(sink.queue(new), Fold::Overflow);
        let kept = parse_report(&report("script-src", "https://cdn0.example/")).unwrap();
        assert_eq!(sink.queue(kept), Fold::Counted);
        assert_eq!(sink.take().len(), MAX_PENDING);
    }

    #[test]
    fn one_pair_counts_up_to_the_control_planes_cap_and_the_rest_overflow() {
        let sink = CspSink::new();
        let v = parse_report(&report("script-src", "https://cdn.example/x.js")).unwrap();
        let overflow = (0..MAX_COUNT_PER_PAIR + 5)
            .filter(|_| sink.queue(v.clone()) == Fold::Overflow)
            .count();
        assert_eq!(
            overflow, 5,
            "the excess is counted as dropped, not sent and clamped"
        );
        assert_eq!(sink.take()[0].1, MAX_COUNT_PER_PAIR);
        // The next interval starts from zero.
        assert_eq!(sink.queue(v), Fold::Added);
    }

    #[test]
    fn past_the_hard_cap_of_tracked_addresses_new_reports_are_refused() {
        // A prune stamped in the far future never comes due, so however slow the runner, no
        // address is pruned and the limiter fills to the cap.
        let sink = CspSink {
            last_prune_ms: std::sync::atomic::AtomicU64::new(u64::MAX),
            ..CspSink::new()
        };
        for i in 0..HARD_CAP_CLIENTS as u32 {
            assert!(sink.admit(IpAddr::from((0x0a00_0000u32 + i).to_be_bytes())));
        }
        assert!(!sink.admit("203.0.113.250".parse().unwrap()));
        assert_eq!(
            sink.limiter.len(),
            HARD_CAP_CLIENTS,
            "and the limiter did not grow"
        );
    }

    #[test]
    fn pruning_is_rate_limited_not_per_request() {
        // A sink built long ago has never pruned: the first call prunes and stamps the time …
        let far = PRUNE_INTERVAL.as_millis() as u64 * 3;
        let sink = CspSink {
            started: std::time::Instant::now() - Duration::from_millis(far),
            ..CspSink::new()
        };
        sink.maybe_prune();
        let stamped = sink
            .last_prune_ms
            .load(std::sync::atomic::Ordering::Acquire);
        assert!(stamped >= far);
        // … and the next one, straight after, does not.
        sink.maybe_prune();
        assert_eq!(
            sink.last_prune_ms
                .load(std::sync::atomic::Ordering::Acquire),
            stamped
        );
    }

    #[test]
    fn each_client_address_has_its_own_budget() {
        let sink = CspSink::new();
        let flood: IpAddr = "203.0.113.7".parse().unwrap();
        let other: IpAddr = "198.51.100.9".parse().unwrap();
        let admitted = (0..PER_CLIENT_BURST + 20)
            .filter(|_| sink.admit(flood))
            .count();
        assert_eq!(admitted, PER_CLIENT_BURST as usize);
        assert!(sink.admit(other), "another address is unaffected");
    }
}
