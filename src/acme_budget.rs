//! ACME issuance budget — refuse to ask a CA for a certificate it is about to refuse.
//!
//! # The failure this prevents
//!
//! Certificate authorities rate-limit issuance, and the limits are low enough to hit by accident.
//! Let's Encrypt allows **5 certificates per exact set of identifiers per 7 days**. An edge that
//! re-orders on every start — because its certificate cache is not durable, or because a rollout
//! replaces the instance — burns that in five restarts and then has **no certificate for a week**.
//! That is not hypothetical: it is why the k3s edge deployment carries a dedicated persistent volume
//! for the ACME cache, with a comment explaining exactly this.
//!
//! Without a budget the edge finds out by being refused, at which point the week has started.
//!
//! # Modelled as the CA models it
//!
//! Let's Encrypt publishes these as **token buckets with refill rates** — "50 per 7 days, refilling
//! 1 every 202 minutes" — not as fixed windows. The difference matters in the dangerous direction: a
//! fixed-window counter believes the whole allowance returns at a boundary, so it permits a burst
//! the CA will refuse. GCRA is exactly the right shape, and this crate already has it in
//! [`crate::limiter`], so the buckets reuse that arithmetic rather than growing a second
//! rate-limiter.
//!
//! # What this ledger is, and what decides when it is not
//!
//! **It is per-edge.** Each edge keeps its own ledger, which fully covers the per-edge limit — the
//! exact-identifier-set bucket, the one behind the outage above. It cannot, on its own, coordinate
//! the per-registered-domain bucket across many edges: fifty edges under one registered domain
//! would each believe they had the full 50-per-week allowance and between them spend it.
//!
//! That gap is closed **above** this module rather than inside it. In managed mode the edge asks the
//! control plane for an issuance lease first (`crate::cp::CpClient::acme_lease`), and the control
//! plane holds the shared buckets for the whole fleet — see `acme::check_budget` for the decision
//! and the fallback. This ledger is then the authority in exactly two cases: an unmanaged edge, and
//! a managed edge whose control plane cannot answer. Both are real, so it is not vestigial; but the
//! per-registered-domain bucket **here** is still a local guard rather than a fleet total, and the
//! metric help text says so rather than implying a number it does not have.
//!
//! # Never trades a real certificate for a self-signed one
//!
//! A refusal here is a *deferral*, never a downgrade. `main.rs` documents the invariant this
//! respects: ACME runs before the self-signed floor precisely so a failed order cannot silently put
//! an untrusted certificate on a public name. An exhausted budget keeps whatever certificate is
//! already on disk and says so loudly; it does not manufacture one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::limiter::{gcra_admit, Gcra};

/// Which CA limit refused an order. Also the metric label, so it is a fixed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    /// New orders per ACME account.
    Orders,
    /// New certificates per registered domain.
    RegisteredDomain,
    /// New certificates per exact set of identifiers. The binding limit for a restart loop.
    IdentifierSet,
}

impl Bucket {
    pub fn label(&self) -> &'static str {
        match self {
            Bucket::Orders => "orders",
            Bucket::RegisteredDomain => "registered_domain",
            Bucket::IdentifierSet => "identifier_set",
        }
    }
}

/// The verdict for one proposed order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// The CA would refuse. `retry_at_unix` is when this bucket next admits.
    Defer {
        bucket: Bucket,
        retry_at_unix: i64,
    },
}

/// One CA's published limits.
///
/// Per-CA because these numbers are **not** universal — they are Let's Encrypt's. A CA whose
/// directory URL is not recognised gets no profile and no budget, rather than being held to somebody
/// else's numbers: refusing an order a private or commercial CA would happily accept is a
/// self-inflicted outage.
#[derive(Debug, Clone)]
pub struct CaProfile {
    pub name: &'static str,
    pub orders: Gcra,
    pub registered_domain: Gcra,
    pub identifier_set: Gcra,
}

impl CaProfile {
    /// Let's Encrypt's published production limits, verified against their rate-limits page:
    ///
    /// | Limit | Value | Refill |
    /// |---|---|---|
    /// | New orders per account | 300 / 3 h | 1 per 36 s |
    /// | New certificates per registered domain | 50 / 7 d | 1 per 202 min |
    /// | New certificates per exact identifier set | 5 / 7 d | 1 per 34 h |
    ///
    /// The burst equals the limit and the emission interval is `window / limit`, which reproduces
    /// the published refill rates exactly — that agreement is what says the model matches the CA's.
    fn lets_encrypt() -> Result<CaProfile> {
        Ok(CaProfile {
            name: "letsencrypt",
            orders: Gcra::from_parts(300, Duration::from_secs(3 * 3_600), 300)?,
            registered_domain: Gcra::from_parts(50, Duration::from_secs(7 * 86_400), 50)?,
            identifier_set: Gcra::from_parts(5, Duration::from_secs(7 * 86_400), 5)?,
        })
    }

    /// Resolve a profile from the ACME directory URL.
    ///
    /// Staging gets the **production** profile deliberately, even though its real limits are much
    /// higher. Staging is the compiled-in default for this crate, so an inert budget there would
    /// mean the budget code is never exercised in the configuration most deployments start from —
    /// untested code on the path that matters. Being conservative on a test CA costs nothing.
    pub fn for_directory(url: &str) -> Option<CaProfile> {
        let host = url
            .split_once("://")
            .map(|(_, r)| r)
            .unwrap_or(url)
            .split('/')
            .next()
            .unwrap_or("");
        if host.ends_with("letsencrypt.org") {
            CaProfile::lets_encrypt().ok()
        } else {
            None
        }
    }

    fn gcra(&self, b: Bucket) -> &Gcra {
        match b {
            Bucket::Orders => &self.orders,
            Bucket::RegisteredDomain => &self.registered_domain,
            Bucket::IdentifierSet => &self.identifier_set,
        }
    }
}

/// Group a hostname for the per-registered-domain bucket.
///
/// The CA groups by registered domain (eTLD+1), which needs the Public Suffix List to compute
/// exactly. This crate will not take that dependency for one bucket, so it uses the **last two
/// labels** and is honest about the consequence:
///
/// - `a.b.example.com` → `example.com` — correct.
/// - `a.example.co.uk` → `co.uk` — **wrong, and wrong in the safe direction.** It merges every
///   `.co.uk` registered domain into one bucket, so the guard becomes stricter than the CA. It never
///   splits one CA bucket into two, which is the only error that would let issuance through that the
///   CA then refuses.
///
/// An IP literal, or a name with two or fewer labels, is returned unchanged.
pub fn group_key(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.parse::<std::net::IpAddr>().is_ok() {
        return h;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() <= 2 {
        return h;
    }
    labels[labels.len() - 2..].join(".")
}

/// The stable key for the exact-identifier-set bucket: the domains, lowercased, deduplicated and
/// sorted, so the same set in a different order is the same key. The CA matches on the set, not the
/// order it was written in.
pub fn identifier_set_key(domains: &[String]) -> String {
    let mut d: Vec<String> = domains
        .iter()
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    d.sort();
    d.dedup();
    d.join(",")
}

/// The persisted state: one theoretical-arrival-time per bucket key, in microseconds.
#[derive(Debug, Default, Serialize, Deserialize)]
struct LedgerFile {
    /// `"<bucket>:<key>" -> TAT µs`.
    #[serde(default)]
    tats: HashMap<String, u64>,
}

/// The issuance budget for one edge.
///
/// Persisted in the ACME cache directory — the same place the account key lives, and the directory a
/// deployment must already make durable for ACME to work at all. A budget that resets on restart
/// would be no budget: restarts are precisely the event it exists to survive.
pub struct IssuanceBudget {
    profile: CaProfile,
    path: PathBuf,
    file: LedgerFile,
}

impl IssuanceBudget {
    /// Load (or start) the ledger for `cache_dir`. `None` when the CA is unrecognised — see
    /// [`CaProfile::for_directory`].
    pub fn load(directory_url: &str, cache_dir: &str) -> Option<IssuanceBudget> {
        let profile = CaProfile::for_directory(directory_url)?;
        let path = Path::new(cache_dir).join("issuance-budget.json");
        let file = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<LedgerFile>(&s).ok())
            .unwrap_or_default();
        info!(
            ca = profile.name,
            ledger = %path.display(),
            entries = file.tats.len(),
            "ACME issuance budget active"
        );
        Some(IssuanceBudget {
            profile,
            path,
            file,
        })
    }

    fn key(bucket: Bucket, k: &str) -> String {
        format!("{}:{}", bucket.label(), k)
    }

    /// Would every bucket admit an order for `domains`? Does **not** debit — see [`Self::debit`].
    pub fn check(&self, domains: &[String], now_unix: i64) -> Decision {
        let now_us = (now_unix.max(0) as u64).saturating_mul(1_000_000);
        for (bucket, k) in self.keys_for(domains) {
            let g = self.profile.gcra(bucket);
            let stored = self.file.tats.get(&Self::key(bucket, &k)).copied();
            if gcra_admit(stored, now_us, g).is_none() {
                return Decision::Defer {
                    bucket,
                    retry_at_unix: (g.next_admit_at(stored, now_us) / 1_000_000) as i64,
                };
            }
        }
        Decision::Allow
    }

    /// Debit every bucket and persist, **before** the order is sent.
    ///
    /// Ordering is the whole point. An order that reaches the CA may have been counted by it even if
    /// the response never arrives, so a debit that happened only on success would let a failing loop
    /// spend the real allowance while the local ledger showed it untouched. There is deliberately no
    /// refund on failure, for the same reason.
    pub fn debit(&mut self, domains: &[String], now_unix: i64) -> Result<()> {
        let now_us = (now_unix.max(0) as u64).saturating_mul(1_000_000);
        for (bucket, k) in self.keys_for(domains) {
            let g = self.profile.gcra(bucket);
            let key = Self::key(bucket, &k);
            let stored = self.file.tats.get(&key).copied();
            if let Some(new_tat) = gcra_admit(stored, now_us, g) {
                self.file.tats.insert(key, new_tat);
            }
        }
        self.persist()
    }

    fn keys_for(&self, domains: &[String]) -> Vec<(Bucket, String)> {
        let mut out = vec![
            (Bucket::Orders, "account".to_string()),
            (Bucket::IdentifierSet, identifier_set_key(domains)),
        ];
        // One entry per distinct registered domain in the request.
        let mut groups: Vec<String> = domains.iter().map(|d| group_key(d)).collect();
        groups.sort();
        groups.dedup();
        for g in groups {
            out.push((Bucket::RegisteredDomain, g));
        }
        out
    }

    /// Write the ledger atomically: a torn file would be unparseable and silently reset the budget
    /// to empty, which is the one failure mode that looks like everything is fine.
    fn persist(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let body = serde_json::to_string(&self.file).context("serialising the issuance ledger")?;
        std::fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming into {}", self.path.display()))?;
        Ok(())
    }

    /// Remaining admissions per bucket, for metrics and for the operator's warning before
    /// exhaustion rather than after.
    pub fn remaining(&self, domains: &[String], now_unix: i64) -> Vec<(Bucket, String, u64)> {
        let now_us = (now_unix.max(0) as u64).saturating_mul(1_000_000);
        self.keys_for(domains)
            .into_iter()
            .map(|(bucket, k)| {
                let stored = self.file.tats.get(&Self::key(bucket, &k)).copied();
                let left = self.profile.gcra(bucket).remaining(stored, now_us);
                (bucket, k, left)
            })
            .collect()
    }

    pub fn ca_name(&self) -> &'static str {
        self.profile.name
    }
}

/// Unix seconds now.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Render the budget as Prometheus text, so an operator sees it draining rather than gone.
///
/// Deliberately a gauge per bucket rather than a single "is it exhausted" flag: the alert that
/// matters fires at 60% consumed, days before the outage, and a boolean cannot say that.
///
/// The identifier-set key is a tenant's full hostname list, so it is **hashed** into the label.
/// Putting it in plaintext would publish the customer's domain names to whoever can read
/// `/metrics`; the mapping stays behind the authenticated API.
pub fn render_metrics(budget: &IssuanceBudget, domains: &[String], now_unix: i64) -> String {
    let mut out = String::new();
    // The help text names the scope, because the number is easy to misread as a fleet total and an
    // operator would size a rollout against it. The registered_domain bucket in particular is
    // SHARED with every other edge under that domain; this gauge only knows what this edge spent.
    out.push_str(
        "# HELP edgeguard_acme_budget_remaining Issuance THIS EDGE's own ledger still allows, per bucket. Not a fleet total: the registered_domain limit is shared across every edge under that domain, and the control plane's GET /v3/acme/budget is the fleet figure.\n",
    );
    out.push_str("# TYPE edgeguard_acme_budget_remaining gauge\n");
    for (bucket, key, left) in budget.remaining(domains, now_unix) {
        let label = match bucket {
            Bucket::IdentifierSet => short_hash(&key),
            _ => key.clone(),
        };
        out.push_str(&format!(
            "edgeguard_acme_budget_remaining{{ca=\"{}\",bucket=\"{}\",key=\"{}\"}} {left}\n",
            budget.ca_name(),
            bucket.label(),
            escape_label(&label),
        ));
    }
    out
}

/// A short, stable, non-reversible label for a hostname set.
fn short_hash(s: &str) -> String {
    // FNV-1a, 64-bit. Not a cryptographic commitment — it only has to be stable and to not be the
    // customer's domain list in plaintext.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{h:016x}")
}

/// Prometheus label values may not carry a raw `"` or `\`.
fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Log a deferral in the form an operator can act on.
pub fn warn_deferred(bucket: Bucket, retry_at_unix: i64, domains: &[String]) {
    warn!(
        bucket = bucket.label(),
        retry_at_unix,
        domains = ?domains,
        "ACME issuance deferred: the CA's rate limit for this bucket is exhausted. \
         The existing certificate (if any) keeps serving; no self-signed certificate is \
         substituted on a public name."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(dir: &Path) -> IssuanceBudget {
        IssuanceBudget::load(
            "https://acme-v02.api.letsencrypt.org/directory",
            dir.to_str().unwrap(),
        )
        .expect("letsencrypt profile")
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("eg-acme-budget-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_identifier_set_bucket_stops_a_restart_loop_at_five() {
        // THE failure this module exists for. An edge whose cert cache is not durable re-orders the
        // same identifier set on every boot; the CA allows five per week and then refuses for a
        // week. The sixth attempt must be refused HERE, before the CA counts it.
        let d = tmpdir("restart");
        let mut b = budget(&d);
        let domains = vec!["edge.example.com".to_string()];
        let now = 1_800_000_000;

        for i in 0..5 {
            assert_eq!(
                b.check(&domains, now),
                Decision::Allow,
                "order {i} must be allowed"
            );
            b.debit(&domains, now).unwrap();
        }
        match b.check(&domains, now) {
            Decision::Defer {
                bucket,
                retry_at_unix,
            } => {
                assert_eq!(bucket, Bucket::IdentifierSet);
                assert!(retry_at_unix > now, "a deferral must say when to retry");
            }
            Decision::Allow => panic!("the sixth order must be deferred"),
        }
    }

    #[test]
    fn the_budget_survives_a_restart() {
        // A budget that resets on restart is no budget: restarts are the event it exists to
        // survive, and its ledger lives in the ACME cache dir for exactly that reason.
        let d = tmpdir("persist");
        let domains = vec!["edge.example.com".to_string()];
        let now = 1_800_000_000;
        {
            let mut b = budget(&d);
            for _ in 0..5 {
                b.debit(&domains, now).unwrap();
            }
        }
        // A fresh process, same cache directory.
        let b2 = budget(&d);
        assert!(
            matches!(b2.check(&domains, now), Decision::Defer { .. }),
            "the ledger must be read back from disk"
        );
    }

    #[test]
    fn the_bucket_refills_over_time_rather_than_resetting_at_a_boundary() {
        // Let's Encrypt publishes these as token buckets with refill rates, not fixed windows. A
        // fixed-window model believes the whole allowance returns at a boundary and permits a burst
        // the CA refuses — wrong in the dangerous direction.
        let d = tmpdir("refill");
        let mut b = budget(&d);
        let domains = vec!["edge.example.com".to_string()];
        let now = 1_800_000_000;
        for _ in 0..5 {
            b.debit(&domains, now).unwrap();
        }
        assert!(matches!(b.check(&domains, now), Decision::Defer { .. }));

        // The identifier-set bucket refills one per emission interval, which is exactly
        // 7 days / 5 = 120 960 s = 33.6 h. Let's Encrypt publishes this as "1 every 34 hours",
        // rounded; the model uses the exact quotient, which is what reproduces their limit over a
        // full window rather than drifting by 0.4 h per token.
        const EI: i64 = 7 * 86_400 / 5;
        assert!(matches!(
            b.check(&domains, now + EI - 60),
            Decision::Defer { .. }
        ));
        assert_eq!(b.check(&domains, now + EI + 60), Decision::Allow);
        // And one refill is one token, not a reset: a second order at the same instant is refused.
        b.debit(&domains, now + EI + 60).unwrap();
        assert!(matches!(
            b.check(&domains, now + EI + 60),
            Decision::Defer { .. }
        ));
    }

    #[test]
    fn a_different_identifier_set_has_its_own_bucket() {
        let d = tmpdir("sets");
        let mut b = budget(&d);
        let now = 1_800_000_000;
        let a = vec!["a.example.com".to_string()];
        for _ in 0..5 {
            b.debit(&a, now).unwrap();
        }
        assert!(matches!(b.check(&a, now), Decision::Defer { .. }));
        // A different set under the same registered domain still has 45 of the domain bucket left.
        let c = vec!["b.example.com".to_string()];
        assert_eq!(b.check(&c, now), Decision::Allow);
    }

    #[test]
    fn the_registered_domain_bucket_binds_across_different_hostnames() {
        let d = tmpdir("domain");
        let mut b = budget(&d);
        let now = 1_800_000_000;
        // 50 distinct hostnames under one registered domain exhausts the 50/7d domain bucket, even
        // though each identifier set is used once.
        for i in 0..50 {
            let h = vec![format!("h{i}.example.com")];
            assert_eq!(b.check(&h, now), Decision::Allow, "host {i}");
            b.debit(&h, now).unwrap();
        }
        let next = vec!["h50.example.com".to_string()];
        match b.check(&next, now) {
            Decision::Defer { bucket, .. } => assert_eq!(bucket, Bucket::RegisteredDomain),
            Decision::Allow => panic!("the 51st registered-domain order must be deferred"),
        }
        // A different registered domain is unaffected.
        assert_eq!(b.check(&["x.other.com".to_string()], now), Decision::Allow);
    }

    #[test]
    fn identifier_set_key_is_order_and_case_insensitive() {
        // The CA matches the SET. Treating a reordering as a new set would let a caller bypass the
        // bucket entirely by shuffling its SAN list.
        let a = identifier_set_key(&["b.example.com".into(), "A.example.com".into()]);
        let b = identifier_set_key(&["a.example.com".into(), "B.EXAMPLE.COM.".into()]);
        assert_eq!(a, b);
        // ...and a genuinely different set is a different key.
        assert_ne!(a, identifier_set_key(&["a.example.com".into()]));
    }

    #[test]
    fn group_key_errs_toward_merging_never_splitting() {
        // Splitting one CA bucket into two would let issuance through that the CA then refuses —
        // the only error direction that matters. Merging is merely stricter than necessary.
        assert_eq!(group_key("a.b.example.com"), "example.com");
        assert_eq!(group_key("example.com"), "example.com");
        assert_eq!(group_key("EXAMPLE.COM."), "example.com");
        // The known-wrong case, wrong safely: every .co.uk shares one bucket.
        assert_eq!(group_key("a.example.co.uk"), "co.uk");
        assert_eq!(group_key("b.other.co.uk"), "co.uk");
        // Literals and short names pass through.
        assert_eq!(group_key("127.0.0.1"), "127.0.0.1");
        assert_eq!(group_key("localhost"), "localhost");
    }

    #[test]
    fn an_unrecognised_ca_gets_no_budget() {
        // Holding a private or commercial CA to Let's Encrypt's numbers would refuse orders it
        // would have accepted — a self-inflicted outage from a guard.
        let d = tmpdir("unknown");
        assert!(
            IssuanceBudget::load("https://acme.internal/directory", d.to_str().unwrap()).is_none()
        );
        assert!(CaProfile::for_directory("https://ca.example.com/dir").is_none());
        // Staging IS budgeted, deliberately: it is the compiled-in default, so leaving it inert
        // would mean this code is never exercised in the configuration most deployments start from.
        assert!(
            CaProfile::for_directory("https://acme-staging-v02.api.letsencrypt.org/directory")
                .is_some()
        );
    }

    #[test]
    fn metrics_never_publish_the_customers_hostname_set() {
        // /metrics is commonly scraped by something less privileged than the API. The identifier-set
        // key is the tenant's full hostname list and must not appear there in plaintext.
        let d = tmpdir("metrics");
        let b = budget(&d);
        let domains = vec!["secret-customer.example.com".to_string()];
        let text = render_metrics(&b, &domains, 1_800_000_000);
        assert!(
            !text.contains("secret-customer"),
            "the hostname set leaked into /metrics:\n{text}"
        );
        // The registered domain IS published — it is the bucket the CA groups by, and an operator
        // cannot act on the alert without it.
        assert!(
            text.contains("bucket=\"registered_domain\",key=\"example.com\""),
            "{text}"
        );
        assert!(text.contains("edgeguard_acme_budget_remaining"), "{text}");
    }

    #[test]
    fn remaining_counts_down_and_is_reported_per_bucket() {
        let d = tmpdir("remaining");
        let mut b = budget(&d);
        let domains = vec!["edge.example.com".to_string()];
        let now = 1_800_000_000;
        let before = b.remaining(&domains, now);
        let set_before = before
            .iter()
            .find(|(bk, _, _)| *bk == Bucket::IdentifierSet)
            .unwrap()
            .2;
        assert_eq!(set_before, 5);
        b.debit(&domains, now).unwrap();
        let after = b.remaining(&domains, now);
        let set_after = after
            .iter()
            .find(|(bk, _, _)| *bk == Bucket::IdentifierSet)
            .unwrap()
            .2;
        assert_eq!(
            set_after, 4,
            "an operator must see the budget draining before it is gone"
        );
    }
}
