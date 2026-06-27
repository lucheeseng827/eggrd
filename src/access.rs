//! IP allow/deny lists with CIDR matching.
//!
//! A front door often needs a coarse network gate independent of auth — "lock `/admin` (or the
//! whole app) to the office IP / VPN range", "drop this abusive subnet". `[access]` provides it:
//! `allow` and `deny` lists of plain IPs and CIDR ranges, evaluated against the resolved client
//! IP before auth and rate limiting. `deny` wins over `allow`; a non-empty `allow` is a
//! whitelist. Compiled into an [`AccessPolicy`] held on the hot-swappable runtime (`None` when
//! both lists are empty, so the proxy skips the check entirely).
//!
//! CIDR matching is implemented directly (no extra dependency): each entry is normalized to a
//! base address + prefix length, and an address matches when its high `prefix` bits equal the
//! base's. IPv4 and IPv6 are kept separate — a v4 client never matches a v6 rule, and
//! vice-versa.

use std::net::IpAddr;

use anyhow::{Context, Result};

use crate::config::AccessCfg;

/// A single CIDR rule: a base address and a prefix length, kept per family. A bare IP is stored
/// as a full-length prefix (`/32` for v4, `/128` for v6).
#[derive(Debug, Clone, Copy)]
enum Cidr {
    V4 { base: u32, prefix: u8 },
    V6 { base: u128, prefix: u8 },
}

impl Cidr {
    /// Parse `"10.0.0.0/8"`, `"203.0.113.7"`, `"2001:db8::/32"`, or `"::1"`. The host bits below
    /// the prefix are masked off, so `"10.1.2.3/8"` is accepted and treated as `10.0.0.0/8`.
    fn parse(s: &str) -> Result<Cidr> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_part
            .parse()
            .with_context(|| format!("invalid IP/CIDR address {s:?}"))?;
        match addr {
            IpAddr::V4(v4) => {
                let prefix = match prefix_part {
                    Some(p) => p
                        .parse::<u8>()
                        .ok()
                        .filter(|p| *p <= 32)
                        .with_context(|| format!("invalid IPv4 CIDR prefix in {s:?} (0-32)"))?,
                    None => 32,
                };
                let base = u32::from(v4) & mask_v4(prefix);
                Ok(Cidr::V4 { base, prefix })
            }
            IpAddr::V6(v6) => {
                let prefix = match prefix_part {
                    Some(p) => p
                        .parse::<u8>()
                        .ok()
                        .filter(|p| *p <= 128)
                        .with_context(|| format!("invalid IPv6 CIDR prefix in {s:?} (0-128)"))?,
                    None => 128,
                };
                let base = u128::from(v6) & mask_v6(prefix);
                Ok(Cidr::V6 { base, prefix })
            }
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { base, prefix }, IpAddr::V4(v4)) => {
                u32::from(v4) & mask_v4(*prefix) == *base
            }
            (Cidr::V6 { base, prefix }, IpAddr::V6(v6)) => {
                u128::from(v6) & mask_v6(*prefix) == *base
            }
            // Cross-family never matches (a v4 client vs a v6 rule, or vice-versa).
            _ => false,
        }
    }
}

/// The `/prefix` network mask for IPv4. `prefix == 0` yields `0` (matches everything) without the
/// undefined-behavior of a 32-bit shift by 32.
fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Compiled allow/deny policy.
pub struct AccessPolicy {
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
}

impl AccessPolicy {
    /// Compile the lists, or `Ok(None)` when both are empty (no gating). An unparseable entry is a
    /// hard error so a typo'd range fails at startup/reload rather than silently letting traffic
    /// through (or, worse, silently blocking it).
    pub fn build(cfg: &AccessCfg) -> Result<Option<AccessPolicy>> {
        if cfg.allow.is_empty() && cfg.deny.is_empty() {
            return Ok(None);
        }
        let allow = cfg
            .allow
            .iter()
            .map(|s| Cidr::parse(s))
            .collect::<Result<_>>()?;
        let deny = cfg
            .deny
            .iter()
            .map(|s| Cidr::parse(s))
            .collect::<Result<_>>()?;
        Ok(Some(AccessPolicy { allow, deny }))
    }

    /// Whether `ip` may proceed. `deny` is checked first (it wins), then — if `allow` is
    /// non-empty — the address must be in it; an empty `allow` admits anything not denied.
    pub fn allowed(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|c| c.contains(ip)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|c| c.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn policy(allow: &[&str], deny: &[&str]) -> AccessPolicy {
        AccessPolicy::build(&AccessCfg {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        })
        .unwrap()
        .unwrap()
    }

    #[test]
    fn empty_lists_build_to_none() {
        assert!(AccessPolicy::build(&AccessCfg::default())
            .unwrap()
            .is_none());
    }

    #[test]
    fn allowlist_is_a_whitelist() {
        let p = policy(&["10.0.0.0/8", "203.0.113.7"], &[]);
        assert!(p.allowed(ip("10.1.2.3")));
        assert!(p.allowed(ip("203.0.113.7")));
        assert!(!p.allowed(ip("8.8.8.8")));
    }

    #[test]
    fn deny_wins_over_allow() {
        let p = policy(&["10.0.0.0/8"], &["10.0.0.5"]);
        assert!(p.allowed(ip("10.0.0.6")));
        assert!(!p.allowed(ip("10.0.0.5")));
    }

    #[test]
    fn deny_only_blocks_listed_and_admits_rest() {
        let p = policy(&[], &["192.168.0.0/16"]);
        assert!(!p.allowed(ip("192.168.1.1")));
        assert!(p.allowed(ip("203.0.113.1")));
    }

    #[test]
    fn ipv6_and_cross_family() {
        let p = policy(&["2001:db8::/32"], &[]);
        assert!(p.allowed(ip("2001:db8::1")));
        assert!(!p.allowed(ip("2001:dead::1")));
        // A v4 client never matches a v6-only allowlist.
        assert!(!p.allowed(ip("10.0.0.1")));
    }

    #[test]
    fn rejects_bad_entries() {
        assert!(AccessPolicy::build(&AccessCfg {
            allow: vec!["not-an-ip".into()],
            deny: vec![],
        })
        .is_err());
        assert!(AccessPolicy::build(&AccessCfg {
            allow: vec!["10.0.0.0/99".into()],
            deny: vec![],
        })
        .is_err());
    }
}
