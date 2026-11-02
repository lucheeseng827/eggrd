//! BYO-key vault + egress governance (gateway L2).
//!
//! The security wedge: clients authenticate with a **virtual key**; the real **provider key** (the
//! upstream's `sk-…` secret) lives only on the edge and is injected into the upstream request on the
//! way out. A client — or a compromised one — never sees a provider key, and a leaked virtual key is
//! revoked by deleting one vault entry without rotating the provider credential.
//!
//! Two controls per key:
//!   * **key swap** — the presented virtual key is replaced by its mapped provider key in the
//!     upstream `Authorization`, so the provider secret never appears in the client surface or logs;
//!   * **egress allowlist** — an optional set of model names the key may reach; a request for any
//!     other model is denied `403` (fail-closed once a list is set).
//!
//! Virtual keys are matched by a **constant-time** comparison that scans every entry (mirroring the
//! API-key gate in [`crate::auth`]), so the match time doesn't reveal which key — if any — was hit.
//! Provider keys are held in memory as configured (encryption-at-rest is a property of wherever the
//! config/secret is stored, e.g. the control-plane secret store that pushes them).
//!
//! When any `[[llm.keys]]` is configured the vault is **enabled for all proxied traffic**: a request
//! without a known virtual key is rejected `401` before it reaches the upstream.
//!
//! **Chosen by a workload's identity.** An entry may name the `claims` of a verified JWT in place
//! of a virtual key ([`KeyVault::lookup_claims`]): with `auth.mode = "jwt"` against a CI system's
//! issuer, a job presents the short-lived OIDC token its run was given, and the entry its claims
//! match (its repository, its trust class) has its provider key injected. The job holds no key at
//! all, and a token that leaks is good for minutes, for the one run it names.

use std::collections::HashSet;

use anyhow::Result;

use crate::config::{AuthCfg, LlmCfg};

/// One resolved vault entry: the provider secret to inject and the model egress policy.
pub struct VaultEntry {
    /// The client-facing secret this entry matches (compared constant-time on lookup). Empty for
    /// an entry chosen by its `claims` instead.
    virtual_key: String,
    /// The verified JWT claims this entry is chosen by, each to one of its values; empty for an
    /// entry chosen by its virtual key.
    claims: Vec<(String, Vec<String>)>,
    provider_key: String,
    /// Egress allowlist of model names; empty means unrestricted.
    allowed_models: HashSet<String>,
    /// Non-secret label for logs / metrics / audit.
    label: String,
}

impl VaultEntry {
    /// The real provider secret to inject upstream. Not exposed beyond the proxy boundary.
    pub fn provider_key(&self) -> &str {
        &self.provider_key
    }

    /// The non-secret label (e.g. a team / tenant name) for logging.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Whether `model` is permitted for this key. An empty allowlist permits any model; a non-empty
    /// one permits only listed models (fail-closed for everything else, including `None` — a request
    /// whose model cannot be parsed is denied when an allowlist is set).
    pub fn model_allowed(&self, model: Option<&str>) -> bool {
        self.allowed_models.is_empty() || model.is_some_and(|m| self.allowed_models.contains(m))
    }
}

/// The configured vault entries. Built once per config (re)load and carried on the proxy
/// [`Runtime`](crate::proxy::Runtime).
pub struct KeyVault {
    entries: Vec<VaultEntry>,
}

impl KeyVault {
    /// Build the vault from `[llm].keys`. Returns `Ok(None)` when no keys are configured (the proxy
    /// then skips vault enforcement entirely). Rejects an empty virtual/provider key or a duplicate
    /// virtual key, so a broken config fails at startup/reload rather than per-request.
    pub fn build(cfg: &LlmCfg) -> Result<Option<KeyVault>> {
        if cfg.keys.is_empty() {
            return Ok(None);
        }
        let mut entries: Vec<VaultEntry> = Vec::with_capacity(cfg.keys.len());
        for (i, k) in cfg.keys.iter().enumerate() {
            anyhow::ensure!(
                k.virtual_key.is_empty() || k.claims.is_empty(),
                "llm.keys[{i}] sets both virtual_key and claims: an entry is chosen by one"
            );
            for (claim, values) in &k.claims {
                anyhow::ensure!(
                    !claim.trim().is_empty() && !values.is_empty(),
                    "llm.keys[{i}].claims.{claim}: a claim names at least one value"
                );
                anyhow::ensure!(
                    values.iter().all(|v| !v.is_empty() && v != "*"),
                    "llm.keys[{i}].claims.{claim}: a value is not empty, and not `*` alone \
                     (leave the claim out to take any)"
                );
            }
            anyhow::ensure!(
                !k.virtual_key.is_empty() || !k.claims.is_empty(),
                "llm.keys[{i}].virtual_key must not be empty (or name the entry's claims)"
            );
            anyhow::ensure!(
                k.virtual_key == k.virtual_key.trim(),
                "llm.keys[{i}].virtual_key must not have leading/trailing whitespace"
            );
            anyhow::ensure!(
                !k.provider_key.is_empty(),
                "llm.keys[{i}].provider_key must not be empty"
            );
            anyhow::ensure!(
                k.provider_key == k.provider_key.trim(),
                "llm.keys[{i}].provider_key must not have leading/trailing whitespace"
            );
            anyhow::ensure!(
                k.virtual_key.is_empty() || !entries.iter().any(|e| e.virtual_key == k.virtual_key),
                "llm.keys[{i}]: duplicate virtual_key"
            );
            let label = if k.label.trim().is_empty() {
                format!("key{i}")
            } else {
                k.label.clone()
            };
            entries.push(VaultEntry {
                virtual_key: k.virtual_key.clone(),
                claims: k
                    .claims
                    .iter()
                    .map(|(c, v)| (c.clone(), v.clone()))
                    .collect(),
                provider_key: k.provider_key.clone(),
                allowed_models: k.allowed_models.iter().cloned().collect(),
                label,
            });
        }
        Ok(Some(KeyVault { entries }))
    }

    /// Resolve a presented virtual key to its entry, or `None` if unknown. Scans **every** entry
    /// with a constant-time comparison so the lookup time doesn't reveal which key matched (the same
    /// discipline as [`crate::auth`]'s API-key check).
    pub fn lookup(&self, presented: &str) -> Option<&VaultEntry> {
        let mut matched: Option<&VaultEntry> = None;
        for entry in &self.entries {
            // An entry chosen by claims has no virtual key, and never matches one.
            if !entry.virtual_key.is_empty()
                && constant_time_eq(entry.virtual_key.as_bytes(), presented.as_bytes())
            {
                matched = Some(entry);
            }
        }
        matched
    }

    /// Resolve the verified claims of the request's JWT to the first entry whose every claim
    /// matches, or `None`. Only entries that name claims are asked; the claims are the issuer's
    /// word (the token was verified before this is asked), never the client's.
    pub fn lookup_claims(&self, claims: &serde_json::Value) -> Option<&VaultEntry> {
        self.entries.iter().find(|entry| {
            !entry.claims.is_empty()
                && entry
                    .claims
                    .iter()
                    .all(|(name, values)| claim_matches(claims.get(name), values))
        })
    }
}

/// An entry chosen by `claims` takes the token's word for whose it is, so the token must be one
/// meant for this gateway: verified (`auth.mode = "jwt"`) as of one issuer and one audience.
/// Without `auth.jwt.audience`, a token its issuer minted for another service would choose the
/// entry; without `auth.jwt.issuer`, any token the key or JWKS verifies would. Refused at load.
pub fn check_claims_auth(auth: &AuthCfg, llm: &LlmCfg) -> Result<()> {
    let Some(i) = llm.keys.iter().position(|k| !k.claims.is_empty()) else {
        return Ok(());
    };
    anyhow::ensure!(
        auth.mode == "jwt",
        "llm.keys[{i}] is chosen by claims, which are read only of a verified JWT: set \
         auth.mode = \"jwt\""
    );
    anyhow::ensure!(
        !auth.jwt.issuer.trim().is_empty() && !auth.jwt.audience.trim().is_empty(),
        "llm.keys[{i}] is chosen by claims: set auth.jwt.issuer and auth.jwt.audience, or a token \
         of another issuer, or one minted for another audience, would choose it"
    );
    Ok(())
}

/// Whether a claim's value is one of `values`: a string, number or boolean as written, or any
/// string of a list (as `aud` may be). A value ending in `*` matches any rest.
fn claim_matches(claim: Option<&serde_json::Value>, values: &[String]) -> bool {
    let one = |text: &str| {
        values.iter().any(|v| match v.strip_suffix('*') {
            Some(prefix) => text.starts_with(prefix),
            None => text == v,
        })
    };
    match claim {
        Some(serde_json::Value::String(s)) => one(s),
        Some(serde_json::Value::Number(n)) => one(&n.to_string()),
        Some(serde_json::Value::Bool(b)) => one(&b.to_string()),
        Some(serde_json::Value::Array(items)) => items.iter().any(|i| i.as_str().is_some_and(one)),
        _ => false,
    }
}

/// Constant-time byte comparison: folds every byte *and the length mismatch* into one `usize`
/// accumulator, so the execution path is identical regardless of where (or whether) the bytes
/// differ. Returning early on a length mismatch would let an attacker distinguish "wrong length"
/// from "right length, wrong bytes" by timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeyEntryCfg;

    fn cfg(keys: Vec<KeyEntryCfg>) -> LlmCfg {
        LlmCfg {
            enabled: true,
            keys,
            ..Default::default()
        }
    }

    fn entry(virtual_key: &str, provider_key: &str, models: &[&str]) -> KeyEntryCfg {
        KeyEntryCfg {
            virtual_key: virtual_key.into(),
            provider_key: provider_key.into(),
            allowed_models: models.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn by_claims(claims: &[(&str, &[&str])], provider_key: &str, label: &str) -> KeyEntryCfg {
        KeyEntryCfg {
            claims: claims
                .iter()
                .map(|(c, v)| (c.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect(),
            provider_key: provider_key.into(),
            label: label.into(),
            ..Default::default()
        }
    }

    /// A workload's verified claims choose its entry: the first whose every claim matches, by
    /// value or by prefix; a token whose claims match none is given no key, and a virtual key
    /// never chooses an entry by claims.
    #[test]
    fn a_jwt_s_claims_choose_the_entry_they_match() {
        let vault = KeyVault::build(&cfg(vec![
            entry("sk-virt-a", "sk-real-a", &[]),
            by_claims(
                &[
                    ("iss", &["https://dagron.example.com"]),
                    ("trust", &["agent"]),
                    ("repository", &["acme/*"]),
                ],
                "sk-real-agents",
                "dagron-agents",
            ),
            by_claims(
                &[
                    ("iss", &["https://dagron.example.com"]),
                    ("trust", &["trusted"]),
                ],
                "sk-real-ci",
                "dagron-ci",
            ),
        ]))
        .unwrap()
        .unwrap();
        let claims = |trust: &str, repository: &str| {
            serde_json::json!({
                "iss": "https://dagron.example.com", "aud": ["eggrd"], "trust": trust,
                "repository": repository, "run_id": "run-1",
            })
        };
        assert_eq!(
            vault
                .lookup_claims(&claims("agent", "acme/widgets"))
                .unwrap()
                .label(),
            "dagron-agents"
        );
        assert_eq!(
            vault
                .lookup_claims(&claims("trusted", "other/x"))
                .unwrap()
                .label(),
            "dagron-ci"
        );
        assert!(
            vault.lookup_claims(&claims("agent", "other/x")).is_none(),
            "not acme's"
        );
        assert!(vault
            .lookup_claims(&claims("untrusted", "acme/widgets"))
            .is_none());
        assert!(vault.lookup_claims(&serde_json::json!({})).is_none());
        // A virtual key's entry is not chosen by claims, nor a claims entry by a key.
        assert!(vault.lookup("").is_none());
        assert_eq!(
            vault.lookup("sk-virt-a").unwrap().provider_key(),
            "sk-real-a"
        );
        assert!(claim_matches(
            Some(&serde_json::json!(["a", "eggrd"])),
            &["eggrd".into()]
        ));
        assert!(claim_matches(Some(&serde_json::json!(7)), &["7".into()]));

        // An entry is chosen by one or the other, and a claim names what it takes.
        let both = KeyEntryCfg {
            virtual_key: "sk-v".into(),
            ..by_claims(&[("trust", &["agent"])], "sk-r", "x")
        };
        assert!(KeyVault::build(&cfg(vec![both])).is_err());
        assert!(KeyVault::build(&cfg(vec![by_claims(&[("trust", &[])], "sk-r", "x")])).is_err());
        assert!(KeyVault::build(&cfg(vec![by_claims(&[("trust", &["*"])], "sk-r", "x")])).is_err());
        // Two claims entries need no virtual key to tell them apart.
        assert!(KeyVault::build(&cfg(vec![
            by_claims(&[("trust", &["agent"])], "sk-r", "a"),
            by_claims(&[("trust", &["trusted"])], "sk-r", "b"),
        ]))
        .unwrap()
        .is_some());
    }

    /// An entry chosen by claims is refused without a JWT gate bound to one issuer and one
    /// audience; a vault of virtual keys alone asks for neither.
    #[test]
    fn claims_need_a_jwt_of_one_issuer_and_one_audience() {
        let llm = cfg(vec![by_claims(&[("trust", &["agent"])], "sk-r", "a")]);
        let jwt = |issuer: &str, audience: &str| AuthCfg {
            mode: "jwt".into(),
            jwt: crate::config::JwtCfg {
                issuer: issuer.into(),
                audience: audience.into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(check_claims_auth(&jwt("https://ci.example.com", "eggrd"), &llm).is_ok());
        for (auth, says) in [
            (AuthCfg::default(), "auth.mode"),
            (jwt("", "eggrd"), "auth.jwt.issuer"),
            (jwt("https://ci.example.com", ""), "auth.jwt.audience"),
        ] {
            let e = check_claims_auth(&auth, &llm).unwrap_err().to_string();
            assert!(e.contains(says), "{e}");
        }
        let keys = cfg(vec![entry("sk-virt-a", "sk-real-a", &[])]);
        assert!(check_claims_auth(&AuthCfg::default(), &keys).is_ok());
    }

    #[test]
    fn build_is_none_without_keys() {
        assert!(KeyVault::build(&LlmCfg::default()).unwrap().is_none());
    }

    #[test]
    fn lookup_maps_virtual_to_provider_key() {
        let vault = KeyVault::build(&cfg(vec![entry("sk-virt-a", "sk-real-a", &[])]))
            .unwrap()
            .unwrap();
        let e = vault.lookup("sk-virt-a").expect("known key resolves");
        assert_eq!(e.provider_key(), "sk-real-a");
        // An unknown virtual key resolves to nothing (caller rejects 401).
        assert!(vault.lookup("sk-virt-unknown").is_none());
        // The provider key is never itself a valid virtual key.
        assert!(vault.lookup("sk-real-a").is_none());
    }

    #[test]
    fn egress_allowlist_enforced_when_set() {
        let vault = KeyVault::build(&cfg(vec![entry(
            "sk-virt-a",
            "sk-real-a",
            &["gpt-4o", "gpt-4o-mini"],
        )]))
        .unwrap()
        .unwrap();
        let e = vault.lookup("sk-virt-a").unwrap();
        assert!(e.model_allowed(Some("gpt-4o")));
        assert!(!e.model_allowed(Some("o1-preview"))); // not on the allowlist → denied
        assert!(!e.model_allowed(None)); // unparseable model → fail-closed when allowlist set
    }

    #[test]
    fn empty_allowlist_permits_any_model() {
        let vault = KeyVault::build(&cfg(vec![entry("sk-virt-a", "sk-real-a", &[])]))
            .unwrap()
            .unwrap();
        let e = vault.lookup("sk-virt-a").unwrap();
        assert!(e.model_allowed(Some("anything-goes")));
        assert!(e.model_allowed(None)); // empty allowlist → unrestricted even without a model
    }

    #[test]
    fn rejects_empty_or_duplicate_keys() {
        // Empty provider key.
        assert!(KeyVault::build(&cfg(vec![entry("sk-v", "", &[])])).is_err());
        // Empty virtual key.
        assert!(KeyVault::build(&cfg(vec![entry("", "sk-real", &[])])).is_err());
        // Duplicate virtual key across two entries.
        assert!(KeyVault::build(&cfg(vec![
            entry("sk-dup", "sk-real-1", &[]),
            entry("sk-dup", "sk-real-2", &[]),
        ]))
        .is_err());
    }

    #[test]
    fn rejects_whitespace_padded_keys() {
        // A virtual key with a leading space would never match a client's presented key (which
        // wouldn't have the space), so catch it at build time rather than silently creating a
        // dead entry.
        assert!(KeyVault::build(&cfg(vec![entry(" sk-v", "sk-real", &[])])).is_err());
        assert!(KeyVault::build(&cfg(vec![entry("sk-v ", "sk-real", &[])])).is_err());
        assert!(KeyVault::build(&cfg(vec![entry("sk-v", " sk-real", &[])])).is_err());
        assert!(KeyVault::build(&cfg(vec![entry("sk-v", "sk-real ", &[])])).is_err());
    }

    #[test]
    fn label_defaults_to_positional_id() {
        let vault = KeyVault::build(&cfg(vec![entry("sk-v", "sk-r", &[])]))
            .unwrap()
            .unwrap();
        assert_eq!(vault.lookup("sk-v").unwrap().label(), "key0");
    }
}
