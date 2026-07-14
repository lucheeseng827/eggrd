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

use std::collections::HashSet;

use anyhow::Result;

use crate::config::LlmCfg;

/// One resolved vault entry: the provider secret to inject and the model egress policy.
pub struct VaultEntry {
    /// The client-facing secret this entry matches (compared constant-time on lookup).
    virtual_key: String,
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
                !k.virtual_key.is_empty(),
                "llm.keys[{i}].virtual_key must not be empty"
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
                !entries.iter().any(|e| e.virtual_key == k.virtual_key),
                "llm.keys[{i}]: duplicate virtual_key"
            );
            let label = if k.label.trim().is_empty() {
                format!("key{i}")
            } else {
                k.label.clone()
            };
            entries.push(VaultEntry {
                virtual_key: k.virtual_key.clone(),
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
            if constant_time_eq(entry.virtual_key.as_bytes(), presented.as_bytes()) {
                matched = Some(entry);
            }
        }
        matched
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
            label: String::new(),
        }
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
