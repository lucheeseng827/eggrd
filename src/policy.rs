//! The policy the proxy runs, and in managed mode its last-known-good copy on disk.
//!
//! The live [`Runtime`] is built from two layers: the edge's own config file, and — in managed
//! mode — the policy pulled from the control plane on top of it
//! ([`Config::with_policy_from`]). [`Policy`] holds both and is the only thing that rebuilds the
//! runtime, so neither source can discard the other's layer: a config-file edit keeps the pushed
//! policy, and a new pushed policy keeps the file's edge-local sections.
//!
//! The pushed layer is also written to `control_plane.cache_path` each time one is applied, and
//! read back at startup ([`Policy::restore_cached`]). Without it, "edges keep serving their last
//! policy when the control plane is down" held only until the edge restarted: it then came up on
//! the config file alone, which is usually the looser of the two.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::Config;
use crate::proxy::Runtime;

/// A policy document from the control plane: its body and the ETag it was served with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pushed {
    pub etag: String,
    pub body: String,
}

/// The two layers of policy, and the runtime built from them.
pub struct Policy {
    layers: Mutex<Layers>,
    runtime: Arc<ArcSwap<Runtime>>,
    cache: Option<Cache>,
    /// Shared with the request path: set while `boot_without_policy = "refuse"` and no pushed
    /// policy has been applied yet.
    pending: Arc<AtomicBool>,
}

struct Layers {
    local: Arc<Config>,
    pushed: Option<Pushed>,
}

impl Policy {
    /// Hold the runtime `local` was built into. In managed mode, reads `cache_path` and
    /// `boot_without_policy` from `local.control_plane`; `refuse` sets `pending` until a pushed
    /// policy is applied.
    pub fn new(
        local: Arc<Config>,
        runtime: Arc<ArcSwap<Runtime>>,
        pending: Arc<AtomicBool>,
    ) -> Result<Arc<Policy>> {
        let cp = &local.control_plane;
        let refuse = match cp.boot_without_policy.as_str() {
            "local" => false,
            "refuse" => true,
            other => anyhow::bail!(
                "unknown control_plane.boot_without_policy {other:?} (expected local|refuse)"
            ),
        };
        let managed = cp.enabled;
        let cache = (managed && !cp.cache_path.is_empty()).then(|| Cache {
            path: cp.cache_path.clone(),
            control_plane: cp.url.trim_end_matches('/').to_string(),
            tenant_id: cp.tenant_id.clone(),
        });
        pending.store(managed && refuse, Ordering::Release);
        Ok(Arc::new(Policy {
            layers: Mutex::new(Layers {
                local,
                pushed: None,
            }),
            runtime,
            cache,
            pending,
        }))
    }

    /// The config file changed: rebuild with the new file underneath whatever was pushed. On
    /// error nothing changes.
    pub fn set_local(&self, local: Config) -> Result<()> {
        let mut layers = self.layers.lock().expect("policy mutex poisoned");
        let local = Arc::new(local);
        self.rebuild(&local, layers.pushed.as_ref())?;
        layers.local = local;
        Ok(())
    }

    /// Apply a policy pulled from the control plane, and keep a copy in `cache_path`. On error —
    /// a policy this edge cannot build — nothing changes and nothing is cached.
    pub fn apply_pushed(&self, pushed: Pushed) -> Result<()> {
        self.install(pushed.clone())?;
        if let Some(cache) = &self.cache {
            if let Err(e) = cache.save(&pushed) {
                // The policy is live in memory; only a restart would miss the copy.
                warn!(
                    error = format!("{e:#}"),
                    path = %cache.path,
                    "could not write the policy cache; a restart while the control plane is down \
                     would start without this policy"
                );
            }
        }
        Ok(())
    }

    /// At startup, before the first pull: apply the policy in `cache_path`, if there is one
    /// written for this control plane and tenant. Returns it, so the first pull can send its ETag
    /// and the usage report can name it. A cache that does not load is logged and ignored.
    pub fn restore_cached(&self) -> Option<Pushed> {
        let cache = self.cache.as_ref()?;
        let (pushed, saved_at) = match cache.load() {
            Ok(Some(found)) => found,
            Ok(None) => return None,
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    path = %cache.path,
                    "ignoring the policy cache; starting without it"
                );
                return None;
            }
        };
        match self.install(pushed.clone()) {
            Ok(()) => {
                info!(
                    etag = %pushed.etag,
                    age_secs = now_unix().saturating_sub(saved_at),
                    "applied the cached control-plane policy; the control plane replaces it when it answers"
                );
                Some(pushed)
            }
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    path = %cache.path,
                    "the cached policy no longer builds against this config; ignoring it"
                );
                None
            }
        }
    }

    /// Whether proxied requests are being refused for want of a policy.
    pub fn pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    fn install(&self, pushed: Pushed) -> Result<()> {
        let mut layers = self.layers.lock().expect("policy mutex poisoned");
        self.rebuild(&layers.local, Some(&pushed))?;
        layers.pushed = Some(pushed);
        self.pending.store(false, Ordering::Release);
        Ok(())
    }

    /// Build the runtime from the layers and swap it in. Called with the lock held, so two
    /// rebuilds cannot interleave and leave a runtime built from a layer already replaced.
    fn rebuild(&self, local: &Config, pushed: Option<&Pushed>) -> Result<()> {
        let cfg = match pushed {
            Some(p) => local
                .with_policy_from(&p.body)
                .context("merging the control-plane policy")?,
            None => local.clone(),
        };
        let mut runtime = crate::build_runtime(Arc::new(cfg)).context("building the runtime")?;
        runtime.carry_health_from(&self.runtime.load());
        self.runtime.store(Arc::new(runtime));
        Ok(())
    }
}

/// `control_plane.cache_path`: one JSON file, replaced atomically, `0600`.
struct Cache {
    path: String,
    /// Which control plane and tenant it was written for. A cache left by another configuration
    /// — a volume reused across tenants, a moved edge — is not this edge's policy.
    control_plane: String,
    tenant_id: String,
}

/// The cache file's layout. `version` is bumped on any change a reader must understand.
#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    version: u32,
    control_plane: String,
    tenant_id: String,
    etag: String,
    saved_at: u64,
    policy: String,
}

const CACHE_VERSION: u32 = 1;

impl Cache {
    fn save(&self, pushed: &Pushed) -> Result<()> {
        let file = CacheFile {
            version: CACHE_VERSION,
            control_plane: self.control_plane.clone(),
            tenant_id: self.tenant_id.clone(),
            etag: pushed.etag.clone(),
            saved_at: now_unix(),
            policy: pushed.body.clone(),
        };
        let json = serde_json::to_string(&file).context("serializing the policy cache")?;
        crate::selfsigned::replace_private(&self.path, &json)
    }

    /// The cached policy and when it was saved; `None` when there is no file.
    fn load(&self) -> Result<Option<(Pushed, u64)>> {
        if !Path::new(&self.path).exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&self.path)
            .with_context(|| format!("reading {}", self.path))?;
        let file: CacheFile = serde_json::from_str(&raw).context("not a policy cache file")?;
        anyhow::ensure!(
            file.version == CACHE_VERSION,
            "written in format version {}, this build reads {CACHE_VERSION}",
            file.version
        );
        anyhow::ensure!(
            file.control_plane == self.control_plane && file.tenant_id == self.tenant_id,
            "written for control plane {:?} tenant {:?}, this edge is configured for {:?} tenant \
             {:?}",
            file.control_plane,
            file.tenant_id,
            self.control_plane,
            self.tenant_id
        );
        Ok(Some((
            Pushed {
                etag: file.etag,
                body: file.policy,
            },
            file.saved_at,
        )))
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_for(cfg: Config) -> Result<Arc<Policy>> {
        let cfg = Arc::new(cfg);
        let runtime = Arc::new(ArcSwap::from_pointee(
            crate::build_runtime(Arc::clone(&cfg)).unwrap(),
        ));
        Policy::new(cfg, runtime, Arc::default())
    }

    #[test]
    fn an_unknown_boot_mode_is_refused() {
        let mut cfg = Config::default();
        cfg.control_plane.boot_without_policy = "wait".into();
        let Err(e) = policy_for(cfg) else {
            panic!("an unknown boot_without_policy must not load");
        };
        assert!(format!("{e:#}").contains("local|refuse"), "{e:#}");
    }

    #[test]
    fn refuse_only_holds_requests_in_managed_mode() {
        let mut cfg = Config::default();
        cfg.control_plane.boot_without_policy = "refuse".into();
        assert!(
            !policy_for(cfg.clone()).unwrap().pending(),
            "nothing to wait for"
        );
        cfg.control_plane.enabled = true;
        assert!(policy_for(cfg).unwrap().pending());
    }

    #[test]
    fn a_cache_from_another_format_version_is_not_read() {
        let dir = std::env::temp_dir().join(format!(
            "eg-policy-unit-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = Cache {
            path: dir.join("p.json").to_string_lossy().into_owned(),
            control_plane: "https://cp.example".into(),
            tenant_id: "t1".into(),
        };
        let pushed = Pushed {
            etag: "\"v1\"".into(),
            body: "[auth]\nmode = \"basic\"\n".into(),
        };
        cache.save(&pushed).unwrap();
        assert_eq!(cache.load().unwrap().map(|(p, _)| p), Some(pushed));

        let raw = std::fs::read_to_string(&cache.path).unwrap();
        std::fs::write(&cache.path, raw.replace("\"version\":1", "\"version\":2")).unwrap();
        let e = cache.load().unwrap_err();
        assert!(format!("{e:#}").contains("version 2"), "{e:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
