//! Config hot-reload.
//!
//! Watches the config file and, on change, rebuilds the [`Runtime`] and atomically swaps it
//! into the live [`ArcSwap`]. Because only the policy snapshot is replaced — never the
//! listener or the connection pool — in-flight requests finish under the policy they started
//! with and no connections are dropped. A reload that fails to parse/validate is logged and
//! the previous runtime is kept, so a typo can never take the proxy down.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::build_runtime;
use crate::config::Config;
use crate::proxy::Runtime;

/// Watch `path` and hot-reload on every change. Runs until the channel closes; spawn it as a
/// background task. `path` is the config file the binary was started with.
pub async fn watch(path: PathBuf, runtime: Arc<ArcSwap<Runtime>>) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<()>(8);

    // We watch the directory (see below), so filter events down to ones that touch the config
    // file *by name* — otherwise unrelated churn in the same directory (logs, other configs)
    // would trigger needless reloads. Matching by name also catches atomic saves, where the
    // final rename targets the config path.
    let target_name = path.file_name().map(|n| n.to_os_string());

    // notify invokes this closure from its own (non-async) thread on each FS event. Forward a
    // lightweight "something changed" tick; `try_send` so a burst can't block the watcher
    // thread (we coalesce below anyway).
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(event) if is_modifying(&event) && touches(&event, target_name.as_deref()) => {
            let _ = tx.try_send(());
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "config watcher error"),
    })
    .context("creating config watcher")?;

    // Watch the *parent directory*, not the file: editors and `mv`-based atomic writes replace
    // the file via rename, which would drop a watch placed on the inode itself.
    let watch_dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    watcher
        .watch(&watch_dir, RecursiveMode::NonRecursive)
        .with_context(|| format!("watching {}", watch_dir.display()))?;

    info!(path = %path.display(), "config hot-reload enabled");

    while rx.recv().await.is_some() {
        // Coalesce the burst of events most editors emit per save.
        tokio::time::sleep(Duration::from_millis(200)).await;
        while rx.try_recv().is_ok() {}

        match reload(&path, &runtime) {
            Ok(()) => info!(path = %path.display(), "config reloaded"),
            Err(e) => {
                error!(
                    error = format!("{e:#}"),
                    "config reload failed; keeping previous config"
                )
            }
        }
    }
    Ok(())
}

/// Reload the config file and swap in a freshly-built runtime. Pure enough to unit-test: it
/// takes the same `ArcSwap` the request path reads from.
fn reload(path: &Path, runtime: &ArcSwap<Runtime>) -> Result<()> {
    let cfg = Config::load(path.to_str()).context("reloading config")?;
    let new_runtime = build_runtime(Arc::new(cfg)).context("rebuilding runtime")?;
    runtime.store(Arc::new(new_runtime));
    Ok(())
}

fn is_modifying(event: &Event) -> bool {
    matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
}

/// Does this event touch a file named `target_name`? With no name to match against (a config
/// path with no file name — unusual) we conservatively accept everything.
fn touches(event: &Event, target_name: Option<&std::ffi::OsStr>) -> bool {
    match target_name {
        Some(name) => event.paths.iter().any(|p| p.file_name() == Some(name)),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn reload_swaps_in_new_policy_and_rejects_bad_config() {
        let dir = std::env::temp_dir().join(format!("edgeguard-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("edgeguard.toml");

        // Initial config: rate limiting disabled.
        std::fs::write(&path, "[ratelimit]\nenabled = false\n").unwrap();
        let initial = build_runtime(Arc::new(Config::load(path.to_str()).unwrap())).unwrap();
        assert!(initial.ip_limiter.is_none());
        let swap = ArcSwap::from_pointee(initial);

        // A good reload turns rate limiting on — the swap reflects it.
        std::fs::write(
            &path,
            "[ratelimit]\nenabled = true\nrate = \"10/sec\"\nburst = 5\n",
        )
        .unwrap();
        reload(&path, &swap).unwrap();
        assert!(swap.load().ip_limiter.is_some());

        // A broken reload (invalid rate) is an error and must NOT clobber the live policy.
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            "[ratelimit]\nenabled = true\nrate = \"0/sec\"\nburst = 5\n"
        )
        .unwrap();
        drop(f);
        assert!(reload(&path, &swap).is_err());
        assert!(swap.load().ip_limiter.is_some()); // previous (working) policy retained

        let _ = std::fs::remove_dir_all(&dir);
    }
}
