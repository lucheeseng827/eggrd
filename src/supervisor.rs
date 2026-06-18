//! Co-process supervisor.
//!
//! When EdgeGuard is run with `--wrap "<command>"`, it launches the user's app as a
//! child process and acts as a tiny init for the container: it restarts the child on
//! crash, and on shutdown forwards a termination signal to the child before exiting.
//! The child is told to listen on `APP_PORT` via the `PORT` env var (the convention
//! most web frameworks follow), while EdgeGuard itself binds the public `$PORT`.
//!
//! The signal/process-group plumbing is Unix-specific; on Windows we fall back to a
//! plain child kill (no process groups, no POSIX signals).

use std::time::Duration;
use tokio::process::Command;
use tokio::sync::watch;
use tracing::{error, info, warn};

/// Run the supervised child until `shutdown` flips to true.
pub async fn run(cmd: String, app_port: u16, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = Duration::from_millis(500);

    loop {
        if *shutdown.borrow() {
            break;
        }

        info!(command = %cmd, app_port, "starting wrapped app");
        let mut command = build_command(&cmd, app_port);
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "failed to spawn wrapped app; retrying");
                if wait_or_shutdown(&mut shutdown, backoff).await {
                    break;
                }
                backoff = (backoff * 2).min(Duration::from_secs(10));
                continue;
            }
        };

        let pid = child.id();

        tokio::select! {
            status = child.wait() => {
                if *shutdown.borrow() {
                    break;
                }
                match status {
                    Ok(s) => warn!(?s, "wrapped app exited; restarting"),
                    Err(e) => error!(error = %e, "error waiting on wrapped app; restarting"),
                }
                // Reap any stragglers left in the child's process group (Unix only).
                reap_group(pid);
                if wait_or_shutdown(&mut shutdown, backoff).await {
                    break;
                }
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }
            _ = shutdown.changed() => {
                info!("shutdown requested; terminating wrapped app");
                terminate(&mut child, pid).await;
                break;
            }
        }
    }

    info!("supervisor stopped");
}

/// Build the child `Command`. On Unix the app runs under `sh -c` in its own session
/// (so the whole process tree can be signaled); on Windows it runs under `cmd /C`.
#[cfg(unix)]
fn build_command(cmd: &str, app_port: u16) -> Command {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .env("PORT", app_port.to_string())
        .env("HOST", "127.0.0.1")
        .kill_on_drop(true);
    // Put the child in its own process group (leader pid == child pid) so we can
    // signal the entire tree — `sh -c` may fork the real app as a grandchild.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

#[cfg(windows)]
fn build_command(cmd: &str, app_port: u16) -> Command {
    let mut command = Command::new("cmd");
    command
        .arg("/C")
        .arg(cmd)
        .env("PORT", app_port.to_string())
        .env("HOST", "127.0.0.1")
        .kill_on_drop(true);
    command
}

/// Sleep for `dur`, returning early (true) if a shutdown is requested meanwhile.
async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, dur: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(dur) => *shutdown.borrow(),
        _ = shutdown.changed() => true,
    }
}

/// After an unexpected exit, force-kill any stragglers left in the child's process
/// group. No-op on Windows, where `kill_on_drop` already reaps the direct child.
#[cfg(unix)]
fn reap_group(pid: Option<u32>) {
    if let Some(pid) = pid {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

#[cfg(windows)]
fn reap_group(_pid: Option<u32>) {}

/// Gracefully stop the child, escalating to a hard kill if it lingers.
///
/// On Unix this sends SIGTERM to the child's process group, waits up to 10s, then
/// SIGKILLs the group. Windows has no POSIX signals, so we issue a single kill and
/// wait for it to land.
#[cfg(unix)]
async fn terminate(child: &mut tokio::process::Child, pid: Option<u32>) {
    if let Some(pid) = pid {
        // Negative pid targets the process group (leader == pid), so the real app
        // running under `sh -c` is signaled too, not just the shell.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGTERM);
        }
    }
    match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
        Ok(Ok(s)) => info!(?s, "wrapped app exited after SIGTERM"),
        _ => {
            warn!("wrapped app did not exit in time; sending SIGKILL");
            if let Some(pid) = pid {
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
            }
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
}

#[cfg(windows)]
async fn terminate(child: &mut tokio::process::Child, _pid: Option<u32>) {
    let _ = child.start_kill();
    match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
        Ok(Ok(s)) => info!(?s, "wrapped app exited"),
        _ => warn!("wrapped app did not exit in time"),
    }
}
