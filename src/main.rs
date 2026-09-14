//! EdgeGuard — a drop-in security front door for any HTTP app.
//!
//! Modes:
//!   * Co-process (default for PaaS/VPS): `edgeguard --wrap "npm start"` launches the app
//!     on APP_PORT and proxies the public PORT to it.
//!   * Front proxy (separate service): omit `--wrap` and point UPSTREAM at the app.
//!
//! TLS termination (with optional ACME), Prometheus metrics, and config hot-reload are all
//! driven by the config file (`[tls]`, `[tls.acme]`, and any change to the watched file).
//!
//! Utility: `edgeguard --hash` reads a password on stdin and prints an Argon2id PHC hash
//! for `auth.users`, so operators don't need a separate argon2 tool.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use edgeguard::config::{parse_duration, Config};
use edgeguard::generate::{generate, Target};
use edgeguard::logship;
use edgeguard::telemetry;
use edgeguard::{
    acme, build_admin_router, build_public_router, build_router, build_runtime, build_state, cp,
    doctor, hash_password, reload, scaffold, selfsigned, supervisor, tls,
};

/// The selected mode of operation. `serve` is the default; `hash` and `generate` are standalone
/// utilities that run and exit without starting a listener.
enum Cmd {
    Serve {
        wrap: Option<String>,
        config: Option<String>,
    },
    /// `edgeguard --hash`: read a password on stdin, print an argon2 hash.
    Hash,
    /// `edgeguard generate`: render the `[headers]` policy as static-host / edge config.
    Generate {
        config: Option<String>,
        target: String,
        out: Option<String>,
    },
    /// `edgeguard doctor`: load + validate the config and print advisory warnings.
    Doctor { config: Option<String> },
    /// `edgeguard init`: scaffold a starter `edgeguard.toml` (+ a wrap-your-app Dockerfile).
    Init { force: bool },
    /// `edgeguard cert`: write a self-signed certificate + key. Standalone utility — it makes
    /// files and exits, so a certificate can be produced before (or without) running the proxy,
    /// e.g. in a Dockerfile build stage or a compose init step.
    Cert {
        hosts: Vec<String>,
        days: u32,
        cert_out: String,
        key_out: String,
        force: bool,
    },
}

fn parse_args() -> Result<Cmd> {
    let mut wrap = std::env::var("WRAP_CMD").ok().filter(|s| !s.is_empty());
    let mut config = std::env::var("EDGEGUARD_CONFIG")
        .ok()
        .filter(|s| !s.is_empty());

    let argv: Vec<String> = std::env::args().skip(1).collect();

    // `generate` is a subcommand word (e.g. `edgeguard generate --target _headers`); the rest of
    // the CLI is flag-only, matching the existing `--hash` / `--wrap` style.
    if argv.first().map(String::as_str) == Some("generate") {
        let mut target = "_headers".to_string();
        let mut out = None;
        let mut it = argv.iter().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--config" => config = Some(require_value(&mut it, "--config")?),
                "--target" => target = require_value(&mut it, "--target")?,
                "--out" | "-o" => out = Some(require_value(&mut it, "--out")?),
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "-V" | "--version" => {
                    print_version();
                    std::process::exit(0);
                }
                // Reject unknown flags rather than ignoring them, matching `doctor` and `init`.
                // A typo like `--targt vercel` must not silently emit the default `_headers`
                // target and report success.
                other => anyhow::bail!("unknown argument for `edgeguard generate`: {other}"),
            }
        }
        return Ok(Cmd::Generate {
            config,
            target,
            out,
        });
    }

    // `doctor`: validate the config and report foot-guns. Flag-only after the subcommand word.
    if argv.first().map(String::as_str) == Some("doctor") {
        let mut it = argv.iter().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--config" => config = Some(require_value(&mut it, "--config")?),
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "-V" | "--version" => {
                    print_version();
                    std::process::exit(0);
                }
                // Reject unknown flags rather than ignoring them: a typo like `--confg` must not
                // silently fall through to validating the default config instead of the file meant.
                other => anyhow::bail!("unknown argument for `edgeguard doctor`: {other}"),
            }
        }
        return Ok(Cmd::Doctor { config });
    }

    // `cert`: emit a self-signed certificate/key pair. Flag-only after the subcommand word.
    if argv.first().map(String::as_str) == Some("cert") {
        let mut hosts: Vec<String> = Vec::new();
        let mut days = 90u32;
        let mut cert_out = "./tls/cert.pem".to_string();
        let mut key_out = "./tls/key.pem".to_string();
        let mut force = false;
        let mut it = argv.iter().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                // Repeatable, and comma-separated, so both `--host a --host b` and
                // `--host a,b` do the obvious thing.
                "--host" => hosts.extend(
                    require_value(&mut it, "--host")?
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                ),
                "--days" => {
                    let v = require_value(&mut it, "--days")?;
                    days = v
                        .parse()
                        .with_context(|| format!("--days expects a number of days, got {v:?}"))?;
                }
                "--cert-out" => cert_out = require_value(&mut it, "--cert-out")?,
                "--key-out" => key_out = require_value(&mut it, "--key-out")?,
                "--force" | "-f" => force = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "-V" | "--version" => {
                    print_version();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument for `edgeguard cert`: {other}"),
            }
        }
        if hosts.is_empty() {
            hosts = selfsigned::DEFAULT_HOSTS
                .iter()
                .map(|s| s.to_string())
                .collect();
        }
        return Ok(Cmd::Cert {
            hosts,
            days,
            cert_out,
            key_out,
            force,
        });
    }

    // `init`: scaffold a starter config (+ Dockerfile). Refuses to clobber an existing
    // edgeguard.toml unless `--force`.
    if argv.first().map(String::as_str) == Some("init") {
        let mut force = false;
        for arg in argv.iter().skip(1) {
            match arg.as_str() {
                "--force" | "-f" => force = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "-V" | "--version" => {
                    print_version();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument for `edgeguard init`: {other}"),
            }
        }
        return Ok(Cmd::Init { force });
    }

    let mut hash = false;
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--wrap" => wrap = Some(require_value(&mut it, "--wrap")?),
            "--config" => config = Some(require_value(&mut it, "--config")?),
            "--hash" => hash = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                print_version();
                std::process::exit(0);
            }
            // This catch-all used to be `_ => {}`, which meant every unrecognised argument was
            // discarded in silence. `edgeguard --version` started a proxy instead of printing a
            // version, and a typo such as `--wrpa "npm start"` started an unwrapped, unconfigured
            // proxy that looked healthy. Fail loudly: a front door that ignores its instructions
            // is worse than one that refuses to open.
            other => anyhow::bail!("unknown argument: {other} (run `edgeguard --help` for usage)"),
        }
    }
    Ok(if hash {
        Cmd::Hash
    } else {
        Cmd::Serve { wrap, config }
    })
}

/// Pull the value that must follow a flag (e.g. the `<path>` in `--config <path>`), erroring if
/// the flag was the last token rather than silently keeping the default. Generic over the arg
/// iterator so the `generate` and serve parsers share it.
fn require_value<'a, I: Iterator<Item = &'a String>>(it: &mut I, flag: &str) -> Result<String> {
    it.next()
        .cloned()
        .with_context(|| format!("{flag} requires a value"))
}

/// `edgeguard --version`. Read from the crate manifest at compile time, so the binary and the
/// image tag cannot disagree about what they are. There was no way to ask a published image its
/// version before 0.3.1 — `--version` fell through to the catch-all below and started a proxy.
fn print_version() {
    println!("edgeguard {}", env!("CARGO_PKG_VERSION"));
}

fn print_help() {
    eprintln!(
        "edgeguard [--wrap \"<start command>\"] [--config <path>]\n\
         edgeguard init [--force]               # scaffold edgeguard.toml + a wrap-your-app Dockerfile\n\
         edgeguard doctor [--config <path>]     # validate the config and warn on foot-guns\n\
         edgeguard cert [--host <h>]... [--days <n>] [--cert-out <p>] [--key-out <p>] [--force]\n\
         \x20                                    # write a self-signed certificate + key (dev/internal use)\n\
         edgeguard --hash                       # read a password on stdin, print an argon2 hash\n\
         edgeguard --version                    # print the version and exit\n\
         edgeguard generate [--target <t>] [--config <path>] [--out <path>]\n\
         \x20                                    # emit static-host / edge config from [headers]\n\
         \x20  targets: _headers (Netlify/CF Pages), vercel, vercel-middleware, netlify-edge\n\
         env: PORT, APP_PORT, ADMIN_PORT, REDIRECT_PORT, UPSTREAM, WRAP_CMD, EDGEGUARD_CONFIG,\n\
         \x20    EDGEGUARD_JWT_SECRET, EDGEGUARD_API_KEYS"
    );
}

/// Render and emit static-host / edge config for the `[headers]` policy (the `generate`
/// subcommand). Like `--hash`, this is a standalone utility: no logging, no listener.
fn run_generate(config: Option<String>, target: &str, out: Option<String>) -> Result<()> {
    let cfg = Config::load(config.as_deref())?;
    let target = Target::parse(target)?;
    let content = generate(&cfg, target);
    match out {
        Some(path) => {
            std::fs::write(&path, &content).with_context(|| format!("writing {path}"))?;
            eprintln!("wrote {} ({} target)", path, target.filename());
        }
        None => print!("{content}"),
    }
    Ok(())
}

/// Write a self-signed certificate + key (the `cert` subcommand). Like `--hash` and `generate`,
/// a standalone utility: no logging setup, no listener, no config file needed.
fn run_cert(hosts: &[String], days: u32, cert_out: &str, key_out: &str, force: bool) -> Result<()> {
    // Overwriting a certificate is not recoverable — the previous key is gone, and anything that
    // pinned or trusted it breaks — so refuse unless the operator said so, matching `init`.
    if !force {
        for path in [cert_out, key_out] {
            anyhow::ensure!(
                !selfsigned::path_present(path),
                "{path} already exists (pass --force to overwrite it)"
            );
        }
    }
    selfsigned::write_to(hosts, days, cert_out, key_out)?;
    eprintln!(
        "wrote {cert_out} and {key_out} ({}, {days} days)",
        hosts.join(", ")
    );
    eprintln!(
        "This certificate is self-signed: it encrypts traffic but proves no identity, so \
         browsers will warn and strict clients will refuse it. Trust it explicitly \
         (curl --cacert {cert_out}) for local/internal use, or use [tls.acme] for a publicly \
         trusted certificate."
    );
    eprintln!("Point [tls] at it:\n  [tls]\n  enabled   = true\n  cert_path = \"{cert_out}\"\n  key_path  = \"{key_out}\"");
    Ok(())
}

/// Read a password from stdin and print its Argon2id PHC hash. Reading from stdin (not
/// argv) keeps the secret out of the process list; pipe it with `echo -n 'pw' | ...`.
fn run_hash() -> Result<()> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        eprint!("Password to hash: ");
    }
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("reading password from stdin")?;
    let password = input.trim_end_matches(['\n', '\r']);
    if password.is_empty() {
        anyhow::bail!("no password supplied on stdin");
    }
    println!("{}", hash_password(password)?);
    Ok(())
}

/// `edgeguard doctor`: load + validate the config and print advisory findings. Reuses the exact
/// load + `build_runtime` paths the proxy uses (so it can't drift from real startup behavior),
/// then layers the [`doctor`] lints on top. Exits non-zero if anything is a hard error, so it
/// can gate a deploy in CI.
fn run_doctor(config: Option<String>) -> Result<()> {
    use doctor::Level;

    let cfg = match Config::load(config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ [error] config failed to load: {e:#}");
            std::process::exit(1);
        }
    };

    let findings = doctor::lint(&cfg);
    // Hard validation: the same startup sequence the proxy runs. `build_state` does
    // `CpClient::from_cfg` (managed mode) before `build_runtime`, so a broken `[control_plane]`
    // would pass `doctor` if we only built the runtime — validate both, mirroring real boot.
    let cp_err = cp::CpClient::from_cfg(&cfg.control_plane).err();
    let build_err = build_runtime(Arc::new(cfg)).err();

    let mut errors = 0usize;
    let mut warns = 0usize;
    for f in &findings {
        match f.level {
            Level::Error => errors += 1,
            Level::Warn => warns += 1,
            Level::Info => {}
        }
        println!("{} [{}] {}", f.level.glyph(), f.level.label(), f.message);
    }
    if let Some(e) = &cp_err {
        errors += 1;
        println!("✗ [error] control-plane config does not build: {e:#}");
    }
    if let Some(e) = &build_err {
        errors += 1;
        println!("✗ [error] config does not build: {e:#}");
    }

    // Only claim a clean bill of health when there was genuinely nothing to report — info-level
    // findings (e.g. "TLS disabled") are still output above, so they must suppress the banner.
    if findings.is_empty() && cp_err.is_none() && build_err.is_none() {
        println!("✓ no issues found");
    }
    println!("\n{errors} error(s), {warns} warning(s)");
    if errors > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// `edgeguard init`: scaffold a starter `edgeguard.toml` and a wrap-your-app
/// `Dockerfile.edgeguard`, tailored to the runtime detected from the working directory. Refuses
/// to overwrite either file unless `--force`, so re-running it never silently clobbers edits.
fn run_init(force: bool) -> Result<()> {
    let mut entries = Vec::new();
    if let Ok(rd) = std::fs::read_dir(".") {
        for e in rd.flatten() {
            entries.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    let runtime = scaffold::Runtime::detect(&entries);

    // Refuse to clobber existing files — re-running `init` must never silently overwrite edits.
    // This is an expected user condition, not a crash, so exit cleanly (no error backtrace).
    if !force {
        for path in ["edgeguard.toml", "Dockerfile.edgeguard"] {
            if std::path::Path::new(path).exists() {
                eprintln!(
                    "{path} already exists; re-run `edgeguard init --force` to overwrite it."
                );
                std::process::exit(1);
            }
        }
    }

    std::fs::write("edgeguard.toml", scaffold::EDGEGUARD_TOML).context("writing edgeguard.toml")?;
    std::fs::write("Dockerfile.edgeguard", scaffold::dockerfile(runtime))
        .context("writing Dockerfile.edgeguard")?;

    eprintln!("Detected runtime: {}", runtime.label());
    eprintln!("Wrote edgeguard.toml and Dockerfile.edgeguard.\n");
    eprint!("{}", scaffold::next_steps(runtime));
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // `--hash` and `generate` are standalone utilities: no logging setup, no listener. `serve`
    // (the default) falls through to the proxy bootstrap below.
    let (wrap, config) = match parse_args()? {
        Cmd::Hash => return run_hash(),
        Cmd::Generate {
            config,
            target,
            out,
        } => return run_generate(config, &target, out),
        Cmd::Doctor { config } => return run_doctor(config),
        Cmd::Init { force } => return run_init(force),
        Cmd::Cert {
            hosts,
            days,
            cert_out,
            key_out,
            force,
        } => return run_cert(&hosts, days, &cert_out, &key_out, force),
        Cmd::Serve { wrap, config } => (wrap, config),
    };

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Arc::new(Config::load(config.as_deref())?);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Start the wrapped app (co-process mode) if requested.
    if let Some(cmd) = wrap.clone() {
        let app_port = cfg.server.app_port;
        let rx = shutdown_rx.clone();
        tokio::spawn(async move {
            supervisor::run(cmd, app_port, rx).await;
        });
    }

    // Best-effort readiness wait, but only when the upstream is local (a wrapped child or one
    // derived from APP_PORT). For an external UPSTREAM there's no local port to wait on.
    if wrap.is_some() || cfg.server.upstream.is_empty() {
        wait_for_upstream(cfg.server.app_port, Duration::from_secs(30)).await;
    }

    let state = build_state(cfg.clone())?;
    // Keep a handle to the hot-swappable runtime for the reload watcher.
    let runtime = state.runtime.clone();
    // Clones for the managed-mode background loops (grabbed before `state` is moved into the router).
    let cp_client = state.cp.clone();
    // The ACME order below runs before the managed-mode loops take ownership of `cp_client`, and it
    // needs the same client: in managed mode the CA's SHARED rate limits are held by the control
    // plane, not by this box's local ledger. See `acme::check_budget`.
    let acme_cp = state.cp.clone();
    let cp_runtime = state.runtime.clone();
    let cp_metrics = state.metrics.clone();
    // Also grabbed here, before `state` moves into the router below: the access-log shipper is
    // installed on the same registry the response path already holds.
    let log_metrics = state.metrics.clone();
    let cp_quota = state.quota.clone();

    // Hard quota needs the managed-mode client to poll verdicts; without it the gate would stay
    // permissive forever. Fail fast rather than silently not enforcing a configured cap.
    anyhow::ensure!(
        !(cfg.control_plane.enforce_quota && cp_client.is_none()),
        "control_plane.enforce_quota requires control_plane.enabled = true (with url/tenant_id/edge_token)"
    );

    // Optional private admin listener: when `server.admin_port` is set, the internal ops
    // endpoints (health/readiness/metrics) move to a separate plain-HTTP listener so they
    // aren't exposed on the public port; the public port then serves only the proxy (plus the
    // browser-facing CSP sink). See the README "Public/private split" section.
    let app = if cfg.server.admin_port != 0 {
        let ip: IpAddr =
            cfg.server.admin_addr.parse().with_context(|| {
                format!("invalid server.admin_addr {:?}", cfg.server.admin_addr)
            })?;
        let admin_addr = SocketAddr::new(ip, cfg.server.admin_port);
        let admin_listener = TcpListener::bind(admin_addr)
            .await
            .with_context(|| format!("binding admin listener on {admin_addr}"))?;
        let admin_app = build_admin_router(state.clone());
        let admin_rx = shutdown_rx.clone();
        info!(listen = %admin_addr, "EdgeGuard admin endpoints listening (health/ready/metrics)");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(admin_listener, admin_app)
                .with_graceful_shutdown(shutdown_on(admin_rx))
                .await
            {
                warn!(error = %e, "admin listener stopped");
            }
        });
        build_public_router(state)
    } else {
        build_router(state)
    };

    // Config hot-reload: watch the config file (if one was given) and swap policy in place.
    if let Some(path) = config.clone() {
        tokio::spawn(async move {
            if let Err(e) = reload::watch(PathBuf::from(path), runtime).await {
                warn!(error = format!("{e:#}"), "config watcher stopped");
            }
        });
    }

    // Access-log shipping: stream the structured request log to a collector.
    //
    // Started independently of managed mode on purpose. Centralized logs are useful to an operator
    // running one edge with no control plane at all, and coupling the two would mean a self-hosted
    // user could not have logs without also enrolling in a hosted control plane.
    if cfg.log.ship.enabled {
        // The same identity the fleet registry uses, so a log line and a fleet row can be joined by
        // `edge_id`. Two different identifiers for one process would make that join impossible
        // exactly when someone is trying to correlate a bad edge's logs with its version.
        let edge_id = if cfg.control_plane.edge_id.trim().is_empty() {
            std::env::var("HOSTNAME")
                .ok()
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| format!("edge-{}", std::process::id()))
        } else {
            cfg.control_plane.edge_id.trim().to_string()
        };
        match logship::spawn(&cfg.log.ship, edge_id, shutdown_rx.clone()) {
            Some(shipper) => {
                log_metrics.set_log_shipper(shipper);
            }
            None => warn!("[log.ship] is enabled but produced no shipper; check log.ship.url"),
        }
    }

    // Request tracing: one OTLP SERVER span per proxied request, batched off-box.
    //
    // Independent of managed mode and of `[llm.telemetry]`, deliberately. A plain reverse-proxy
    // install — the majority — emitted no traces at all, because the only span this proxy produced
    // was the LLM client span.
    if cfg.tracing.enabled {
        match telemetry::spawn_span_shipper(&cfg.tracing, shutdown_rx.clone()) {
            Some(shipper) => {
                log_metrics.set_span_shipper(shipper);
            }
            None => warn!("[tracing] is enabled but produced no shipper; check tracing.endpoint"),
        }
    }

    // Managed mode: poll the control plane for policy (hot-reloading it) and report usage deltas.
    if let Some(cp_client) = cp_client {
        let poll = parse_duration(&cfg.control_plane.poll_interval).unwrap_or_else(|e| {
            warn!(error = %e, interval = %cfg.control_plane.poll_interval, "invalid poll_interval; using 30s");
            Duration::from_secs(30)
        });
        let report = parse_duration(&cfg.control_plane.report_interval).unwrap_or_else(|e| {
            warn!(error = %e, interval = %cfg.control_plane.report_interval, "invalid report_interval; using 60s");
            Duration::from_secs(60)
        });
        let base = cfg.clone();
        let poll_rx = shutdown_rx.clone();
        let poller = cp_client.clone();
        tokio::spawn(async move { cp::poll_loop(poller, base, cp_runtime, poll, poll_rx).await });
        // Quota enforcement poller (opt-in): publishes the edge's quota verdict to the shared
        // QuotaState the proxy hard-stops on.
        if cfg.control_plane.enforce_quota {
            let quota_interval = parse_duration(&cfg.control_plane.quota_poll_interval)
                .unwrap_or_else(|e| {
                    warn!(error = %e, interval = %cfg.control_plane.quota_poll_interval, "invalid quota_poll_interval; using 30s");
                    Duration::from_secs(30)
                });
            let quota_rx = shutdown_rx.clone();
            let quota_client = cp_client.clone();
            tokio::spawn(async move {
                cp::quota_loop(quota_client, cp_quota, quota_interval, quota_rx).await
            });
        }
        let report_rx = shutdown_rx.clone();
        tokio::spawn(
            async move { cp::report_loop(cp_client, cp_metrics, report, report_rx).await },
        );
    }

    // A single task flips the shutdown watch on Ctrl-C/SIGTERM; both the supervisor and the
    // listener react to it for a graceful, connection-draining stop.
    tokio::spawn(async move {
        wait_for_signal().await;
        info!("shutdown signal received");
        let _ = shutdown_tx.send(true);
    });

    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cfg.server.port));

    if cfg.tls.enabled {
        tls::init_crypto();
        // Fail on a bad `redirect_status` here, before anything binds. The check also lives in
        // `serve_redirect`, but that runs inside a spawned task whose error only warns — the
        // listener would then be closed with the proxy still serving HTTPS, so a bare hostname
        // got "connection refused" from a config mistake that should not have started at all.
        if cfg.tls.redirect_port != 0 {
            tls::parse_redirect_status(cfg.tls.redirect_status)?;
        }
        // ACME runs FIRST. It must: both paths write to the same cert_path, and the ACME branch
        // below skips issuance when a certificate is already there — so generating a self-signed
        // one first would make it silently win over the publicly trusted certificate the
        // operator actually asked for, on the public domain where that matters most. Ordering it
        // this way keeps `self_signed` the floor it is documented to be ("never fail to start
        // for want of a certificate"): after a successful order `ensure` finds the file and does
        // nothing, and a failed order propagates below rather than falling back to an untrusted
        // certificate on a public name.
        if cfg.tls.acme.enabled {
            // Only order a certificate when one isn't already on disk; re-ordering on every
            // boot would burn ACME issuance rate limits. (Renewal before expiry is future
            // work — see docs/ROADMAP.md.)
            // BOTH files, not just the certificate. A cert without its key is not a usable
            // pair: skipping issuance there used to hand the half-pair to `selfsigned::ensure`
            // below, which regenerates both — quietly serving a self-signed certificate on the
            // domain ACME was configured for. Missing either file means order one.
            if selfsigned::path_present(&cfg.tls.cert_path)
                && selfsigned::path_present(&cfg.tls.key_path)
            {
                info!(cert = %cfg.tls.cert_path, "ACME: using existing certificate (skipping issuance)");
            } else {
                match acme::obtain_certificate(&cfg.tls.acme, &cfg.tls, acme_cp.as_deref())
                    .await
                    .context("ACME certificate provisioning")?
                {
                    acme::Issuance::Issued => {}
                    // The budget refused, so no order was sent and no certificate arrived. Falling
                    // through to `selfsigned::ensure` below would put an untrusted certificate on
                    // the public domain ACME was configured for — the exact substitution the
                    // ordering above exists to prevent, and every browser reaching this edge would
                    // see an interstitial.
                    //
                    // There is nothing on disk (the branch above already established that), so
                    // there is also nothing to keep serving. Refusing to start is the honest
                    // outcome: it is loud, it names the bucket and the retry instant, and it leaves
                    // the previous replica serving in any rollout that has one.
                    acme::Issuance::Deferred {
                        bucket,
                        key,
                        retry_at_unix,
                        source,
                    } => {
                        // `source` decides what the operator should do, so it leads the message. A
                        // FLEET refusal means another edge under the same key spent the allowance
                        // and nothing about this box will change that; a LOCAL one usually means
                        // this box's certificate cache is not durable, which is fixable here.
                        anyhow::bail!(
                            "ACME issuance is rate-limited by the {} budget ({} limit{}) and no \
                             certificate is on disk; it next admits at unix {}. Refusing to start \
                             rather than serving a self-signed certificate on {:?}. {}",
                            source.label(),
                            bucket,
                            if key.is_empty() {
                                String::new()
                            } else {
                                format!(" for {key:?}")
                            },
                            retry_at_unix,
                            cfg.tls.acme.domains,
                            match source {
                                acme::DeferSource::Fleet =>
                                    "Another edge under the same key has spent the fleet's \
                                     allowance; check GET /v3/acme/budget on the control plane.",
                                acme::DeferSource::Local =>
                                    "Restore the certificate cache from a durable volume, or wait.",
                            }
                        );
                    }
                }
            }
        }
        if cfg.tls.self_signed {
            selfsigned::ensure(
                &cfg.tls.self_signed_host_list(),
                cfg.tls.self_signed_days,
                &cfg.tls.cert_path,
                &cfg.tls.key_path,
            )
            .context("generating a self-signed certificate")?;
        }
        let server_config = tls::load_server_config(&cfg.tls.cert_path, &cfg.tls.key_path)?;

        // HTTP→HTTPS redirect on a second, plaintext port. Bound after any ACME order above has
        // finished and dropped its own `:80` listener, so the two never contend for the port.
        if cfg.tls.redirect_port != 0 {
            let redirect_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cfg.tls.redirect_port));
            let redirect_listener = TcpListener::bind(redirect_addr).await.with_context(|| {
                format!(
                    "binding HTTP→HTTPS redirect listener on {redirect_addr}                      (ports below 1024 need privilege or CAP_NET_BIND_SERVICE)"
                )
            })?;
            let tls_port = cfg.server.port;
            let status = cfg.tls.redirect_status;
            let hosts = cfg.tls.redirect_hosts.clone();
            let redirect_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    tls::serve_redirect(redirect_listener, tls_port, status, hosts, redirect_rx)
                        .await
                {
                    warn!(error = %e, "HTTP→HTTPS redirect listener stopped");
                }
            });
        }

        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding public TLS listener on {addr}"))?;
        info!(
            listen = %addr,
            upstream = %cfg.upstream_base(),
            auth = %cfg.auth.mode,
            rate_limit = cfg.ratelimit.enabled,
            store = %cfg.ratelimit.store,
            waf = %cfg.waf.mode,
            tls = true,
            redirect_port = cfg.tls.redirect_port,
            "EdgeGuard listening (HTTPS)"
        );
        tls::serve(listener, server_config, app, shutdown_rx.clone())
            .await
            .context("TLS server error")?;
    } else {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding public listener on {addr}"))?;
        info!(
            listen = %addr,
            upstream = %cfg.upstream_base(),
            auth = %cfg.auth.mode,
            rate_limit = cfg.ratelimit.enabled,
            store = %cfg.ratelimit.store,
            waf = %cfg.waf.mode,
            "EdgeGuard listening"
        );
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_on(shutdown_rx.clone()))
        .await
        .context("server error")?;
    }

    info!("EdgeGuard stopped");
    Ok(())
}

/// Poll the upstream port until it accepts a connection or the timeout elapses.
async fn wait_for_upstream(port: u16, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            info!(port, "upstream is ready");
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            warn!(
                port,
                "upstream not ready before timeout; serving anyway (will 502 until up)"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Resolve once the shutdown watch flips to `true` (for axum's graceful shutdown).
async fn shutdown_on(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}

/// Resolve on Ctrl-C or SIGTERM.
async fn wait_for_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}
