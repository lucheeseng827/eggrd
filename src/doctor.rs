//! Config linting for `edgeguard doctor`.
//!
//! `Config::load` + `build_runtime` already prove the config *parses* and *compiles* (bad
//! rate/size/regex/auth values fail there). The linter adds the advisory layer on top: the
//! foot-guns a drop-in-front-of-your-app operator actually hits — the shipped placeholder
//! credential still in place, auth turned off on a public port, secrets committed to the file,
//! an over-permissive CORS policy. It is intentionally pure (`&Config` in, findings out) so the
//! CLI can format it and tests can assert on it.

use argon2::PasswordHash;

use crate::config::Config;

/// Severity of a [`Finding`]. `Error` means "this will not work / is unsafe as written" and
/// makes `edgeguard doctor` exit non-zero; `Warn`/`Info` are advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warn,
    Info,
}

impl Level {
    /// A short glyph for the CLI report.
    pub fn glyph(self) -> &'static str {
        match self {
            Level::Error => "✗",
            Level::Warn => "⚠",
            Level::Info => "ℹ",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
        }
    }
}

/// One linter result: a severity and a human-readable message (with remediation where useful).
#[derive(Debug, Clone)]
pub struct Finding {
    pub level: Level,
    pub message: String,
}

impl Finding {
    fn error(msg: impl Into<String>) -> Finding {
        Finding {
            level: Level::Error,
            message: msg.into(),
        }
    }
    fn warn(msg: impl Into<String>) -> Finding {
        Finding {
            level: Level::Warn,
            message: msg.into(),
        }
    }
    fn info(msg: impl Into<String>) -> Finding {
        Finding {
            level: Level::Info,
            message: msg.into(),
        }
    }
}

/// Lint a resolved [`Config`] for common deployment foot-guns. Findings are ordered roughly by
/// the pipeline (listener → auth → rate limit → TLS → CORS → secrets → managed mode).
pub fn lint(cfg: &Config) -> Vec<Finding> {
    let mut f = Vec::new();
    lint_listener(cfg, &mut f);
    lint_upstream_tls(cfg, &mut f);
    lint_pools(cfg, &mut f);
    lint_auth(cfg, &mut f);
    lint_ratelimit(cfg, &mut f);
    lint_tls(cfg, &mut f);
    lint_client_auth(cfg, &mut f);
    lint_cert_expiry(cfg, &mut f);
    lint_trusted_header(cfg, &mut f);
    lint_client_cert_expiry(cfg, &mut f);
    lint_cors(cfg, &mut f);
    lint_forwarded(cfg, &mut f);
    lint_proxy_protocol(cfg, &mut f);
    lint_secrets(cfg, &mut f);
    lint_control_plane(cfg, &mut f);
    lint_outbound(cfg, &mut f);
    f
}

fn lint_auth(cfg: &Config, f: &mut Vec<Finding>) {
    match cfg.auth.mode.as_str() {
        "none" => f.push(Finding::warn(
            "auth.mode = \"none\": every request is forwarded unauthenticated. Set a gate \
             (basic/apikey/jwt) before exposing this.",
        )),
        "basic" => {
            if cfg.auth.users.is_empty() {
                f.push(Finding::error(
                    "auth.mode = \"basic\" but auth.users is empty: no one can authenticate.",
                ));
            }
            for (user, value) in &cfg.auth.users {
                if value.starts_with("$argon2") {
                    // A real PHC string parses; the shipped placeholder ($argon2id$REPLACE_ME$…)
                    // does not, and would reject every login.
                    if PasswordHash::new(value).is_err() {
                        f.push(Finding::error(format!(
                            "auth.users[\"{user}\"] is not a valid argon2 hash (the shipped \
                             placeholder?): no one can authenticate. Run `edgeguard --hash` and \
                             paste the result."
                        )));
                    }
                } else {
                    f.push(Finding::warn(format!(
                        "auth.users[\"{user}\"] is a plaintext password (dev convenience). Replace \
                         it with an argon2 hash (`edgeguard --hash`) before exposing anything."
                    )));
                }
            }
        }
        "apikey" => {
            if cfg.auth.api_keys.is_empty() {
                f.push(Finding::error(
                    "auth.mode = \"apikey\" but no api_keys are set (config or EDGEGUARD_API_KEYS): \
                     no request can authenticate.",
                ));
            }
        }
        "jwt" => {
            let j = &cfg.auth.jwt;
            if j.secret.is_empty() && j.public_key_pem.is_empty() && j.jwks_url.is_empty() {
                f.push(Finding::error(
                    "auth.mode = \"jwt\" but none of auth.jwt.secret / public_key_pem / jwks_url \
                     is set: tokens cannot be verified.",
                ));
            }
        }
        _ => {} // unknown modes are already rejected by build_runtime
    }
}

fn lint_ratelimit(cfg: &Config, f: &mut Vec<Finding>) {
    let rl = &cfg.ratelimit;
    if !rl.enabled {
        f.push(Finding::warn(
            "ratelimit.enabled = false: no rate limiting. A public front door usually wants a \
             per-IP cap to blunt abuse/brute-force.",
        ));
        return;
    }
    if rl.store == "redis" && rl.redis_url.trim().is_empty() {
        f.push(Finding::error(
            "ratelimit.store = \"redis\" but redis_url is empty (set it or EDGEGUARD_REDIS_URL).",
        ));
    }
}

/// `[tls.acme]` settings that would fail an order: an ACME client that cannot be built (a CA
/// bundle, certificate or proxy that will not load, a directory that is not https://), an unknown
/// challenge, a wildcard over HTTP-01 (the CA cannot validate it), and a DNS-01 provider that
/// cannot be built — no provider, no zone, or its token's environment variable unset. Checked against this process's
/// environment, so run `doctor` where the proxy runs.
fn lint_acme_challenge(cfg: &Config, f: &mut Vec<Finding>) {
    let acme = &cfg.tls.acme;
    if !acme.enabled {
        return;
    }
    if let Err(e) = crate::acme::http_client(acme) {
        f.push(Finding::error(format!(
            "{e:#}: EdgeGuard will refuse to start"
        )));
    }
    let dns01 = match acme.challenge.as_str() {
        "http-01" | "" => false,
        "dns-01" => true,
        other => {
            f.push(Finding::error(format!(
                "tls.acme.challenge = {other:?} is not supported; use \"http-01\" or \"dns-01\""
            )));
            return;
        }
    };
    for d in acme.domains.iter().filter(|d| d.trim().starts_with("*.")) {
        if !dns01 {
            f.push(Finding::error(format!(
                "{d} is a wildcard; the CA only validates wildcards over DNS. Set \
                 tls.acme.challenge = \"dns-01\" and configure [tls.acme.dns]."
            )));
        }
    }
    if dns01 {
        if let Err(e) = crate::acme_dns::DnsProvider::from_cfg(&acme.dns) {
            f.push(Finding::error(format!("{e:#}")));
        }
        if acme.dns.provider == "challtestsrv" {
            f.push(Finding::warn(
                "tls.acme.dns.provider = \"challtestsrv\" is Pebble's test DNS server; it cannot \
                 publish records a real CA will see.",
            ));
        }
    }
}

fn lint_tls(cfg: &Config, f: &mut Vec<Finding>) {
    lint_acme_challenge(cfg, f);
    if !cfg.tls.enabled {
        f.push(Finding::info(
            "tls.enabled = false: EdgeGuard serves plain HTTP. Fine when your platform terminates \
             TLS in front of it; on a VPS/front-proxy, enable [tls] (or [tls.acme]) so traffic \
             isn't unencrypted. `tls.self_signed = true` gets you an encrypted port immediately \
             without obtaining a certificate first.",
        ));
        // HSTS over plaintext is not merely useless, it is a trap: nothing sets it (browsers
        // ignore the header on an http:// response), so the config reads as protected while
        // every request is still in the clear.
        if cfg.headers.hsts {
            f.push(Finding::warn(
                "headers.hsts = true but tls.enabled = false: browsers ignore \
                 Strict-Transport-Security on a plain-HTTP response, so this setting is doing \
                 nothing. Terminate TLS here, or make sure the proxy in front of you sets HSTS.",
            ));
        }
        return;
    }

    if cfg.tls.self_signed {
        f.push(Finding::warn(
            "tls.self_signed = true: the certificate proves no identity, so browsers show an \
             interstitial and strict clients refuse the connection. Correct for localhost, a \
             private network or staging; for a public domain switch to [tls.acme].",
        ));
        if cfg.tls.self_signed_days > 825 {
            f.push(Finding::warn(
                "tls.self_signed_days is over 825: some clients reject certificates with a \
                 lifetime that long outright. Keep it short and re-issue instead.",
            ));
        }
    }

    if !cfg.tls.self_signed
        && !cfg.tls.acme.enabled
        && (cfg.tls.cert_path.is_empty() || cfg.tls.key_path.is_empty())
    {
        f.push(Finding::error(
            "tls.enabled = true but there is no certificate to serve: set cert_path/key_path, \
             or enable tls.acme (public domain) or tls.self_signed (local/internal). EdgeGuard \
             will refuse to start as configured.",
        ));
    }

    if cfg.tls.self_signed && (cfg.tls.cert_path.is_empty() || cfg.tls.key_path.is_empty()) {
        f.push(Finding::error(
            "tls.self_signed = true needs tls.cert_path and tls.key_path — they are where the \
             generated certificate is written, not only where an existing one is read from.",
        ));
    }

    match cfg.tls.redirect_port {
        // The whole point of the redirect listener is to catch the browser's first, bare-hostname
        // request. Silence here is the single most common way TLS is enabled and still bypassed.
        0 => f.push(Finding::info(
            "tls.redirect_port = 0: nothing is listening on plain HTTP, so a visitor who types \
             the bare hostname gets a connection error rather than being sent to HTTPS. Set \
             tls.redirect_port = 80 to upgrade them instead.",
        )),
        p if p == cfg.server.port => f.push(Finding::error(format!(
            "tls.redirect_port = {p} is the same as server.port: the redirect listener and the \
             TLS listener cannot share a port, and EdgeGuard will fail to bind."
        ))),
        p if p == cfg.server.admin_port => f.push(Finding::error(format!(
            "tls.redirect_port = {p} is the same as server.admin_port: the two listeners cannot \
             share a port."
        ))),
        p => {
            if !(300..400).contains(&cfg.tls.redirect_status) {
                f.push(Finding::error(format!(
                    "tls.redirect_status = {} is not a 3xx redirect status.",
                    cfg.tls.redirect_status
                )));
            }
            if cfg.tls.redirect_hosts.is_empty() {
                f.push(Finding::info(
                    "tls.redirect_hosts is empty: the redirect listener reflects whatever Host \
                     header it is sent. That is the usual behaviour, but listing the hostnames \
                     you actually serve stops a forged Host from producing a redirect that \
                     appears to come from your domain.",
                ));
            }
            if p == 80 && cfg.tls.acme.enabled {
                f.push(Finding::info(
                    "tls.redirect_port = 80 with ACME enabled: EdgeGuard orders the certificate \
                     first and starts the redirect listener afterwards, so the two do not \
                     contend for :80. The redirect listener answers 404 (not a redirect) on \
                     /.well-known/acme-challenge/ so a future renewal is not broken by it.",
                ));
            }
        }
    }
}

/// The certificate on disk, judged against when it expires and whether anything here renews it.
///
/// Reads the file, so it is the one lint that is not purely config — but "TLS is configured
/// correctly and the certificate expires on Thursday" is exactly what an operator runs `doctor`
/// to find out. A missing or unreadable file is not reported here: self-signed and ACME create it
/// at startup, and a file-sourced pair that cannot load already fails `edgeguard` on boot.
fn lint_cert_expiry(cfg: &Config, f: &mut Vec<Finding>) {
    if !cfg.tls.enabled || cfg.tls.cert_path.is_empty() {
        return;
    }
    let Ok(certs) = crate::tls::load_certs(&cfg.tls.cert_path) else {
        return;
    };
    let Ok(info) = crate::certstore::CertInfo::from_der(&certs[0]) else {
        return;
    };
    let plan = crate::certstore::RenewPlan::from_cfg(&cfg.tls);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    f.extend(cert_expiry_findings(&cfg.tls.cert_path, &info, plan, now));
    // Extra `[[tls.certs]]` pairs: host patterns that would fail startup, and expiry. Nothing here
    // renews them, so they get the "nothing renews it" thresholds.
    for c in &cfg.tls.certs {
        if c.hosts.is_empty() {
            f.push(Finding::error(format!(
                "[[tls.certs]] {}: `hosts` is empty; list the names this certificate is served for",
                c.cert_path
            )));
        }
        for h in &c.hosts {
            if let Err(e) = crate::certstore::parse_sni_host(h) {
                f.push(Finding::error(format!("{e:#}")));
            }
        }
        let Ok(certs) = crate::tls::load_certs(&c.cert_path) else {
            f.push(Finding::error(format!(
                "[[tls.certs]] {}: the certificate cannot be read; the proxy will not start",
                c.cert_path
            )));
            continue;
        };
        if let Ok(info) = crate::certstore::CertInfo::from_der(&certs[0]) {
            f.extend(cert_expiry_findings(
                &c.cert_path,
                &info,
                crate::certstore::RenewPlan::None,
                now,
            ));
        }
    }
    if cfg.tls.acme.enabled && !cfg.tls.acme.renew {
        f.push(Finding::warn(
            "tls.acme.renew = false: the ACME certificate is issued once and never renewed, so it \
             expires in at most 90 days. Leave renew on unless something else renews it.",
        ));
    }
}

/// Every client certificate the config presents, by where it is configured, for the expiry lint.
/// Only sections that would use theirs: an enabled collector, a JWKS URL, managed mode. One taken
/// from `[outbound]` is reported as `outbound`'s.
fn client_cert_paths(cfg: &Config) -> Vec<(&'static str, &str)> {
    let mut out: Vec<(&'static str, &str)> = vec![("upstream_tls", &cfg.upstream_tls.cert_path)];
    out.extend(
        cfg.upstream_tls
            .targets
            .iter()
            .map(|t| ("[[upstream_tls.targets]]", t.cert_path.as_str())),
    );
    for client in cfg.outbound_clients().into_iter().filter(|c| c.enabled) {
        if let Some((cert, _, origin)) =
            crate::outbound::Settings::of(client.outbound, client.url).identity
        {
            let what = match origin {
                crate::outbound::Origin::Section => client.section,
                crate::outbound::Origin::Outbound => "outbound",
            };
            out.push((what, cert));
        }
    }
    out.retain(|(_, path)| !path.is_empty());
    out
}

/// Client certificates the edge presents, the CAs it checks client certificates against, and the
/// CRLs it checks them with: nothing here renews any of them, so each is linted for running out.
/// A file that will not load is reported by the section that loads it, not here.
fn lint_client_cert_expiry(cfg: &Config, f: &mut Vec<Finding>) {
    let now = crate::certstore::now_unix();
    let mut seen = std::collections::BTreeSet::new();
    for (what, path) in client_cert_paths(cfg) {
        if !seen.insert(path) {
            continue;
        }
        let Some(info) = crate::tls::load_certs(path)
            .ok()
            .and_then(|c| crate::certstore::CertInfo::from_der(&c[0]).ok())
        else {
            continue;
        };
        for mut finding in cert_expiry_findings(path, &info, crate::certstore::RenewPlan::None, now)
        {
            finding.message = format!("{what}: {}", finding.message);
            f.push(finding);
        }
    }

    if let Ok(Some(auth)) = crate::client_auth::ClientAuth::from_cfg(&cfg.tls) {
        trust_findings("tls.client_auth", &auth.trust(), now, f);
    }
    if let Ok(Some(header)) =
        crate::client_cert_header::TrustedHeader::from_cfg(&cfg.trusted_client_cert_header)
    {
        if let Some(verifier) = header.verifier() {
            trust_findings("trusted_client_cert_header", &verifier.trust(), now, f);
        }
    }
}

/// The CAs and CRLs a client-certificate verifier (`what`) was built from, linted for running out.
fn trust_findings(
    what: &str,
    trust: &crate::client_auth::TrustInfo,
    now: i64,
    f: &mut Vec<Finding>,
) {
    for ca in &trust.cas {
        let days = ca.info.days_left(now);
        if ca.info.not_after <= now {
            f.push(Finding::error(format!(
                "{what}.ca_path: the CA {:?} has expired, so every client certificate it issued is \
                 refused. Replace the CA bundle (it is reloaded on change).",
                ca.name
            )));
        } else if days < 21 {
            f.push(Finding::warn(format!(
                "{what}.ca_path: the CA {:?} expires in {days} day(s); after that every client \
                 certificate it issued is refused. Add its successor to the bundle now.",
                ca.name
            )));
        }
    }
    for crl in &trust.crls {
        if crl.info.stale(now) {
            f.push(Finding::warn(format!(
                "{what}.crl_paths {}: past its nextUpdate, so the CA has published a newer one. This \
                 one goes on being used, and revocations since it are not applied. Fetch the current \
                 CRL (the file is reloaded on change).",
                crl.name
            )));
        }
    }
}

/// Expiry findings for one certificate. Split out so the thresholds are testable without files.
pub fn cert_expiry_findings(
    path: &str,
    info: &crate::certstore::CertInfo,
    plan: crate::certstore::RenewPlan,
    now: i64,
) -> Vec<Finding> {
    use crate::certstore::RenewPlan;
    let days = info.days_left(now);
    let renews = plan != RenewPlan::None;
    let mut f = Vec::new();
    if info.not_after <= now {
        f.push(Finding::error(format!(
            "the certificate at {path} has expired; clients will refuse it.{}",
            if renews {
                " Renewal is configured but has not succeeded — check the log for renewal errors."
            } else {
                " Replace it — the running proxy reloads the new files without a restart."
            }
        )));
    } else if days < 7 {
        f.push(Finding::error(format!(
            "the certificate at {path} expires in {days} day(s).{}",
            if renews {
                " Renewal should have happened at two-thirds of its lifetime; check the log and \
                 GET /__edgeguard/tls for the last renewal error."
            } else {
                " Nothing in this process renews it; replace the files before then."
            }
        )));
    } else if days < 21 && !renews {
        f.push(Finding::warn(format!(
            "the certificate at {path} expires in {days} days and nothing in this process renews \
             it; replace the files (they are reloaded automatically) or use [tls.acme]."
        )));
    } else if crate::certstore::renewal_due(info.not_before, info.not_after, now) && renews {
        f.push(Finding::info(format!(
            "the certificate at {path} is past two-thirds of its lifetime ({days} days left); the \
             running proxy renews it on its next check."
        )));
    }
    f
}

fn lint_cors(cfg: &Config, f: &mut Vec<Finding>) {
    let c = &cfg.cors;
    if !c.enabled {
        return;
    }
    let wildcard = c.allow_origins.iter().any(|o| o.trim() == "*");
    if wildcard && c.allow_credentials {
        // Also rejected by build, but report it cleanly here so `doctor` names the exact fix.
        f.push(Finding::error(
            "cors.allow_credentials = true cannot be combined with a \"*\" origin; list explicit \
             origins instead.",
        ));
    } else if wildcard {
        f.push(Finding::warn(
            "cors.allow_origins = [\"*\"]: any website may make cross-origin requests and read \
             responses. Prefer an explicit origin list.",
        ));
    }
}

/// The listener timeouts and the drain. They are read when the listener starts, not by
/// `build_runtime`, so a value that does not parse is reported here as the startup error it is.
fn lint_listener(cfg: &Config, f: &mut Vec<Finding>) {
    let opts = match crate::serve::ServeOpts::from_cfg(&cfg.server) {
        Ok(opts) => opts,
        Err(e) => {
            f.push(Finding::error(format!(
                "{e:#}: EdgeGuard will refuse to start"
            )));
            return;
        }
    };
    if opts.header_read_timeout.is_none() {
        f.push(Finding::warn(
            "server.header_read_timeout = \"0\": a client can hold a connection open indefinitely \
             by sending nothing, or a byte at a time, before auth or rate limiting run. Keep the 30s \
             default unless something in front of EdgeGuard already enforces one.",
        ));
    }
    let drain = opts.drain_delay + opts.drain_timeout;
    if drain >= std::time::Duration::from_secs(30) {
        f.push(Finding::warn(format!(
            "server.drain_delay + server.drain_timeout = {}s, at or over Kubernetes' default 30s \
             terminationGracePeriodSeconds: the process is killed before the drain ends and \
             in-flight requests are cut. Raise terminationGracePeriodSeconds above it, or shorten \
             the drain.",
            drain.as_secs()
        )));
    }
}

/// `[tls.client_auth]` is loaded when the listener starts, so a CA bundle or CRL that will not load
/// is reported here as the startup error it is. `optional` with nothing reading the certificate is
/// a verifier with no effect: a client without a certificate is let in exactly like one with.
/// `[trusted_client_cert_header]` is built with the pipeline, not the runtime, so settings that
/// refuse startup are reported here. A header that is read but required by nothing gives a client
/// without a certificate the same access, like `tls.client_auth.mode = "optional"`.
fn lint_trusted_header(cfg: &Config, f: &mut Vec<Finding>) {
    match crate::client_cert_header::TrustedHeader::from_cfg(&cfg.trusted_client_cert_header) {
        Err(e) => f.push(Finding::error(format!(
            "{e:#}: EdgeGuard will refuse to start"
        ))),
        Ok(Some(_))
            if cfg.auth.mode != "mtls" && cfg.tls.client_auth.forward_client_cert == "off" =>
        {
            f.push(Finding::warn(
                "[trusted_client_cert_header] is read, but neither auth.mode = \"mtls\" nor \
                 forward_client_cert = \"xfcc\" uses it: a request without a certificate gets the \
                 same access. Require it with auth, or pass it to the app.",
            ));
        }
        Ok(_) => {}
    }
}

fn lint_client_auth(cfg: &Config, f: &mut Vec<Finding>) {
    match crate::client_auth::ClientAuth::from_cfg(&cfg.tls) {
        Err(e) => f.push(Finding::error(format!(
            "{e:#}: EdgeGuard will refuse to start"
        ))),
        Ok(Some(auth))
            if auth.mode() == crate::client_auth::Mode::Optional
                && cfg.auth.mode != "mtls"
                && cfg.tls.client_auth.forward_client_cert == "off" =>
        {
            f.push(Finding::warn(
                "tls.client_auth.mode = \"optional\" with neither auth.mode = \"mtls\" nor \
                 forward_client_cert = \"xfcc\": certificates are checked when presented, but \
                 nothing uses them, so a client without one gets the same access. Use \
                 \"required\", or let auth or the app read the certificate.",
            ));
        }
        Ok(_) => {}
    }
}

/// `[upstream_tls]` is loaded when the proxy starts, not by `build_runtime`, so a CA bundle or
/// client certificate that will not load is reported here as the startup error it is. A
/// `[[upstream_tls.targets]]` entry that names no configured upstream is almost always a typo, and
/// it fails quietly: that upstream gets the default settings.
fn lint_upstream_tls(cfg: &Config, f: &mut Vec<Finding>) {
    if let Err(e) = crate::upstream::UpstreamTls::from_cfg(&cfg.upstream_tls) {
        f.push(Finding::error(format!(
            "{e:#}: EdgeGuard will refuse to start"
        )));
        return;
    }
    let upstreams: Vec<(String, u16)> = std::iter::once(cfg.upstream_base())
        .chain(cfg.upstreams.iter().map(|u| u.target.clone()))
        .chain(
            cfg.upstreams
                .iter()
                .flat_map(|u| u.targets.iter().chain(&u.backup).map(|t| t.url.clone())),
        )
        .filter_map(|url| crate::upstream::target_key(&url).ok())
        .collect();
    for t in &cfg.upstream_tls.targets {
        if let Ok(key) = crate::upstream::target_key(&t.target) {
            if !upstreams.contains(&key) {
                f.push(Finding::warn(format!(
                    "[[upstream_tls.targets]] target = {:?} matches no https:// upstream \
                     (server.upstream, or a [[upstreams]] target or targets entry, by host and \
                     port), so its settings are never used.",
                    t.target
                )));
            }
        }
    }
}

/// A pool fails over only as fast as it can tell a target is gone. Without a connect timeout, a
/// target whose packets are dropped holds each request for all of `upstream_timeout` before the
/// next one is tried; with neither a health check nor ejection, a dead target is tried, and fails,
/// on every request that comes to it.
fn lint_pools(cfg: &Config, f: &mut Vec<Finding>) {
    let pools: Vec<_> = cfg
        .upstreams
        .iter()
        .filter(|u| !u.targets.is_empty())
        .collect();
    if pools.is_empty() {
        return;
    }
    if crate::config::parse_duration(&cfg.validation.upstream_connect_timeout)
        .is_ok_and(|d| d.is_zero())
    {
        f.push(Finding::warn(
            "validation.upstream_connect_timeout = \"0\" with [[upstreams]] targets: a target that \
             drops packets (a partitioned network, a firewall) holds each request for the whole \
             upstream_timeout before the next target is tried. Keep a few seconds.",
        ));
    }
    for u in pools {
        let checked = !u.health_check.path.is_empty() || u.health_check.kind == "tcp";
        if !checked && u.eject_after == 0 {
            f.push(Finding::warn(format!(
                "[[upstreams]] path = {:?} has neither a health check nor eject_after: nothing \
                 takes a target out of rotation, so while one is down every request that comes to it \
                 tries it and fails over. Set eject_after (default 1), or a health check.",
                u.path
            )));
        }
    }
}

/// The collectors' clients are built once at startup, outside the runtime `doctor` builds, so
/// their TLS and proxy settings are checked here. The control plane, the JWKS fetch, the alert
/// webhook and LLM telemetry are checked by building the client and the runtime.
fn lint_outbound(cfg: &Config, f: &mut Vec<Finding>) {
    let clients = [
        (
            cfg.log.ship.enabled,
            &cfg.log.ship.outbound,
            "log.ship",
            &cfg.log.ship.url,
        ),
        (
            cfg.tracing.enabled,
            &cfg.tracing.outbound,
            "tracing",
            &cfg.tracing.endpoint,
        ),
        (
            cfg.metrics.otlp.enabled,
            &cfg.metrics.otlp.outbound,
            "metrics.otlp",
            &cfg.metrics.otlp.endpoint,
        ),
    ];
    for (enabled, outbound, what, url) in clients {
        if !enabled || url.trim().is_empty() {
            continue;
        }
        if let Err(e) = crate::outbound::builder(outbound, what, url.trim()) {
            f.push(Finding::error(format!(
                "{e:#}: EdgeGuard will refuse to start"
            )));
        }
    }

    // `[outbound]`'s CA and certificate reach `https://` URLs only. A section on plain http:// is
    // not an error — it may be a collector on this machine — but to another machine it sends in
    // clear text what the operator set `[outbound]` up to protect. `control_plane` has its own.
    for client in cfg.outbound_clients() {
        if client.enabled
            && client.section != "control_plane"
            && is_remote_http(client.url)
            && crate::outbound::Settings::would_inherit_tls(client.outbound)
        {
            f.push(Finding::warn(format!(
                "{}: {:?} is plain http:// to another machine, and [outbound]'s extra_ca_path and \
                 client certificate apply to https:// URLs only, so this client uses neither and \
                 what it sends crosses the network in clear text. Use https://.",
                client.section, client.url
            )));
        }
    }
    if !cfg.outbound.is_empty() {
        let users = crate::outbound::inheritors(cfg);
        f.push(Finding::info(if users.is_empty() {
            "[outbound] is set, but no client this config turns on takes anything from it: each \
             is off or sets its own keys."
                .to_string()
        } else {
            let users: Vec<String> = users
                .into_iter()
                .map(|(section, keys)| format!("{section} ({})", keys.join(", ")))
                .collect();
            format!("[outbound] is used by {}.", users.join(", "))
        }));
    }
}

/// Whether `url` is plain `http://` to a host other than this one.
fn is_remote_http(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    let host = url.host_str().unwrap_or("");
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let local = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    url.scheme() == "http" && !local
}

fn lint_forwarded(cfg: &Config, f: &mut Vec<Finding>) {
    if cfg.server.trust_forwarded_for {
        f.push(Finding::info(
            "server.trust_forwarded_for = true: only correct when EdgeGuard is behind a trusted \
             proxy/LB that sets X-Forwarded-For. If it's directly reachable, clients can spoof \
             their IP and defeat per-IP rate limiting.",
        ));
    }
}

/// `server.proxy_protocol` names the client from the balancer's header; two settings can undo
/// that. Behind an L4 balancer, `X-Forwarded-For` is whatever the client wrote, so trusting it
/// lets the client choose its address after all. And `[trusted_client_cert_header]` is trusted by
/// the TCP peer: from an L4 balancer, a certificate header is the client's own. (An L7 balancer
/// that also sends PROXY headers, like HAProxy in HTTP mode, writes both itself.)
fn lint_proxy_protocol(cfg: &Config, f: &mut Vec<Finding>) {
    let s = &cfg.server;
    if !s.proxy_protocol {
        if !s.proxy_protocol_trusted.is_empty() {
            f.push(Finding::info(
                "server.proxy_protocol_trusted is set but server.proxy_protocol is off: no PROXY \
                 header is read, and every client behind an L4 balancer has its address.",
            ));
        }
        return;
    }
    if s.trust_forwarded_for {
        f.push(Finding::warn(
            "server.trust_forwarded_for with server.proxy_protocol: an L4 balancer passes the \
             client's own X-Forwarded-For through, and it wins over the PROXY header, so a client \
             chooses its address after all. Turn trust_forwarded_for off unless the balancer is L7 \
             and overwrites the header.",
        ));
    }
    let cidrs = |list: &[String]| -> Vec<crate::access::Cidr> {
        list.iter()
            .filter_map(|t| crate::access::Cidr::parse(t).ok())
            .collect()
    };
    let header = &cfg.trusted_client_cert_header;
    if !header.name.is_empty() {
        let balancers = cidrs(&s.proxy_protocol_trusted);
        let shared: Vec<&String> = header
            .trusted_proxies
            .iter()
            .filter(|t| {
                crate::access::Cidr::parse(t)
                    .is_ok_and(|c| balancers.iter().any(|b| b.overlaps(&c)))
            })
            .collect();
        if !shared.is_empty() {
            f.push(Finding::warn(format!(
                "trusted_client_cert_header.trusted_proxies {shared:?} overlaps \
                 server.proxy_protocol_trusted: the certificate header is trusted from the PROXY \
                 balancer. If it passes TCP through (an NLB, a TCP proxy), the header is the \
                 client's own and any client can claim any certificate. Only an L7 balancer that \
                 terminates TLS and writes the header belongs in both."
            )));
        }
    }
}

fn lint_secrets(cfg: &Config, f: &mut Vec<Finding>) {
    // A secret field is populated by `Config::load` either from the file or from the environment
    // (the env/`*_FILE` override wins). We only want to nudge when it came from the *file* — so
    // check whether the env (or `*_FILE`) source is set; if it is, the value is env-backed and the
    // recommended path is already in use. Without this, a correct deployment using the env vars
    // gets wrongly scolded for "committing" a secret.
    if !cfg.auth.jwt.secret.is_empty() && !env_sourced("EDGEGUARD_JWT_SECRET") {
        f.push(Finding::info(
            "auth.jwt.secret is set in the config file; prefer the EDGEGUARD_JWT_SECRET env var (or \
             EDGEGUARD_JWT_SECRET_FILE) so the secret isn't committed.",
        ));
    }
    if !cfg.auth.api_keys.is_empty() && !env_sourced("EDGEGUARD_API_KEYS") {
        f.push(Finding::info(
            "auth.api_keys are listed in the config file; prefer the EDGEGUARD_API_KEYS env var (or \
             EDGEGUARD_API_KEYS_FILE).",
        ));
    }
    if !cfg.control_plane.edge_token.is_empty() && !env_sourced("EDGEGUARD_CP_EDGE_TOKEN") {
        f.push(Finding::info(
            "control_plane.edge_token is set in the config file; prefer EDGEGUARD_CP_EDGE_TOKEN (or \
             EDGEGUARD_CP_EDGE_TOKEN_FILE).",
        ));
    }
}

/// Whether a secret env var (or its `*_FILE` companion) is set non-empty — i.e. `Config::load`
/// would have sourced the value from the environment rather than the config file.
fn env_sourced(name: &str) -> bool {
    let nonempty = |k: String| std::env::var(k).is_ok_and(|v| !v.is_empty());
    nonempty(name.to_string()) || nonempty(format!("{name}_FILE"))
}

fn lint_control_plane(cfg: &Config, f: &mut Vec<Finding>) {
    if cfg.control_plane.enforce_quota && !cfg.control_plane.enabled {
        f.push(Finding::error(
            "control_plane.enforce_quota = true requires control_plane.enabled = true (with \
             url/tenant_id/edge_token); otherwise the quota gate can never be evaluated.",
        ));
    }
    let cp = &cfg.control_plane;
    if !matches!(cp.boot_without_policy.as_str(), "local" | "refuse") {
        f.push(Finding::error(format!(
            "control_plane.boot_without_policy = {:?}: expected \"local\" or \"refuse\"; \
             EdgeGuard will refuse to start.",
            cp.boot_without_policy
        )));
    }
    if !cp.enabled {
        return;
    }
    if is_remote_http(&cp.url) {
        f.push(Finding::warn(format!(
            "control_plane.url {:?} is plain http:// to another machine: the edge token, the \
             pushed policy (and any keys in it) and usage reports cross the network in clear \
             text. Use https:// — with control_plane.ca_path for a control plane behind a \
             private CA.",
            cp.url
        )));
    }
    if cp.cache_path.is_empty() {
        f.push(Finding::warn(
            "control_plane.cache_path is empty: the control-plane policy is kept in memory only, \
             so a restart while the control plane is unreachable starts on this config file alone \
             — typically looser than the pushed policy. Set cache_path to keep the last policy on \
             disk (it holds the policy's secrets; it is written 0600).",
        ));
    } else {
        let dir = std::path::Path::new(&cp.cache_path)
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        if !dir.is_dir() {
            f.push(Finding::warn(format!(
                "control_plane.cache_path {:?}: directory {} does not exist, so the policy cannot \
                 be kept and a restart would start without it.",
                cp.cache_path,
                dir.display()
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn has_error(f: &[Finding]) -> bool {
        f.iter().any(|x| x.level == Level::Error)
    }

    #[test]
    fn default_config_has_no_errors() {
        // The shipped default (auth = none) warns but doesn't error.
        let f = lint(&Config::default());
        assert!(!has_error(&f), "{f:?}");
        assert!(f.iter().any(|x| x.message.contains("auth.mode = \"none\"")));
    }

    #[test]
    fn managed_mode_without_a_policy_cache_warns_and_a_bad_boot_mode_errors() {
        let mut cfg = Config::default();
        cfg.control_plane.enabled = true;
        let f = lint(&cfg);
        assert!(
            f.iter()
                .any(|x| x.level == Level::Warn && x.message.contains("cache_path is empty")),
            "{f:?}"
        );
        cfg.control_plane.cache_path = "/no/such/dir/policy.json".into();
        cfg.control_plane.boot_without_policy = "wait".into();
        let f = lint(&cfg);
        assert!(
            f.iter()
                .any(|x| x.level == Level::Warn && x.message.contains("does not exist")),
            "{f:?}"
        );
        assert!(
            f.iter()
                .any(|x| x.level == Level::Error && x.message.contains("boot_without_policy")),
            "{f:?}"
        );
        // Unmanaged, the cache settings mean nothing and say nothing.
        cfg.control_plane.enabled = false;
        cfg.control_plane.boot_without_policy = "local".into();
        assert!(!lint(&cfg).iter().any(|x| x.message.contains("cache_path")));
    }

    #[test]
    fn a_plain_http_control_plane_on_another_machine_warns() {
        let warned = |url: &str| {
            let mut cfg = Config::default();
            cfg.control_plane.enabled = true;
            cfg.control_plane.url = url.into();
            lint(&cfg)
                .iter()
                .any(|x| x.level == Level::Warn && x.message.contains("plain http://"))
        };
        assert!(warned("http://cp.internal:8080"));
        assert!(warned("http://10.0.0.5"));
        assert!(!warned("https://cp.internal"));
        assert!(!warned("http://localhost:8080"), "a sidecar control plane");
        assert!(!warned("http://127.0.0.1:8080"));
        assert!(!warned("http://[::1]:8080"));
    }

    #[test]
    fn pools_that_cannot_tell_a_target_is_gone_are_flagged() {
        let mut cfg = Config::default();
        let warned = |cfg: &Config, needle: &str| {
            lint(cfg)
                .iter()
                .any(|f| f.level == Level::Warn && f.message.contains(needle))
        };
        cfg.validation.upstream_connect_timeout = "0".into();
        assert!(
            !warned(&cfg, "upstream_connect_timeout"),
            "no pool, no finding"
        );
        cfg.upstreams = vec![crate::config::UpstreamRoute {
            path: "/".into(),
            targets: vec!["http://a:1".into(), "http://b:1".into()],
            ..Default::default()
        }];
        assert!(warned(&cfg, "upstream_connect_timeout"));
        assert!(!warned(&cfg, "nothing takes a target out"));
        cfg.upstreams[0].eject_after = 0;
        assert!(warned(&cfg, "nothing takes a target out"));
        cfg.upstreams[0].health_check.kind = "tcp".into();
        assert!(!warned(&cfg, "nothing takes a target out"), "a TCP check");
        cfg.upstreams[0].health_check.kind = "http".into();
        cfg.upstreams[0].health_check.path = "/healthz".into();
        assert!(!warned(&cfg, "nothing takes a target out"));
    }

    #[test]
    fn proxy_protocol_settings_that_refuse_startup_or_undo_it_are_flagged() {
        let mut cfg = Config::default();
        let with = |cfg: &Config, level: Level, needle: &str| {
            lint(cfg)
                .iter()
                .any(|f| f.level == level && f.message.contains(needle))
        };
        cfg.server.proxy_protocol_trusted = vec!["10.0.0.0/16".into()];
        assert!(with(&cfg, Level::Info, "server.proxy_protocol is off"));

        cfg.server.proxy_protocol = true;
        cfg.server.proxy_protocol_trusted.clear();
        assert!(with(
            &cfg,
            Level::Error,
            "proxy_protocol_trusted is required"
        ));
        cfg.server.proxy_protocol_trusted = vec!["::/0".into()];
        assert!(with(&cfg, Level::Error, "every address"));

        cfg.server.proxy_protocol_trusted = vec!["10.0.0.0/16".into()];
        assert!(!lint(&cfg)
            .iter()
            .any(|f| f.message.contains("proxy_protocol")));
        cfg.server.trust_forwarded_for = true;
        assert!(with(
            &cfg,
            Level::Warn,
            "a client chooses its address after all"
        ));
        cfg.server.trust_forwarded_for = false;

        // The certificate header trusted from the PROXY balancer: inside its range, or around it.
        cfg.trusted_client_cert_header.name = "X-Client-Cert".into();
        cfg.trusted_client_cert_header.trusted_proxies = vec!["10.1.0.7".into()];
        assert!(!with(
            &cfg,
            Level::Warn,
            "overlaps server.proxy_protocol_trusted"
        ));
        for overlapping in ["10.0.3.4", "10.0.0.0/8"] {
            cfg.trusted_client_cert_header.trusted_proxies = vec![overlapping.into()];
            assert!(
                with(&cfg, Level::Warn, "overlaps server.proxy_protocol_trusted"),
                "{overlapping}"
            );
        }
    }

    #[test]
    fn a_trusted_header_that_trusts_anyone_or_is_used_by_nothing_is_flagged() {
        let mut cfg = Config::default();
        cfg.trusted_client_cert_header.name = "X-Amzn-Mtls-Clientcert".into();
        let errors = |cfg: &Config| {
            lint(cfg)
                .into_iter()
                .filter(|f| f.level == Level::Error)
                .map(|f| f.message)
                .collect::<Vec<_>>()
        };
        assert!(
            errors(&cfg)
                .iter()
                .any(|e| e.contains("needs trusted_proxies or trusted_proxy_names")),
            "{:?}",
            errors(&cfg)
        );
        cfg.trusted_client_cert_header.trusted_proxies = vec!["0.0.0.0/0".into()];
        assert!(errors(&cfg).iter().any(|e| e.contains("every address")));
        cfg.trusted_client_cert_header.trusted_proxies.clear();
        cfg.trusted_client_cert_header.trusted_proxy_names = vec!["*".into()];
        assert!(errors(&cfg).iter().any(|e| e.contains("every certificate")));
        cfg.trusted_client_cert_header.trusted_proxy_names.clear();

        cfg.trusted_client_cert_header.trusted_proxies = vec!["10.0.0.0/16".into()];
        let unused = |cfg: &Config| {
            lint(cfg)
                .iter()
                .any(|f| f.level == Level::Warn && f.message.contains("neither auth.mode"))
        };
        assert!(!errors(&cfg)
            .iter()
            .any(|e| e.contains("trusted_client_cert_header")));
        assert!(unused(&cfg), "read, required by nothing");
        cfg.auth.mode = "mtls".into();
        assert!(!unused(&cfg));
        // And with mtls and only the header, the runtime builds: the header is a certificate source.
        assert!(crate::build_runtime(std::sync::Arc::new(cfg)).is_ok());
    }

    #[test]
    fn a_collector_client_that_will_not_build_is_an_error() {
        let mut cfg = Config::default();
        cfg.tracing.enabled = true;
        cfg.tracing.endpoint = "https://otel.internal:4318/v1/traces".into();
        cfg.tracing.outbound.ca_path = "/no/such/ca.pem".into();
        cfg.log.ship.enabled = true;
        cfg.log.ship.url = "http://vector.internal:9000".into();
        cfg.log.ship.outbound.client_cert_path = "/etc/eggrd/edge.pem".into();
        cfg.log.ship.outbound.client_key_path = "/etc/eggrd/edge.key".into();
        cfg.metrics.otlp.enabled = true;
        cfg.metrics.otlp.endpoint = "https://otel.internal:4318/v1/metrics".into();
        cfg.metrics.otlp.outbound.proxy = "socks5://egress:1080".into();
        let errors: Vec<String> = lint(&cfg)
            .into_iter()
            .filter(|x| x.level == Level::Error)
            .map(|x| x.message)
            .collect();
        for key in ["tracing.ca_path", "log.ship.ca_path", "metrics.otlp.proxy"] {
            assert!(errors.iter().any(|e| e.contains(key)), "{key}: {errors:?}");
        }
        // Off, its settings are not checked.
        cfg.tracing.enabled = false;
        cfg.log.ship.enabled = false;
        cfg.metrics.otlp.enabled = false;
        assert!(!has_error(&lint(&cfg)));
    }

    #[test]
    fn default_listener_settings_lint_clean() {
        let f = lint(&Config::default());
        assert!(
            !f.iter().any(|x| x.message.contains("server.")),
            "the defaults must not trip a listener lint: {f:?}"
        );
    }

    #[test]
    fn an_unparseable_listener_duration_is_an_error() {
        let mut cfg = Config::default();
        cfg.server.drain_timeout = "soon".into();
        let f = lint(&cfg);
        assert!(
            f.iter()
                .any(|x| x.level == Level::Error && x.message.contains("server.drain_timeout")),
            "{f:?}"
        );
    }

    #[test]
    fn a_disabled_header_timeout_and_a_drain_past_the_kill_deadline_warn() {
        let mut cfg = Config::default();
        cfg.server.header_read_timeout = "0".into();
        cfg.server.drain_delay = "10s".into();
        cfg.server.drain_timeout = "20s".into();
        let f = lint(&cfg);
        let warns: Vec<_> = f.iter().filter(|x| x.level == Level::Warn).collect();
        assert!(
            warns
                .iter()
                .any(|x| x.message.contains("header_read_timeout")),
            "{f:?}"
        );
        assert!(warns.iter().any(|x| x.message.contains("= 30s")), "{f:?}");
    }

    #[test]
    fn client_auth_without_tls_or_without_a_ca_is_an_error() {
        let mut cfg = Config::default();
        cfg.tls.client_auth.mode = "required".into();
        cfg.tls.client_auth.ca_path = "/etc/eggrd/client-ca.pem".into();
        let f = lint(&cfg);
        assert!(
            f.iter()
                .any(|x| x.level == Level::Error && x.message.contains("[tls] enabled")),
            "{f:?}"
        );
        cfg.tls.enabled = true;
        cfg.tls.client_auth.ca_path = String::new();
        let f = lint(&cfg);
        assert!(
            f.iter()
                .any(|x| x.level == Level::Error && x.message.contains("ca_path is required")),
            "{f:?}"
        );
    }

    #[test]
    fn an_upstream_tls_file_that_will_not_load_is_an_error() {
        let mut cfg = Config::default();
        cfg.upstream_tls.ca_path = "/no/such/upstream-ca.pem".into();
        let f = lint(&cfg);
        assert!(
            f.iter()
                .any(|x| x.level == Level::Error && x.message.contains("ca_path")),
            "{f:?}"
        );
    }

    #[test]
    fn an_upstream_tls_target_that_matches_no_upstream_warns() {
        let mut cfg = Config::default();
        cfg.server.upstream = "https://app.internal:8443".into();
        cfg.upstream_tls.targets = vec![
            crate::config::UpstreamTlsTarget {
                target: "https://app.internal:8443".into(),
                ..Default::default()
            },
            crate::config::UpstreamTlsTarget {
                target: "https://app.internl:8443".into(),
                ..Default::default()
            },
        ];
        let f = lint(&cfg);
        let warns: Vec<_> = f
            .iter()
            .filter(|x| x.message.contains("matches no https:// upstream"))
            .collect();
        assert_eq!(warns.len(), 1, "{f:?}");
        assert!(warns[0].message.contains("app.internl"), "{f:?}");
    }

    #[test]
    fn pool_targets_and_backups_count_as_upstreams_for_upstream_tls() {
        let mut cfg = Config {
            upstreams: vec![crate::config::UpstreamRoute {
                path: "/".into(),
                targets: vec![crate::config::TargetCfg {
                    url: "https://a.internal".into(),
                    weight: None,
                }],
                backup: vec!["https://dr.example.com:8443".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        cfg.upstream_tls.targets = ["https://a.internal", "https://dr.example.com:8443"]
            .iter()
            .map(|t| crate::config::UpstreamTlsTarget {
                target: t.to_string(),
                ..Default::default()
            })
            .collect();
        let f = lint(&cfg);
        assert!(
            !f.iter()
                .any(|x| x.message.contains("matches no https:// upstream")),
            "{f:?}"
        );
    }

    #[test]
    fn placeholder_basic_credential_is_an_error() {
        let mut cfg = Config::default();
        cfg.auth.mode = "basic".into();
        let mut users = BTreeMap::new();
        users.insert(
            "admin".to_string(),
            "$argon2id$REPLACE_ME$run-edgeguard---hash".to_string(),
        );
        cfg.auth.users = users;
        let f = lint(&cfg);
        assert!(has_error(&f), "{f:?}");
    }

    #[test]
    fn plaintext_basic_password_warns_not_errors() {
        let mut cfg = Config::default();
        cfg.auth.mode = "basic".into();
        let mut users = BTreeMap::new();
        users.insert("admin".to_string(), "hunter2".to_string());
        cfg.auth.users = users;
        let f = lint(&cfg);
        assert!(!has_error(&f), "{f:?}");
        assert!(f.iter().any(|x| x.level == Level::Warn));
    }

    #[test]
    fn credentialed_wildcard_cors_is_an_error() {
        let mut cfg = Config::default();
        cfg.cors.enabled = true;
        cfg.cors.allow_origins = vec!["*".into()];
        cfg.cors.allow_credentials = true;
        assert!(has_error(&lint(&cfg)));
    }

    #[test]
    fn tls_enabled_without_any_certificate_source_is_an_error() {
        let mut cfg = Config::default();
        cfg.tls.enabled = true;
        assert!(
            has_error(&lint(&cfg)),
            "no cert, no ACME, no self-signed must be an error"
        );

        // Any one of the three ways to get a certificate clears it.
        cfg.tls.self_signed = true;
        cfg.tls.cert_path = "/tmp/c.pem".into();
        cfg.tls.key_path = "/tmp/k.pem".into();
        assert!(!has_error(&lint(&cfg)));
    }

    #[test]
    fn self_signed_without_paths_is_an_error_and_with_them_only_warns() {
        let mut cfg = Config::default();
        cfg.tls.enabled = true;
        cfg.tls.self_signed = true;
        // The paths are the OUTPUT location, so omitting them is not a "we'll pick one" case.
        assert!(has_error(&lint(&cfg)));

        cfg.tls.cert_path = "/tmp/c.pem".into();
        cfg.tls.key_path = "/tmp/k.pem".into();
        let f = lint(&cfg);
        assert!(!has_error(&f));
        assert!(
            f.iter().any(|x| x.message.contains("proves no identity")),
            "self-signed must warn that it is not publicly trusted"
        );
    }

    #[test]
    fn redirect_port_colliding_with_another_listener_is_an_error() {
        let mut cfg = Config::default();
        cfg.tls.enabled = true;
        cfg.tls.self_signed = true;
        cfg.tls.cert_path = "/tmp/c.pem".into();
        cfg.tls.key_path = "/tmp/k.pem".into();

        cfg.tls.redirect_port = cfg.server.port;
        assert!(
            has_error(&lint(&cfg)),
            "redirect port == server port must be an error"
        );

        cfg.server.admin_port = 9090;
        cfg.tls.redirect_port = 9090;
        assert!(
            has_error(&lint(&cfg)),
            "redirect port == admin port must be an error"
        );

        cfg.tls.redirect_port = 80;
        assert!(!has_error(&lint(&cfg)));
    }

    #[test]
    fn non_3xx_redirect_status_is_an_error() {
        let mut cfg = Config::default();
        cfg.tls.enabled = true;
        cfg.tls.self_signed = true;
        cfg.tls.cert_path = "/tmp/c.pem".into();
        cfg.tls.key_path = "/tmp/k.pem".into();
        cfg.tls.redirect_port = 80;
        cfg.tls.redirect_status = 200;
        assert!(has_error(&lint(&cfg)));
    }

    #[test]
    fn hsts_without_tls_warns_that_it_does_nothing() {
        let cfg = Config::default();
        // The shipped default is hsts = true, tls.enabled = false — a combination that reads as
        // protected and is not, which is exactly what doctor exists to say out loud.
        assert!(cfg.headers.hsts && !cfg.tls.enabled);
        let f = lint(&cfg);
        assert!(f
            .iter()
            .any(|x| x.message.contains("Strict-Transport-Security")));
        assert!(!has_error(&f), "it is a warning, not an error");
    }

    #[test]
    fn jwt_without_any_key_is_an_error() {
        let mut cfg = Config::default();
        cfg.auth.mode = "jwt".into();
        cfg.auth.jwt.secret = String::new();
        assert!(has_error(&lint(&cfg)));
    }

    #[test]
    fn secret_in_config_warns_only_when_not_env_sourced() {
        let mut cfg = Config::default();
        cfg.auth.jwt.secret = "shhh".into();
        let mentions_secret =
            |f: &[Finding]| f.iter().any(|x| x.message.contains("auth.jwt.secret"));

        // No env source set → the value came from the file, so nudge.
        std::env::remove_var("EDGEGUARD_JWT_SECRET");
        std::env::remove_var("EDGEGUARD_JWT_SECRET_FILE");
        assert!(mentions_secret(&lint(&cfg)));

        // Env-backed (the recommended path) → must NOT be scolded for "committing" a secret.
        std::env::set_var("EDGEGUARD_JWT_SECRET", "shhh");
        assert!(!mentions_secret(&lint(&cfg)));
        std::env::remove_var("EDGEGUARD_JWT_SECRET");
    }

    /// An expired certificate written to a temp dir; returns (dir, cert path, key path).
    fn expired_pair(tag: &str) -> (std::path::PathBuf, String, String) {
        let dir = std::env::temp_dir().join(format!("eg-doctor-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(100);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(10);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let (c, k) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&c, cert.pem()).unwrap();
        std::fs::write(&k, key.serialize_pem()).unwrap();
        let s = |p: std::path::PathBuf| p.to_string_lossy().into_owned();
        (dir, s(c), s(k))
    }

    fn has(f: &[Finding], needle: &str) -> bool {
        f.iter().any(|x| x.message.contains(needle))
    }

    #[test]
    fn an_acme_client_that_will_not_build_is_an_error() {
        let mut cfg = Config::default();
        cfg.tls.acme.enabled = true;
        cfg.tls.acme.outbound.ca_path = "/no/such/acme-ca.pem".into();
        assert!(has(&lint(&cfg), "tls.acme.ca_path"));
        cfg.tls.acme.outbound.ca_path.clear();
        cfg.tls.acme.directory_url = "http://acme.internal/directory".into();
        assert!(has(&lint(&cfg), "not https://"));
        // Off, it is not checked.
        cfg.tls.acme.enabled = false;
        assert!(!has(&lint(&cfg), "not https://"));
    }

    #[test]
    fn outbound_defaults_are_reported_where_they_are_used() {
        let (dir, cert, key) = expired_pair("outbound");
        let mut cfg = Config::default();
        cfg.outbound.client_cert_path = cert;
        cfg.outbound.client_key_path = key;
        cfg.outbound.proxy = "http://egress:3128".into();
        cfg.inherit_outbound();
        let info = |f: &[Finding]| {
            f.iter()
                .filter(|x| x.level == Level::Info && x.message.starts_with("[outbound]"))
                .map(|x| x.message.clone())
                .collect::<Vec<_>>()
        };
        let f = lint(&cfg);
        assert_eq!(
            info(&f),
            [
                "[outbound] is set, but no client this config turns on takes anything from it: \
              each is off or sets its own keys."
            ]
        );
        assert!(
            !has(&f, "outbound: "),
            "an unused certificate is not linted"
        );

        cfg.log.ship.enabled = true;
        cfg.log.ship.url = "https://logs.internal/ingest".into();
        cfg.alerts.enabled = true;
        cfg.alerts.webhook_url = "https://hooks.chat.example/T0".into();
        cfg.alerts.outbound.proxy = "none".into();
        let f = lint(&cfg);
        assert_eq!(
            info(&f),
            ["[outbound] is used by log.ship (client_cert_path, proxy), alerts (client_cert_path)."]
        );
        // Its certificate is linted once, as `[outbound]`'s, however many sections present it.
        let expired: Vec<&Finding> = f
            .iter()
            .filter(|x| x.message.starts_with("outbound: ") && x.message.contains("expired"))
            .collect();
        assert_eq!(expired.len(), 1, "{f:?}");

        // Plain http:// to another machine gets none of its TLS: say so. On this machine, fine.
        let warned = |cfg: &Config| has(&lint(cfg), "apply to https:// URLs only");
        assert!(!warned(&cfg));
        cfg.log.ship.url = "http://127.0.0.1:9000/ingest".into();
        assert!(!warned(&cfg));
        cfg.log.ship.url = "http://logs.internal:9000/ingest".into();
        assert!(warned(&cfg));
        // Nothing to inherit but the proxy: nothing lost on http://.
        cfg.outbound.client_cert_path.clear();
        cfg.outbound.client_key_path.clear();
        cfg.inherit_outbound();
        assert!(!warned(&cfg));
        let _ = std::fs::remove_dir_all(dir);

        // A broken [outbound] fails the runtime build — startup, reload and `doctor` — even with
        // nothing using it yet.
        let mut cfg = Config::default();
        cfg.outbound.ca_path = "/etc/eggrd/corp-ca.pem".into();
        let e = crate::build_runtime(std::sync::Arc::new(cfg))
            .err()
            .unwrap();
        assert!(
            format!("{e:#}").contains("outbound.ca_path is not a setting"),
            "{e:#}"
        );
    }

    /// `lint` reads the certificate on disk — but only when TLS is on and a path is set.
    #[test]
    fn lint_reports_an_expired_certificate_on_disk_only_when_tls_serves_it() {
        let (dir, cert, key) = expired_pair("lint");
        let mut cfg = Config::default();
        cfg.tls.cert_path = cert.clone();
        cfg.tls.key_path = key;

        cfg.tls.enabled = false;
        assert!(
            !has(&lint(&cfg), "has expired"),
            "TLS off: the file is not served"
        );

        cfg.tls.enabled = true;
        let f = lint(&cfg);
        assert!(
            f.iter()
                .any(|x| x.level == Level::Error && x.message.contains("has expired")),
            "{:?}",
            f.iter().map(|x| &x.message).collect::<Vec<_>>()
        );

        cfg.tls.cert_path = String::new();
        assert!(!has(&lint(&cfg), "has expired"), "no path: nothing to read");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `[[tls.certs]]` mistakes that would stop the proxy at startup are errors here first.
    #[test]
    fn sni_certificates_with_bad_hosts_or_unreadable_files_are_errors() {
        let (dir, cert, key) = expired_pair("sni");
        let mut cfg = Config::default();
        cfg.tls.enabled = true;
        cfg.tls.cert_path = cert.clone();
        cfg.tls.key_path = key.clone();
        let sni = |hosts: &[&str], path: &str| crate::config::SniCertCfg {
            cert_path: path.to_string(),
            key_path: key.clone(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
        };
        let errors = |cfg: &Config| {
            lint(cfg)
                .into_iter()
                .filter(|x| x.level == Level::Error && x.message.contains("tls.certs"))
                .count()
        };
        cfg.tls.certs = vec![sni(&["api.example.com", "*.example.org"], &cert)];
        assert_eq!(errors(&cfg), 0);
        cfg.tls.certs = vec![sni(&[], &cert)];
        assert_eq!(errors(&cfg), 1, "empty hosts");
        cfg.tls.certs = vec![sni(&["a.*.example.com"], &cert)];
        assert_eq!(errors(&cfg), 1, "wildcard not in the first label");
        cfg.tls.certs = vec![sni(&["api.example.com"], "/nonexistent/cert.pem")];
        assert_eq!(errors(&cfg), 1, "unreadable certificate");
        // An extra pair's expiry is reported like the default one's.
        cfg.tls.certs = vec![sni(&["api.example.com"], &cert)];
        let expired = lint(&cfg)
            .into_iter()
            .filter(|x| x.message.contains("has expired"))
            .count();
        assert_eq!(expired, 2, "the default pair and the extra one");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn acme_challenge_settings_that_would_fail_an_order_are_errors() {
        let mut cfg = Config::default();
        cfg.tls.enabled = true;
        cfg.tls.acme.enabled = true;
        cfg.tls.acme.domains = vec!["*.example.com".into()];
        let errors = |cfg: &Config| -> Vec<String> {
            lint(cfg)
                .into_iter()
                .filter(|x| x.level == Level::Error)
                .map(|x| x.message)
                .collect()
        };
        assert!(
            errors(&cfg).iter().any(|m| m.contains("wildcard")),
            "wildcard over http-01"
        );
        cfg.tls.acme.challenge = "dns-01".into();
        assert!(
            errors(&cfg).iter().any(|m| m.contains("provider")),
            "dns-01 with no provider"
        );
        cfg.tls.acme.dns.provider = "cloudflare".into();
        cfg.tls.acme.dns.zone_id = "zone".into();
        cfg.tls.acme.dns.api_token_env = "EG_DOCTOR_TOKEN_UNSET_NEVER".into();
        assert!(
            errors(&cfg)
                .iter()
                .any(|m| m.contains("$EG_DOCTOR_TOKEN_UNSET_NEVER")),
            "token variable unset"
        );
        std::env::set_var("EG_DOCTOR_TOKEN_SET", "t");
        cfg.tls.acme.dns.api_token_env = "EG_DOCTOR_TOKEN_SET".into();
        assert!(
            !errors(&cfg)
                .iter()
                .any(|m| m.contains("tls.acme") || m.contains("wildcard")),
            "{:?}",
            errors(&cfg)
        );
        cfg.tls.acme.challenge = "tls-alpn-01".into();
        assert!(errors(&cfg).iter().any(|m| m.contains("tls-alpn-01")));
    }

    #[test]
    fn acme_without_renewal_is_warned_about() {
        let (dir, cert, key) = expired_pair("acme");
        let mut cfg = Config::default();
        cfg.tls.enabled = true;
        cfg.tls.cert_path = cert;
        cfg.tls.key_path = key;
        cfg.tls.acme.enabled = true;
        cfg.tls.acme.domains = vec!["example.com".into()];

        cfg.tls.acme.renew = true;
        assert!(!has(&lint(&cfg), "tls.acme.renew = false"));
        cfg.tls.acme.renew = false;
        assert!(has(&lint(&cfg), "tls.acme.renew = false"));
        cfg.tls.acme.enabled = false;
        assert!(
            !has(&lint(&cfg), "tls.acme.renew = false"),
            "ACME off: nothing to renew"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn certificate_expiry_thresholds_depend_on_whether_anything_renews() {
        use crate::certstore::{CertInfo, RenewPlan};
        let day = 86_400;
        let now = 1_000 * day;
        let cert = |days_left: i64| CertInfo {
            not_before: now - 80 * day,
            not_after: now + days_left * day,
            serial: "01".into(),
            self_issued: true,
            ari_id: None,
        };
        let levels = |days_left, plan| {
            cert_expiry_findings("c.pem", &cert(days_left), plan, now)
                .into_iter()
                .map(|x| x.level)
                .collect::<Vec<_>>()
        };
        assert_eq!(levels(-1, RenewPlan::SelfSigned), vec![Level::Error]);
        assert_eq!(levels(3, RenewPlan::None), vec![Level::Error]);
        assert_eq!(levels(3, RenewPlan::Acme), vec![Level::Error]);
        assert_eq!(levels(14, RenewPlan::None), vec![Level::Warn]);
        // Renewing, past the ⅔ point but with weeks left: only informational.
        assert_eq!(levels(14, RenewPlan::Acme), vec![Level::Info]);
        assert!(levels(200, RenewPlan::None).is_empty());
    }
}
