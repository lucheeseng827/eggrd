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
/// the pipeline (auth → rate limit → TLS → CORS → secrets → managed mode).
pub fn lint(cfg: &Config) -> Vec<Finding> {
    let mut f = Vec::new();
    lint_auth(cfg, &mut f);
    lint_ratelimit(cfg, &mut f);
    lint_tls(cfg, &mut f);
    lint_cors(cfg, &mut f);
    lint_forwarded(cfg, &mut f);
    lint_secrets(cfg, &mut f);
    lint_control_plane(cfg, &mut f);
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

fn lint_tls(cfg: &Config, f: &mut Vec<Finding>) {
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

fn lint_forwarded(cfg: &Config, f: &mut Vec<Finding>) {
    if cfg.server.trust_forwarded_for {
        f.push(Finding::info(
            "server.trust_forwarded_for = true: only correct when EdgeGuard is behind a trusted \
             proxy/LB that sets X-Forwarded-For. If it's directly reachable, clients can spoof \
             their IP and defeat per-IP rate limiting.",
        ));
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
}
