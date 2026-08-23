//! ACME (Let's Encrypt) automatic certificates via the HTTP-01 challenge, using
//! `instant-acme` for the protocol and `rcgen` for the CSR.
//!
//! Flow: create/restore an ACME account → open an order for the configured domains → answer
//! each domain's HTTP-01 challenge from a tiny listener on port 80 → finalize with a freshly
//! generated key + CSR → write the issued chain and key to [`TlsCfg::cert_path`] /
//! [`TlsCfg::key_path`], which the TLS listener then loads.
//!
//! # Proven working, 2026-08-24 (instant-acme 0.8)
//!
//! `acme_http01_issues_against_pebble` passes against Pebble, a real ACME CA. It is the first
//! time it ever has. It was blocked by four separate things, none of them this module's logic:
//!
//! 1. the test never installed a rustls `CryptoProvider`, so it panicked before any ACME ran;
//! 2. `instant-acme` 0.7.2 (Oct 2024) could not parse the CA's authorization payload —
//!    `missing field \`token\`` — which is what broke issuance in the field;
//! 3. 0.7 verified against compiled-in webpki-roots, so no private test CA could be trusted.
//!    0.8 uses the platform trust store, so installing Pebble's root now works;
//! 4. the test rig itself: the wrong Pebble root, the wrong challtestsrv flag, and AAAA
//!    answers pointing validation at ::1. See `loadtest/pebble.compose.yaml`.
//!
//! NOTE: this path talks to a live ACME CA and binds port 80, so it is not exercised by the
//! *default* suite (no domain, no inbound :80). A `#[ignore]`d end-to-end test
//! (`acme_http01_issues_against_pebble`) is written against **Pebble** (a tiny test ACME CA) —
//! see the test for the setup and `loadtest/pebble.compose.yaml`. It does **not** pass yet, and
//! the reason is not this module: the ACME client trusts a compile-time root list, so a private
//! test CA cannot be added to it. Read the test comment before assuming this path is verified.
//! The default directory is Let's Encrypt **staging** (see `AcmeCfg::directory_url`) precisely so
//! a first run can't burn production rate limits.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    routing::get,
    Router,
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::config::{AcmeCfg, TlsCfg};

/// The TCP port the ACME CA connects to for an HTTP-01 challenge. Fixed by RFC 8555 §8.3.
const HTTP01_PORT: u16 = 80;

/// Obtain (or renew) a certificate for the configured domains and write it to the TLS
/// cert/key paths. Returns once the certificate chain and key are on disk.
pub async fn obtain_certificate(acme: &AcmeCfg, tls: &TlsCfg) -> Result<()> {
    anyhow::ensure!(
        !acme.domains.is_empty(),
        "tls.acme.domains must list at least one domain"
    );
    anyhow::ensure!(
        acme.accept_tos,
        "set tls.acme.accept_tos = true to accept the ACME provider's Terms of Service"
    );
    anyhow::ensure!(
        !tls.cert_path.is_empty() && !tls.key_path.is_empty(),
        "tls.cert_path and tls.key_path must be set so the issued certificate can be stored"
    );

    info!(domains = ?acme.domains, directory = %acme.directory_url, "starting ACME order");

    let account = account(acme).await?;

    let identifiers: Vec<Identifier> = acme
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("creating ACME order")?;

    // The challenge server starts BEFORE the authorizations are walked, sharing a map the loop
    // fills in. In 0.8 a challenge is marked ready through a handle that only exists inside the
    // iteration, so responses cannot all be gathered first and served afterwards. Publishing
    // each response *then* signalling ready also closes a window the old two-pass version had,
    // where the CA could validate a token that was not being served yet.
    let responses: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let _server = AbortOnDrop(spawn_challenge_server(Arc::clone(&responses)).await?);

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.context("fetching authorizations")?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => anyhow::bail!("unexpected authorization status: {other:?}"),
        }
        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .context("CA offered no http-01 challenge")?;
        // `ChallengeHandle` derefs to `Challenge`, so the token is still readable here.
        let token = challenge.token.clone();
        let key_auth = challenge.key_authorization().as_str().to_string();
        responses
            .write()
            .expect("challenge response map poisoned")
            .insert(token, key_auth);
        challenge
            .set_ready()
            .await
            .context("signaling challenge ready")?;
    }

    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .context("waiting for the ACME order to become ready")?;
    anyhow::ensure!(
        status == OrderStatus::Ready,
        "ACME order did not become ready (status: {status:?})"
    );

    // 0.8 generates the key pair and CSR itself and hands back the private key, so there is no
    // rcgen step here any more.
    let key_pem = order.finalize().await.context("finalizing ACME order")?;
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("waiting for the issued certificate")?;

    write_pem(&tls.cert_path, &cert_chain_pem)?;
    write_key_pem(&tls.key_path, &key_pem)?;
    info!(cert = %tls.cert_path, key = %tls.key_path, "ACME certificate stored");
    Ok(())
}

/// Restore the ACME account from cached credentials, or create and cache a new one (so renewals
/// reuse the same account instead of re-registering).
async fn account(acme: &AcmeCfg) -> Result<Account> {
    let creds_path = Path::new(&acme.cache_dir).join("account.json");
    if creds_path.exists() {
        let raw = std::fs::read_to_string(&creds_path)
            .with_context(|| format!("reading cached ACME account {}", creds_path.display()))?;
        let creds: AccountCredentials =
            serde_json::from_str(&raw).context("parsing cached ACME account credentials")?;
        return Account::builder()
            .context("building ACME client")?
            .from_credentials(creds)
            .await
            .context("restoring ACME account from cached credentials");
    }

    let mailto = (!acme.email.is_empty()).then(|| format!("mailto:{}", acme.email));
    let contact: Vec<&str> = mailto.as_deref().into_iter().collect();
    let (account, credentials) = Account::builder()
        .context("building ACME client")?
        .create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: acme.accept_tos,
                only_return_existing: false,
            },
            acme.directory_url.clone(),
            None,
        )
        .await
        .context("creating ACME account")?;

    if let Err(e) = std::fs::create_dir_all(&acme.cache_dir)
        .and_then(|_| serde_json::to_string_pretty(&credentials).map_err(std::io::Error::other))
        .and_then(|json| std::fs::write(&creds_path, json))
    {
        warn!(error = %e, path = %creds_path.display(), "could not cache ACME account credentials");
    }
    Ok(account)
}

/// Start a minimal HTTP-01 responder on `:80` serving `token -> key authorization`.
async fn spawn_challenge_server(
    responses: Arc<RwLock<HashMap<String, String>>>,
) -> Result<tokio::task::JoinHandle<()>> {
    let app = Router::new()
        .route("/.well-known/acme-challenge/:token", get(challenge_handler))
        .with_state(responses);
    let listener = TcpListener::bind(("0.0.0.0", HTTP01_PORT))
        .await
        .with_context(|| format!("binding ACME HTTP-01 listener on :{HTTP01_PORT}"))?;
    Ok(tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            warn!(error = %e, "ACME challenge server stopped");
        }
    }))
}

async fn challenge_handler(
    State(responses): State<Arc<RwLock<HashMap<String, String>>>>,
    AxPath(token): AxPath<String>,
) -> (StatusCode, String) {
    // The map is filled in as each authorization is walked, so this reads under a
    // lock rather than from a snapshot taken before the order started.
    let found = responses.read().ok().and_then(|m| m.get(&token).cloned());
    match found {
        Some(key_auth) => (StatusCode::OK, key_auth),
        None => (StatusCode::NOT_FOUND, String::new()),
    }
}

fn create_parent(path: &str) -> Result<()> {
    if let Some(parent) = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory for {path}"))?;
    }
    Ok(())
}

fn write_pem(path: &str, contents: &str) -> Result<()> {
    create_parent(path)?;
    std::fs::write(path, contents).with_context(|| format!("writing {path}"))
}

/// Write the private key with owner-only permissions (`0600` on Unix) rather than inheriting
/// the process umask, which could otherwise leave the key group/world-readable.
fn write_key_pem(path: &str, contents: &str) -> Result<()> {
    create_parent(path)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {path} (mode 0600)"))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("writing {path}"))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents).with_context(|| format!("writing {path}"))
    }
}

/// Aborts the wrapped task on drop, so the HTTP-01 challenge listener is torn down on *every*
/// exit path from [`obtain_certificate`] — including the early `?` returns during ordering —
/// not just the happy path. Otherwise a failed issuance would leave a stray `:80` listener
/// that blocks the next attempt from binding.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcmeCfg, TlsCfg};
    use std::time::{SystemTime, UNIX_EPOCH};

    // End-to-end HTTP-01 issuance against **Pebble** (a tiny test ACME CA), proving the ◐ roadmap
    // item without touching Let's Encrypt's rate limits. `#[ignore]`d — it needs a running CA, the
    // privilege to bind :80 (the challenge port is fixed by RFC 8555), and a domain that resolves
    // to this host. Recipe:
    //
    //   1. Run Pebble + pebble-challtestsrv (see https://github.com/letsencrypt/pebble; a starting
    //      compose is at loadtest/pebble.compose.yaml). challtestsrv must resolve the test domain
    //      to the host running this test, and Pebble's HTTP-01 validation must reach this host's :80.
    //   2. Trust Pebble's DIRECTORY certificate. Note it is signed by the *minica* root, NOT
    //      by `https://localhost:15000/roots/0` (that one signs the certs Pebble issues):
    //        curl -sL https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/pebble.minica.pem     //          | sudo tee /usr/local/share/ca-certificates/pebble.crt >/dev/null
    //        sudo update-ca-certificates
    //      instant-acme 0.8 verifies against the platform store, so this is enough. Under 0.7
    //      it used compiled-in roots and no amount of trust configuration could work.
    //   3. Run it:
    //        EDGEGUARD_TEST_ACME_DIR=https://localhost:14000/dir \
    //        EDGEGUARD_TEST_ACME_DOMAIN=edgeguard.test \
    //        sudo -E cargo test -p eggrd --lib acme_http01 -- --ignored
    //      (`sudo`/CAP_NET_BIND_SERVICE so the challenge server can bind :80.)
    #[tokio::test]
    #[ignore = "requires a live test ACME CA (Pebble) + :80 — see the module test comment"]
    async fn acme_http01_issues_against_pebble() {
        let Ok(directory_url) = std::env::var("EDGEGUARD_TEST_ACME_DIR") else {
            eprintln!("skipping acme_http01_issues_against_pebble: set EDGEGUARD_TEST_ACME_DIR");
            return;
        };
        let domain =
            std::env::var("EDGEGUARD_TEST_ACME_DOMAIN").unwrap_or_else(|_| "edgeguard.test".into());

        // `main` installs the process-wide rustls provider before it reaches the ACME block
        // (main.rs: `tls::init_crypto()` immediately precedes it), so the shipping path is
        // fine. This test calls `obtain_certificate` directly and so has to do the same, or
        // rustls panics on the first HTTPS request to the directory — before any ACME logic
        // runs at all. Without this line the test cannot pass, which is why it had never
        // reported anything despite being written.
        crate::tls::init_crypto();

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("eg-acme-{stamp}"));
        std::fs::create_dir_all(&base).unwrap();
        let cert_path = base.join("cert.pem").to_string_lossy().into_owned();
        let key_path = base.join("key.pem").to_string_lossy().into_owned();

        let acme = AcmeCfg {
            enabled: true,
            domains: vec![domain],
            email: "ci@example.test".into(),
            directory_url,
            cache_dir: base.to_string_lossy().into_owned(),
            accept_tos: true,
        };
        let tls = TlsCfg {
            enabled: true,
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            acme: acme.clone(),
        };

        obtain_certificate(&acme, &tls)
            .await
            .expect("ACME HTTP-01 issuance against Pebble");

        let cert = std::fs::read_to_string(&cert_path).expect("issued certificate written");
        assert!(
            cert.contains("BEGIN CERTIFICATE"),
            "issued PEM chain present"
        );
        let key = std::fs::read_to_string(&key_path).expect("private key written");
        assert!(key.contains("BEGIN"), "private key PEM present");
        let _ = std::fs::remove_dir_all(&base);
    }
}
