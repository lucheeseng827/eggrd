//! ACME (Let's Encrypt) automatic certificates via the HTTP-01 challenge, using
//! `instant-acme` for the protocol and `rcgen` for the CSR.
//!
//! Flow: create/restore an ACME account → open an order for the configured domains → answer
//! each domain's HTTP-01 challenge from a tiny listener on port 80 → finalize with a freshly
//! generated key + CSR → write the issued chain and key to [`TlsCfg::cert_path`] /
//! [`TlsCfg::key_path`], which the TLS listener then loads.
//!
//! NOTE: this path talks to a live ACME CA and binds port 80, so it cannot be exercised by
//! the in-process test suite (no domain, no inbound :80). It is written against the real
//! `instant-acme` 0.7 API and compiled in CI, but proven only against a real CA. The default
//! directory is Let's Encrypt **staging** (see `AcmeCfg::directory_url`) precisely so a first
//! run can't burn production rate limits.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    routing::get,
    Router,
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
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
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .context("creating ACME order")?;

    // Collect each authorization's HTTP-01 response into a token -> key-authorization map and
    // the challenge URLs to mark ready.
    let authorizations = order
        .authorizations()
        .await
        .context("fetching authorizations")?;
    let mut responses: HashMap<String, String> = HashMap::new();
    let mut challenge_urls: Vec<String> = Vec::new();
    for authz in &authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => anyhow::bail!("unexpected authorization status: {other:?}"),
        }
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .context("CA offered no http-01 challenge")?;
        let key_auth = order.key_authorization(challenge);
        responses.insert(challenge.token.clone(), key_auth.as_str().to_string());
        challenge_urls.push(challenge.url.clone());
    }

    // Serve the challenge responses on :80 while the CA validates. The guard aborts the
    // listener when it drops, so every error path below also tears it down.
    let _server = AbortOnDrop(spawn_challenge_server(responses).await?);

    for url in &challenge_urls {
        order
            .set_challenge_ready(url)
            .await
            .context("signaling challenge ready")?;
    }

    poll_until_ready(&mut order).await?;

    // Generate a fresh key + CSR for the domains and finalize.
    let mut params =
        CertificateParams::new(acme.domains.clone()).context("building certificate params")?;
    params.distinguished_name = DistinguishedName::new();
    let key_pair = KeyPair::generate().context("generating certificate key pair")?;
    let csr = params
        .serialize_request(&key_pair)
        .context("serializing CSR")?;
    order
        .finalize(csr.der())
        .await
        .context("finalizing ACME order")?;

    let cert_chain_pem = poll_for_certificate(&mut order).await?;

    write_pem(&tls.cert_path, &cert_chain_pem)?;
    write_key_pem(&tls.key_path, &key_pair.serialize_pem())?;
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
        return Account::from_credentials(creds)
            .await
            .context("restoring ACME account from cached credentials");
    }

    let mailto = (!acme.email.is_empty()).then(|| format!("mailto:{}", acme.email));
    let contact: Vec<&str> = mailto.as_deref().into_iter().collect();
    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &contact,
            terms_of_service_agreed: acme.accept_tos,
            only_return_existing: false,
        },
        &acme.directory_url,
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
    responses: HashMap<String, String>,
) -> Result<tokio::task::JoinHandle<()>> {
    let app = Router::new()
        .route("/.well-known/acme-challenge/:token", get(challenge_handler))
        .with_state(Arc::new(responses));
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
    State(responses): State<Arc<HashMap<String, String>>>,
    AxPath(token): AxPath<String>,
) -> (StatusCode, String) {
    match responses.get(&token) {
        Some(key_auth) => (StatusCode::OK, key_auth.clone()),
        None => (StatusCode::NOT_FOUND, String::new()),
    }
}

/// Poll the order until it leaves `Pending`/`Processing`, erroring if it goes `Invalid`.
async fn poll_until_ready(order: &mut instant_acme::Order) -> Result<()> {
    let mut delay = Duration::from_millis(250);
    for _ in 0..10 {
        tokio::time::sleep(delay).await;
        let state = order.refresh().await.context("refreshing order")?;
        match state.status {
            OrderStatus::Ready => return Ok(()),
            OrderStatus::Invalid => anyhow::bail!("ACME order became invalid"),
            _ => delay = (delay * 2).min(Duration::from_secs(5)),
        }
    }
    anyhow::bail!("ACME order not ready after polling")
}

/// Poll for the issued certificate chain after finalize.
async fn poll_for_certificate(order: &mut instant_acme::Order) -> Result<String> {
    for _ in 0..10 {
        if let Some(pem) = order.certificate().await.context("fetching certificate")? {
            return Ok(pem);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::bail!("certificate not issued after polling")
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
