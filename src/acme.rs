//! ACME (Let's Encrypt) automatic certificates via the HTTP-01 challenge, using
//! `instant-acme` for the protocol; it generates the key and CSR in `finalize()`.
//!
//! Flow: create/restore an ACME account → open an order for the configured domains → answer
//! each domain's HTTP-01 challenge from a tiny listener on port 80 → finalize with a freshly
//! generated key + CSR → write the issued chain and key to [`TlsCfg::cert_path`] /
//! [`TlsCfg::key_path`], which the TLS listener then loads.
//!
//! # Proven working, 2026-08-23 (instant-acme 0.8)
//!
//! `acme_http01_issues_against_pebble` passes against Pebble, a real ACME CA. It is the first
//! time it ever has. It was blocked by four separate things, none of them this module's logic:
//!
//! 1. the test never installed a rustls `CryptoProvider`, so it panicked before any ACME ran;
//! 2. `instant-acme` 0.7.2 (Oct 2024) could not parse the CA's authorization payload —
//!    `` `missing field `token` `` `` — which is what broke issuance in the field;
//! 3. 0.7 verified against compiled-in webpki-roots, so no private test CA could be trusted.
//!    0.8 uses the platform trust store, so installing Pebble's root now works;
//! 4. the test rig itself: the wrong Pebble root, the wrong challtestsrv flag, and AAAA
//!    answers pointing validation at ::1. See `loadtest/pebble.compose.yaml`.
//!
//! NOTE: this path talks to a live ACME CA and binds port 80, so it is not exercised by the
//! *default* suite (no domain, no inbound :80). A `#[ignore]`d end-to-end test
//! (`acme_http01_issues_against_pebble`) is written against **Pebble** (a tiny test ACME CA) —
//! see the test for the setup and `loadtest/pebble.compose.yaml`. It **passes** against Pebble
//! (0.8 verifies with the platform trust store, so a private test CA can now be installed — see
//! the four blockers above and `docs/ACME_TESTING.md`); it stays `#[ignore]`d only because it
//! needs a live CA and inbound port 80, which the default suite has neither of.
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

/// Which set of books refused an order. The remedies are different, so the distinction is worth
/// carrying all the way to the operator's log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferSource {
    /// The **fleet's** shared budget, held by the control plane. Some other edge under the same
    /// registered domain spent the allowance; nothing about this box will change that, and waiting
    /// (or reducing how often the fleet re-orders) is the only remedy.
    Fleet,
    /// This edge's **own** ledger. Usually a certificate cache that is not durable, so every
    /// restart re-orders — fixable here, by making the ACME cache directory survive a restart.
    Local,
}

impl DeferSource {
    pub fn label(&self) -> &'static str {
        match self {
            DeferSource::Fleet => "fleet",
            DeferSource::Local => "local",
        }
    }
}

/// The outcome of an issuance attempt.
#[derive(Debug)]
pub enum Issuance {
    /// A certificate and key are on disk.
    Issued,
    /// The CA's rate limit for `bucket` is spent, so the order was not sent. `retry_at_unix` is when
    /// that bucket next admits.
    ///
    /// Deliberately not an `Err`: the caller must be able to tell "we chose not to ask" from "the
    /// order failed", because the correct response differs. A failure propagates; a deferral keeps
    /// serving whatever certificate is already on disk.
    Deferred {
        /// The CA limit that refused: `orders` | `registered_domain` | `identifier_set`. A string
        /// rather than the local enum because the refusal may have come from the control plane,
        /// whose bucket set is its own — and an edge must not fail to report a deferral because it
        /// did not recognise a word.
        bucket: String,
        /// The bucket key, when the refusal names one (the control plane always does). Says *which*
        /// registered domain or identifier set is exhausted, which is the difference between an
        /// actionable log line and a shrug.
        key: String,
        retry_at_unix: i64,
        source: DeferSource,
    },
}

/// Decide whether to send this order, against the fleet's books first and this edge's own second.
///
/// # Two tiers, and why both
///
/// The local ledger (`acme_budget`) covers what one edge can see: the per-identifier-set limit, the
/// one a restart loop burns. It **cannot** cover the CA's per-registered-domain limit, which is
/// shared — fifty edges under `example.com` each hold a private ledger, each correctly believe they
/// have the full allowance, and between them they spend it. Only something all of them talk to can
/// count that, which is the control plane.
///
/// So in managed mode the control plane decides, and holds the fleet's books. Unmanaged, or when
/// the control plane cannot answer, the local ledger decides.
///
/// # A control plane that is down must not stop certificate issuance
///
/// Any failure reaching the control plane — unreachable, timing out, 5xx, a control plane too old
/// to have the endpoint — falls through to the local budget. That degrades fleet-wide coordination
/// to per-edge coordination, which is exactly where things stood before leases existed. Failing
/// closed instead would turn a control-plane outage into fleet-wide certificate expiry, a far worse
/// failure than the one being guarded against.
///
/// # Only one set of books is debited
///
/// A granted lease means the fleet already debited its buckets, so the local ledger is deliberately
/// **not** also debited: doing both would count one order twice and exhaust the local guard at a
/// fifth of the real rate. The local ledger is the fallback authority, not a second toll booth.
///
/// `Err(Issuance::Deferred)` is the refusal path — the caller returns it unchanged. `Ok` carries the
/// local ledger to debit (when it is the deciding authority) and the granted lease id (when the
/// fleet is).
type BudgetCheck = (Option<crate::acme_budget::IssuanceBudget>, Option<String>);

async fn check_budget(
    acme: &AcmeCfg,
    cp: Option<&crate::cp::CpClient>,
) -> std::result::Result<BudgetCheck, Issuance> {
    use crate::cp::LeaseVerdict;

    // NOTE the ordering: the fleet lease is taken BEFORE `budget_enabled` is consulted.
    //
    // `budget_enabled` is a per-edge switch over a per-edge ledger, and the fleet's books are not
    // this edge's to opt out of. One edge setting it false could otherwise spend the shared
    // registered-domain allowance and leave every other edge under that domain unable to renew —
    // which is precisely the failure this whole mechanism exists to prevent, re-introduced through
    // a config flag. So the flag disables the LOCAL ledger below; it does not buy an exemption from
    // a limit the CA applies to everyone.
    if let Some(client) = cp {
        match client.acme_lease(&acme.directory_url, &acme.domains).await {
            Ok(LeaseVerdict::Granted { lease_id }) => {
                info!(
                    lease_id,
                    domains = ?acme.domains,
                    "ACME issuance leased from the control plane (fleet-wide budget)"
                );
                return Ok((None, Some(lease_id)));
            }
            Ok(LeaseVerdict::Deferred {
                bucket,
                key,
                retry_at_unix,
            }) => {
                warn!(
                    source = DeferSource::Fleet.label(),
                    bucket = %bucket,
                    key = %key,
                    retry_at_unix,
                    domains = ?acme.domains,
                    "ACME issuance deferred: the FLEET's budget for this CA limit is exhausted — \
                     another edge under the same key has spent it. The existing certificate (if \
                     any) keeps serving; no self-signed certificate is substituted on a public \
                     name."
                );
                return Err(Issuance::Deferred {
                    bucket,
                    key,
                    retry_at_unix,
                    source: DeferSource::Fleet,
                });
            }
            // The control plane keeps no books for this CA, so there is nothing fleet-wide to
            // apply and the local ledger below is the only guard there is.
            Ok(LeaseVerdict::Unmanaged) => {}
            Err(e) => {
                // Logged at warn, not error: issuance still proceeds under the local budget. It is
                // worth seeing because while this is happening the fleet-wide limit is unguarded.
                warn!(
                    error = %e,
                    "could not obtain a fleet ACME lease; falling back to this edge's local budget. \
                     The CA's per-registered-domain limit is uncoordinated until the control plane \
                     is reachable again."
                );
            }
        }
    }

    // Past here is the local ledger, and this is what `budget_enabled = false` actually turns off.
    if !acme.budget_enabled {
        return Ok((None, None));
    }

    let mut budget = crate::acme_budget::IssuanceBudget::load(&acme.directory_url, &acme.cache_dir);
    if let Some(b) = &budget {
        let now = crate::acme_budget::now_unix();
        if let crate::acme_budget::Decision::Defer {
            bucket,
            retry_at_unix,
        } = b.check(&acme.domains, now)
        {
            crate::acme_budget::warn_deferred(bucket, retry_at_unix, &acme.domains);
            return Err(Issuance::Deferred {
                bucket: bucket.label().to_string(),
                key: String::new(),
                retry_at_unix,
                source: DeferSource::Local,
            });
        }
    }
    // Debit BEFORE the order is sent, and never refund. An order that reaches the CA may have been
    // counted by it even when the response never arrives, so debiting on success would let a
    // failing loop spend the real allowance while the local ledger showed it untouched — the exact
    // situation the budget exists to prevent.
    if let Some(b) = &mut budget {
        if let Err(e) = b.debit(&acme.domains, crate::acme_budget::now_unix()) {
            // A ledger we cannot persist is a budget that resets on restart, which is no budget.
            // Loud, and not fatal: refusing to serve because a bookkeeping file is unwritable would
            // be a worse outage than the one being guarded against.
            warn!(error = %e, "could not persist the ACME issuance ledger; the budget will not survive a restart");
        }
    }
    Ok((budget, None))
}

/// Obtain (or renew) a certificate for the configured domains and write it to the TLS
/// cert/key paths. Returns once the certificate chain and key are on disk.
///
/// `cp` is the managed-mode control-plane client, when the edge has one. Its presence changes which
/// books decide: see [`check_budget`].
pub async fn obtain_certificate(
    acme: &AcmeCfg,
    tls: &TlsCfg,
    cp: Option<&crate::cp::CpClient>,
) -> Result<Issuance> {
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

    // Ask the budget before asking the CA. A CA that refuses an order still counts it, so the only
    // place this check is worth anything is before the request leaves.
    let (budget, lease) = match check_budget(acme, cp).await {
        Ok(ok) => ok,
        Err(deferred) => return Ok(deferred),
    };

    let result = run_order(acme, tls, budget.as_ref()).await;

    // Tell the control plane how the leased order ended, on EVERY path out of `run_order`.
    //
    // It settles nothing about the budget — the lease was debited at grant and is never refunded —
    // but it is what turns an exhausted bucket from a bare number into "these forty orders were
    // granted and only thirty-one produced a certificate", which is how an operator sees an edge
    // burning fleet budget on orders that keep failing. An unreported lease is closed as consumed
    // by the control plane once it expires, so a lost report costs observability, not correctness.
    if let (Some(client), Some(lease_id)) = (cp, lease.as_deref()) {
        let outcome = if result.is_ok() { "issued" } else { "failed" };
        client.acme_lease_outcome(lease_id, outcome).await;
    }
    result?;

    Ok(Issuance::Issued)
}

/// The ACME order itself: account, authorizations, challenges, finalize, and writing the pair to
/// disk. Split out of [`obtain_certificate`] purely so that every failure path is a single `?` the
/// caller can observe — the lease outcome has to be reported whether this succeeds or not, and a
/// dozen inline `?`s would each have needed their own reporting.
async fn run_order(
    acme: &AcmeCfg,
    tls: &TlsCfg,
    budget: Option<&crate::acme_budget::IssuanceBudget>,
) -> Result<()> {
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
    if let Some(b) = budget {
        for (bucket, key, left) in b.remaining(&acme.domains, crate::acme_budget::now_unix()) {
            info!(
                ca = b.ca_name(),
                bucket = bucket.label(),
                key = %key,
                remaining = left,
                "ACME issuance budget after this order"
            );
        }
    }
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
            // `..default()` so a new AcmeCfg field does not break this test literal. The budget is
            // on (its default) and inert here on purpose: Pebble's directory URL is not a
            // recognised CA, so `CaProfile::for_directory` returns None and no bucket is charged.
            // That is what stops this test failing on its sixth run against a rate limit Pebble
            // does not have.
            ..AcmeCfg::default()
        };
        let tls = TlsCfg {
            enabled: true,
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            acme: acme.clone(),
            ..TlsCfg::default()
        };

        // `None`: this test drives an unmanaged edge, so the local budget is the only authority.
        obtain_certificate(&acme, &tls, None)
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
