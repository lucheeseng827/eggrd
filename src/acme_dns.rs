//! DNS-01 record publishing for ACME (`tls.acme.challenge = "dns-01"`).
//!
//! The CA proves control of a name by looking up a TXT record at `_acme-challenge.<name>`. This
//! module puts that record in the zone before the challenge is answered and takes it out again
//! afterwards, through a provider's API. It is the only way to get a wildcard certificate, and the
//! way to certify hosts the CA cannot reach on :80.
//!
//! Providers:
//! * **Cloudflare** — `POST`/`DELETE /zones/{zone_id}/dns_records` with a scoped API token
//!   (`Zone.DNS:Edit` on that one zone). The token is read from an environment variable, never
//!   from the config file, and never appears in a log line or an error.
//! * **challtestsrv** — Pebble's test DNS server, so DNS-01 issuance is proven in CI against a real
//!   (test) CA. Not for production.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::config::AcmeDnsCfg;

/// The name the CA looks up for `domain`: `_acme-challenge.<domain>`. A wildcard is validated at its
/// base name (`*.example.com` → `_acme-challenge.example.com`), as RFC 8555 §8.4 specifies.
pub fn challenge_record_name(domain: &str) -> String {
    let base = domain.trim().trim_end_matches('.');
    let base = base.strip_prefix("*.").unwrap_or(base);
    format!("_acme-challenge.{}", base.to_ascii_lowercase())
}

/// A provider that can publish and remove TXT records.
pub enum DnsProvider {
    Cloudflare {
        http: reqwest::Client,
        base: String,
        zone_id: String,
        token: String,
    },
    ChallTestSrv {
        http: reqwest::Client,
        url: String,
    },
}

// Hand-written so the API token can never reach a log through `{:?}`.
impl std::fmt::Debug for DnsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsProvider::Cloudflare { base, zone_id, .. } => f
                .debug_struct("Cloudflare")
                .field("base", base)
                .field("zone_id", zone_id)
                .field("token", &"<redacted>")
                .finish(),
            DnsProvider::ChallTestSrv { url, .. } => {
                f.debug_struct("ChallTestSrv").field("url", url).finish()
            }
        }
    }
}

/// A record this order published, so it can be removed afterwards.
#[derive(Debug, Clone)]
pub struct TxtRecord {
    pub name: String,
    /// The provider's record id, where removal needs one (Cloudflare).
    pub id: Option<String>,
}

#[derive(Deserialize)]
struct CfResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: Option<CfRecord>,
}

#[derive(Deserialize)]
struct CfError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct CfRecord {
    id: String,
}

fn cf_errors(errors: &[CfError]) -> String {
    errors
        .iter()
        .map(|e| format!("{} ({})", e.message, e.code))
        .collect::<Vec<_>>()
        .join("; ")
}

impl DnsProvider {
    /// Build the provider `cfg` names. Fails, naming what is missing, when it cannot work: no
    /// provider, no zone, or the token's environment variable unset.
    pub fn from_cfg(cfg: &AcmeDnsCfg) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("building the DNS provider's HTTP client")?;
        match cfg.provider.as_str() {
            "cloudflare" => {
                anyhow::ensure!(
                    !cfg.zone_id.trim().is_empty(),
                    "tls.acme.dns.zone_id is required for the cloudflare provider"
                );
                let token = std::env::var(&cfg.api_token_env)
                    .ok()
                    .filter(|t| !t.trim().is_empty())
                    .with_context(|| {
                        format!(
                            "the cloudflare DNS provider needs an API token in ${} (Zone.DNS:Edit on the zone)",
                            cfg.api_token_env
                        )
                    })?;
                Ok(DnsProvider::Cloudflare {
                    http,
                    base: cfg.api_base.trim_end_matches('/').to_string(),
                    zone_id: cfg.zone_id.trim().to_string(),
                    token,
                })
            }
            "challtestsrv" => {
                anyhow::ensure!(
                    !cfg.url.trim().is_empty(),
                    "tls.acme.dns.url is required for the challtestsrv provider"
                );
                Ok(DnsProvider::ChallTestSrv {
                    http,
                    url: cfg.url.trim_end_matches('/').to_string(),
                })
            }
            "" => bail!("tls.acme.challenge = \"dns-01\" needs tls.acme.dns.provider"),
            other => bail!(
                "unknown tls.acme.dns.provider {other:?} (expected \"cloudflare\" or \"challtestsrv\")"
            ),
        }
    }

    /// Publish `value` as a TXT record at `name`.
    pub async fn publish(&self, name: &str, value: &str) -> Result<TxtRecord> {
        match self {
            DnsProvider::Cloudflare {
                http,
                base,
                zone_id,
                token,
            } => {
                let resp: CfResponse = http
                    .post(format!("{base}/zones/{zone_id}/dns_records"))
                    .bearer_auth(token)
                    .json(&serde_json::json!({
                        "type": "TXT",
                        "name": name,
                        "content": value,
                        "ttl": 60,
                    }))
                    .send()
                    .await
                    .context("calling the Cloudflare API")?
                    .json()
                    .await
                    .context("reading the Cloudflare API response")?;
                if !resp.success {
                    bail!(
                        "Cloudflare refused the TXT record for {name}: {}",
                        cf_errors(&resp.errors)
                    );
                }
                let id = resp.result.context("Cloudflare returned no record id")?.id;
                Ok(TxtRecord {
                    name: name.to_string(),
                    id: Some(id),
                })
            }
            DnsProvider::ChallTestSrv { http, url } => {
                http.post(format!("{url}/set-txt"))
                    .json(&serde_json::json!({ "host": format!("{name}."), "value": value }))
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .context("setting the TXT record on challtestsrv")?;
                Ok(TxtRecord {
                    name: name.to_string(),
                    id: None,
                })
            }
        }
    }

    /// Remove a record [`publish`](Self::publish) created.
    pub async fn remove(&self, record: &TxtRecord) -> Result<()> {
        match self {
            DnsProvider::Cloudflare {
                http,
                base,
                zone_id,
                token,
            } => {
                let id = record.id.as_deref().context("no record id to delete")?;
                let resp: CfResponse = http
                    .delete(format!("{base}/zones/{zone_id}/dns_records/{id}"))
                    .bearer_auth(token)
                    .send()
                    .await
                    .context("calling the Cloudflare API")?
                    .json()
                    .await
                    .context("reading the Cloudflare API response")?;
                if !resp.success {
                    bail!(
                        "Cloudflare did not delete the TXT record for {}: {}",
                        record.name,
                        cf_errors(&resp.errors)
                    );
                }
                Ok(())
            }
            DnsProvider::ChallTestSrv { http, url } => {
                http.post(format!("{url}/clear-txt"))
                    .json(&serde_json::json!({ "host": format!("{}.", record.name) }))
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .context("clearing the TXT record on challtestsrv")?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::{
        body::Bytes,
        extract::State,
        http::{HeaderMap, Method, Uri},
        routing::any,
        Json, Router,
    };

    /// Every request a stub received: (method, path, authorization header, JSON body).
    type Seen = Arc<Mutex<Vec<(String, String, String, serde_json::Value)>>>;

    async fn stub(reply: serde_json::Value) -> (SocketAddr, Seen) {
        let seen: Seen = Arc::default();
        let app = Router::new()
            .fallback(any(
                |State((seen, reply)): State<(Seen, serde_json::Value)>,
                 method: Method,
                 uri: Uri,
                 headers: HeaderMap,
                 body: Bytes| async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                    seen.lock().unwrap().push((
                        method.to_string(),
                        uri.path().to_string(),
                        auth,
                        json,
                    ));
                    Json(reply)
                },
            ))
            .with_state((Arc::clone(&seen), reply));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, seen)
    }

    fn cloudflare(addr: SocketAddr, env: &str) -> AcmeDnsCfg {
        AcmeDnsCfg {
            provider: "cloudflare".into(),
            zone_id: "zone123".into(),
            api_token_env: env.into(),
            api_base: format!("http://{addr}/client/v4"),
            ..AcmeDnsCfg::default()
        }
    }

    #[test]
    fn the_record_name_is_the_base_name_for_a_wildcard() {
        assert_eq!(
            challenge_record_name("Shop.Example.com."),
            "_acme-challenge.shop.example.com"
        );
        assert_eq!(
            challenge_record_name("*.example.com"),
            "_acme-challenge.example.com"
        );
    }

    #[tokio::test]
    async fn cloudflare_creates_then_deletes_the_record_with_the_token() {
        let (addr, seen) = stub(serde_json::json!({
            "success": true, "errors": [], "result": { "id": "rec-1" }
        }))
        .await;
        std::env::set_var("EG_TEST_CF_TOKEN_OK", "s3cret-token");
        let p = DnsProvider::from_cfg(&cloudflare(addr, "EG_TEST_CF_TOKEN_OK")).unwrap();
        assert!(
            !format!("{p:?}").contains("s3cret"),
            "token must not reach Debug"
        );

        let rec = p
            .publish("_acme-challenge.example.com", "abc123")
            .await
            .unwrap();
        assert_eq!(rec.id.as_deref(), Some("rec-1"));
        p.remove(&rec).await.unwrap();

        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        let (m, path, auth, body) = &seen[0];
        assert_eq!(m, "POST");
        assert_eq!(path, "/client/v4/zones/zone123/dns_records");
        assert_eq!(auth, "Bearer s3cret-token");
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["name"], "_acme-challenge.example.com");
        assert_eq!(body["content"], "abc123");
        let (m, path, auth, _) = &seen[1];
        assert_eq!(m, "DELETE");
        assert_eq!(path, "/client/v4/zones/zone123/dns_records/rec-1");
        assert_eq!(auth, "Bearer s3cret-token");
    }

    #[tokio::test]
    async fn a_cloudflare_refusal_is_an_error_that_does_not_carry_the_token() {
        let (addr, _) = stub(serde_json::json!({
            "success": false, "errors": [{ "code": 9109, "message": "Invalid access token" }]
        }))
        .await;
        std::env::set_var("EG_TEST_CF_TOKEN_BAD", "do-not-leak-me");
        let p = DnsProvider::from_cfg(&cloudflare(addr, "EG_TEST_CF_TOKEN_BAD")).unwrap();
        let err = format!(
            "{:#}",
            p.publish("_acme-challenge.x.com", "v").await.unwrap_err()
        );
        assert!(err.contains("Invalid access token (9109)"), "{err}");
        assert!(!err.contains("do-not-leak-me"), "{err}");
    }

    #[test]
    fn missing_configuration_is_named_not_guessed() {
        let mut cfg = AcmeDnsCfg {
            provider: "cloudflare".into(),
            zone_id: "z".into(),
            api_token_env: "EG_TEST_CF_TOKEN_UNSET_NEVER".into(),
            ..AcmeDnsCfg::default()
        };
        let err = format!("{:#}", DnsProvider::from_cfg(&cfg).unwrap_err());
        assert!(err.contains("$EG_TEST_CF_TOKEN_UNSET_NEVER"), "{err}");
        cfg.zone_id.clear();
        assert!(format!("{:#}", DnsProvider::from_cfg(&cfg).unwrap_err()).contains("zone_id"));
        cfg.provider = "route53".into();
        assert!(format!("{:#}", DnsProvider::from_cfg(&cfg).unwrap_err()).contains("route53"));
        cfg.provider.clear();
        assert!(format!("{:#}", DnsProvider::from_cfg(&cfg).unwrap_err()).contains("provider"));
    }

    #[tokio::test]
    async fn challtestsrv_sets_and_clears_the_fully_qualified_name() {
        let (addr, seen) = stub(serde_json::json!({})).await;
        let p = DnsProvider::from_cfg(&AcmeDnsCfg {
            provider: "challtestsrv".into(),
            url: format!("http://{addr}"),
            ..AcmeDnsCfg::default()
        })
        .unwrap();
        let rec = p
            .publish("_acme-challenge.edgeguard.test", "v1")
            .await
            .unwrap();
        p.remove(&rec).await.unwrap();
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[0].1, "/set-txt");
        assert_eq!(seen[0].3["host"], "_acme-challenge.edgeguard.test.");
        assert_eq!(seen[0].3["value"], "v1");
        assert_eq!(seen[1].1, "/clear-txt");
        assert_eq!(seen[1].3["host"], "_acme-challenge.edgeguard.test.");
    }
}
