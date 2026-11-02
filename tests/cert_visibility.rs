//! Visibility of the certificates the edge depends on besides the one it serves: the client
//! certificates it presents, and the CAs and CRLs it checks client certificates against. They
//! join the certificate series (so the existing expiry alert covers them), `GET /__edgeguard/tls`,
//! and `doctor`.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;

mod common;
use common::{Ca, Dir};

use edgeguard::certstore::{CertInfo, CrlInfo};
use edgeguard::config::Config;
use edgeguard::doctor::Level;
use edgeguard::{build_router, build_state};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn tls_status(state: edgeguard::proxy::AppState) -> (u16, serde_json::Value) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let app = build_router(state);
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let resp = reqwest::get(format!("http://{addr}/__edgeguard/tls"))
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or_default())
}

fn base() -> Config {
    let mut cfg = Config::default();
    cfg.auth.mode = "none".into();
    cfg
}

#[tokio::test]
async fn an_upstream_client_certificate_joins_the_expiry_series_and_the_tls_endpoint() {
    let dir = Dir::new();
    let ca = Ca::new("client CA");
    let leaf = ca.client_expiring("edge.example", 10);
    let (cert, key) = dir.pair("edge", &leaf);
    let mut cfg = base();
    cfg.upstream_tls.cert_path = cert.clone();
    cfg.upstream_tls.key_path = key;
    let state = build_state(Arc::new(cfg)).unwrap();

    // Process-wide certificates are only reported by the registry that opts in, as `main`'s does.
    assert!(!state.metrics.render().contains(&format!("client:{cert}")));
    state.metrics.report_client_certs();
    let text = state.metrics.render();
    let not_after = CertInfo::from_der(&leaf.der).unwrap().not_after;
    let series = format!("cert=\"client:{cert}\"");
    assert!(
        text.contains(&format!(
            "edgeguard_tls_cert_not_after_seconds{{source=\"file\",{series}}} {not_after}\n"
        )),
        "{text}"
    );
    assert!(text.contains(&format!(
        "edgeguard_tls_cert_reloads_total{{outcome=\"rejected\",{series}}} 0\n"
    )));
    // This edge serves no TLS: no listener series, and no renewal counters for anything.
    assert!(!text.contains("edgeguard_tls_cert_not_after_seconds{source=\"file\"} "));
    assert!(!text.contains("edgeguard_tls_cert_renewals_total"));

    let (status, j) = tls_status(state).await;
    assert_eq!(status, 200, "a client certificate is something to report");
    assert!(j.get("serial").is_none(), "no served certificate: {j}");
    let mine = j["client_certs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["cert_path"] == cert.as_str())
        .unwrap_or_else(|| panic!("{j}"));
    assert_eq!(mine["used_by"], serde_json::json!(["upstream"]));
    assert!(
        (9..=10).contains(&mine["days_left"].as_i64().unwrap()),
        "{mine}"
    );
    assert_eq!(mine["not_after"], not_after);
}

#[tokio::test]
async fn a_client_certificate_nothing_presents_any_more_is_not_reported() {
    let dir = Dir::new();
    let ca = Ca::new("client CA");
    let (cert, key) = dir.pair("old", &ca.client_expiring("old.example", 5));
    let in_use = |path: &str| {
        edgeguard::outbound::in_use()
            .iter()
            .any(|u| u.store.cert_path() == path)
    };
    let mut cfg = base();
    cfg.upstream_tls.cert_path = cert.clone();
    cfg.upstream_tls.key_path = key;
    let state = build_state(Arc::new(cfg)).unwrap();
    assert!(in_use(&cert));
    // A reload, or a restart, that no longer names the pair: its expiry must not page anyone.
    drop(state);
    assert!(!in_use(&cert));
}

#[tokio::test]
async fn the_client_auth_cas_and_crls_join_the_series_and_the_endpoint() {
    edgeguard::tls::init_crypto();
    let dir = Dir::new();
    let client_ca = Ca::expiring("partner CA", 40);
    let crl_path = dir.write("partners.crl", &client_ca.crl(&[]));
    let mut cfg = base();
    cfg.tls.enabled = true;
    cfg.tls.client_auth.mode = "required".into();
    cfg.tls.client_auth.ca_path = dir.write("partner-ca.pem", &client_ca.pem);
    cfg.tls.client_auth.crl_paths = vec![crl_path.clone()];
    let auth = edgeguard::client_auth::ClientAuth::from_cfg(&cfg.tls)
        .unwrap()
        .unwrap();
    let state = build_state(Arc::new(base())).unwrap();
    assert!(state.metrics.set_client_auth(Arc::clone(&auth)));

    let text = state.metrics.render();
    let ca_line = text
        .lines()
        .find(|l| {
            l.starts_with("edgeguard_tls_cert_not_after_seconds{source=\"file\",cert=\"client-ca:partner CA\"}")
        })
        .unwrap_or_else(|| panic!("{text}"));
    let ca_not_after: i64 = ca_line.rsplit_once(' ').unwrap().1.parse().unwrap();
    assert!(
        (ca_not_after - now() - 40 * 86_400).abs() < 120,
        "{ca_line}"
    );
    let crl_line = text
        .lines()
        .find(|l| l.starts_with("edgeguard_tls_crl_next_update_seconds{"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(
        crl_line.contains(&format!("crl=\"{crl_path}\"")),
        "{crl_line}"
    );
    let next: i64 = crl_line.rsplit_once(' ').unwrap().1.parse().unwrap();
    assert!((next - now() - 86_400).abs() < 120, "{crl_line}");

    // The CA publishes a CRL that is already overdue; the reload picks it up, and says so.
    std::fs::write(
        &crl_path,
        client_ca.crl_next_update(&[], time::Duration::hours(-2)),
    )
    .unwrap();
    assert!(auth.reload().unwrap());
    let (status, j) = tls_status(state).await;
    assert_eq!(status, 200);
    let ca = &j["client_auth"]["cas"][0];
    assert_eq!(ca["name"], "partner CA");
    assert!(
        (39..=40).contains(&ca["days_left"].as_i64().unwrap()),
        "{j}"
    );
    let crl = &j["client_auth"]["crls"][0];
    assert_eq!(crl["name"], crl_path.as_str());
    assert_eq!(crl["stale"], true, "{j}");
    assert!(crl["next_update"].as_i64().unwrap() < now());
    assert_eq!(j["client_auth"]["mode"], "required");
}

#[test]
fn a_crl_reads_its_validity() {
    let ca = Ca::new("any CA");
    let der = |pem: String| {
        rustls_pemfile::crls(&mut pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
    };
    let fresh = CrlInfo::from_der(&der(ca.crl(&[7, 9]))).unwrap();
    assert!((fresh.next_update.unwrap() - now() - 86_400).abs() < 120);
    assert!(fresh.this_update <= now() && !fresh.stale(now()));
    let overdue =
        CrlInfo::from_der(&der(ca.crl_next_update(&[], time::Duration::days(-1)))).unwrap();
    assert!(overdue.stale(now()));
    assert!(overdue.this_update < overdue.next_update.unwrap());
    assert!(CrlInfo::from_der(b"not a crl").is_err());
}

#[test]
fn doctor_lints_expiring_client_certificates_cas_and_stale_crls() {
    edgeguard::tls::init_crypto();
    let dir = Dir::new();
    let ca = Ca::new("client CA");
    let mut cfg = base();
    let (cert, key) = dir.pair("upstream", &ca.client_expiring("up.example", 10));
    cfg.upstream_tls.cert_path = cert;
    cfg.upstream_tls.key_path = key;
    let (cert, key) = dir.pair("logs", &ca.client_expiring("logs.example", 2));
    cfg.log.ship.enabled = true;
    cfg.log.ship.url = "https://collector.internal/ingest".into();
    cfg.log.ship.outbound.client_cert_path = cert;
    cfg.log.ship.outbound.client_key_path = key;
    // Disabled: its certificate is not presented, so not linted.
    let (cert, key) = dir.pair("traces", &ca.client_expiring("traces.example", 1));
    cfg.tracing.outbound.client_cert_path = cert;
    cfg.tracing.outbound.client_key_path = key;
    let partner = Ca::expiring("partner CA", 5);
    cfg.tls.enabled = true;
    cfg.tls.client_auth.mode = "required".into();
    cfg.tls.client_auth.ca_path = dir.write("partner-ca.pem", &partner.pem);
    cfg.tls.client_auth.crl_paths = vec![dir.write(
        "partner.crl",
        &partner.crl_next_update(&[], time::Duration::hours(-3)),
    )];

    let findings = edgeguard::doctor::lint(&cfg);
    let find = |level: Level, needle: &str| {
        findings
            .iter()
            .any(|f| f.level == level && f.message.contains(needle))
    };
    assert!(
        find(Level::Warn, "upstream_tls: the certificate at"),
        "{findings:?}"
    );
    assert!(
        find(Level::Error, "log.ship: the certificate at"),
        "{findings:?}"
    );
    assert!(!findings.iter().any(|f| f.message.contains("tracing:")));
    assert!(
        find(Level::Warn, "the CA \"partner CA\" expires in"),
        "{findings:?}"
    );
    assert!(find(Level::Warn, "past its nextUpdate"), "{findings:?}");
}
