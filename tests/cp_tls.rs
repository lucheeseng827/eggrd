//! The managed-mode client against a control plane behind a private CA (`control_plane.ca_path`)
//! that authenticates edges by client certificate (`client_cert_path`/`client_key_path`), directly
//! and through an egress proxy (`control_plane.proxy`): what is trusted, what is presented, what a
//! rotation changes, and what the proxy sees.

use std::sync::{Arc, Mutex};

use axum::extract::{OriginalUri, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::Engine;
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;
use common::{connect_proxy, Ca, Dir};

use edgeguard::client_auth::{ClientAuth, ClientCert};
use edgeguard::config::{ControlPlaneCfg, TlsCfg};
use edgeguard::cp::{CpClient, PullResult, UsageDelta};

/// Every request the control plane answered: its path and the client certificate's first name
/// (`-` for none).
type Seen = Arc<Mutex<Vec<(String, String)>>>;

struct ControlPlane {
    url: String,
    port: u16,
    seen: Seen,
    _stop: watch::Sender<bool>,
}

/// A control plane on TLS, its certificate for `localhost` from `server_ca`, verifying client
/// certificates against `edge_ca` (`mode`: `required` or `optional`). On rustls's server
/// defaults and HTTP/1.1 keep-alive, as a real one runs: it resumes sessions and keeps connections
/// open, so a client could go on presenting a certificate it has replaced.
async fn control_plane(dir: &Dir, server_ca: &Ca, edge_ca: &Ca, mode: &str) -> ControlPlane {
    edgeguard::tls::init_crypto();
    fn record(seen: &Seen, uri: &axum::http::Uri, cert: Option<Extension<Arc<ClientCert>>>) {
        let name = cert
            .and_then(|Extension(c)| c.identities().next().map(str::to_string))
            .unwrap_or_else(|| "-".into());
        seen.lock().unwrap().push((uri.path().to_string(), name));
    }
    async fn policy(
        State(seen): State<Seen>,
        OriginalUri(uri): OriginalUri,
        cert: Option<Extension<Arc<ClientCert>>>,
    ) -> impl IntoResponse {
        record(&seen, &uri, cert);
        Json(serde_json::json!({ "etag": "\"v1\"", "body": "[auth]\nmode = \"none\"\n" }))
    }
    async fn usage(
        State(seen): State<Seen>,
        OriginalUri(uri): OriginalUri,
        cert: Option<Extension<Arc<ClientCert>>>,
    ) -> impl IntoResponse {
        record(&seen, &uri, cert);
    }
    let app = Router::new()
        .route("/v3/edge/t1/policy", get(policy))
        .route("/v3/edge/t1/usage", post(usage));
    let seen: Seen = Arc::default();
    let app = app.with_state(Arc::clone(&seen));

    let mut tls = TlsCfg {
        enabled: true,
        ..Default::default()
    };
    tls.client_auth.mode = mode.into();
    tls.client_auth.ca_path = dir.write("edge-ca.pem", &edge_ca.pem);
    let client_auth = ClientAuth::from_cfg(&tls).unwrap().unwrap();
    let (cert, key) = dir.pair("cp", &server_ca.server(&["localhost"]));
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    // rustls's defaults, session resumption included, as a control plane would run — not the
    // edge's own listener config, which turns resumption off whenever it verifies clients.
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_client_cert_verifier(client_auth)
    .with_cert_resolver(store);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(edgeguard::serve::serve(
        listener,
        Some(config),
        app,
        edgeguard::serve::ServeOpts::default(),
        rx,
    ));
    ControlPlane {
        url: format!("https://localhost:{port}"),
        port,
        seen,
        _stop: stop,
    }
}

fn managed(url: &str) -> ControlPlaneCfg {
    ControlPlaneCfg {
        enabled: true,
        url: url.into(),
        tenant_id: "t1".into(),
        edge_token: "edge-token".into(),
        ..Default::default()
    }
}

/// `cfg` with `ca_path` trusting `ca`, presenting the client certificate `name` from `edge_ca`.
fn with_identity(
    mut cfg: ControlPlaneCfg,
    dir: &Dir,
    ca: &Ca,
    edge_ca: &Ca,
    name: &str,
) -> ControlPlaneCfg {
    cfg.outbound.ca_path = dir.write("cp-ca.pem", &ca.pem);
    let (cert, key) = dir.pair("edge", &edge_ca.client(name));
    cfg.outbound.client_cert_path = cert;
    cfg.outbound.client_key_path = key;
    cfg
}

async fn pull(client: &CpClient) -> anyhow::Result<String> {
    match client.pull_policy(None).await? {
        PullResult::Policy { etag, .. } => Ok(etag),
        PullResult::NotModified => anyhow::bail!("expected a policy"),
    }
}

#[tokio::test]
async fn the_edge_trusts_the_private_ca_and_presents_its_certificate() {
    let dir = Dir::new();
    let (cp_ca, edge_ca) = (Ca::new("cp-ca"), Ca::new("edge-ca"));
    let cp = control_plane(&dir, &cp_ca, &edge_ca, "required").await;
    let cfg = with_identity(managed(&cp.url), &dir, &cp_ca, &edge_ca, "edge-1");
    let client = CpClient::from_cfg(&cfg).unwrap().unwrap();
    assert!(client.identity().is_some());

    assert_eq!(pull(&client).await.unwrap(), "\"v1\"");
    client.report_usage(&UsageDelta::default()).await.unwrap();
    assert_eq!(
        *cp.seen.lock().unwrap(),
        [
            ("/v3/edge/t1/policy".to_string(), "edge-1".to_string()),
            ("/v3/edge/t1/usage".to_string(), "edge-1".to_string()),
        ]
    );
}

#[tokio::test]
async fn without_the_private_ca_the_control_plane_is_not_trusted() {
    let dir = Dir::new();
    let (cp_ca, edge_ca) = (Ca::new("cp-ca"), Ca::new("edge-ca"));
    let cp = control_plane(&dir, &cp_ca, &edge_ca, "optional").await;
    // Neither setting: the client as it always was, on the public roots.
    let plain = CpClient::from_cfg(&managed(&cp.url)).unwrap().unwrap();
    // A client certificate but no `ca_path`: still the public roots.
    let mut cfg = with_identity(managed(&cp.url), &dir, &cp_ca, &edge_ca, "edge-1");
    cfg.outbound.ca_path.clear();
    let identity_only = CpClient::from_cfg(&cfg).unwrap().unwrap();
    // The wrong CA: a set `ca_path` replaces the public roots, so it is the only trust there is.
    let mut cfg = managed(&cp.url);
    cfg.outbound.ca_path = dir.write("other-ca.pem", &Ca::new("other").pem);
    let wrong_ca = CpClient::from_cfg(&cfg).unwrap().unwrap();

    for (what, client) in [
        ("no settings", plain),
        ("identity only", identity_only),
        ("wrong ca", wrong_ca),
    ] {
        let e = format!("{:#}", pull(&client).await.unwrap_err());
        assert!(e.contains("UnknownIssuer"), "{what}: {e}");
    }
    assert!(cp.seen.lock().unwrap().is_empty(), "nothing got through");
}

#[tokio::test]
async fn a_control_plane_that_requires_a_client_certificate_refuses_an_edge_without_one() {
    let dir = Dir::new();
    let (cp_ca, edge_ca) = (Ca::new("cp-ca"), Ca::new("edge-ca"));
    let cp = control_plane(&dir, &cp_ca, &edge_ca, "required").await;
    let mut cfg = managed(&cp.url);
    cfg.outbound.ca_path = dir.write("cp-ca.pem", &cp_ca.pem);
    let client = CpClient::from_cfg(&cfg).unwrap().unwrap();
    assert!(client.identity().is_none());
    assert!(pull(&client).await.is_err());
    // A certificate from a CA the control plane does not trust fares no better.
    let mut cfg = with_identity(managed(&cp.url), &dir, &cp_ca, &Ca::new("rogue"), "edge-1");
    cfg.outbound.ca_path = dir.write("cp-ca.pem", &cp_ca.pem);
    let rogue = CpClient::from_cfg(&cfg).unwrap().unwrap();
    assert!(pull(&rogue).await.is_err());
    assert!(cp.seen.lock().unwrap().is_empty());

    // A private CA alone is enough for a control plane that authenticates by token only.
    let optional = control_plane(&dir, &cp_ca, &edge_ca, "optional").await;
    let mut cfg = managed(&optional.url);
    cfg.outbound.ca_path = dir.write("cp-ca.pem", &cp_ca.pem);
    let client = CpClient::from_cfg(&cfg).unwrap().unwrap();
    assert_eq!(pull(&client).await.unwrap(), "\"v1\"");
    assert_eq!(optional.seen.lock().unwrap()[0].1, "-");
}

#[tokio::test]
async fn a_rotated_client_certificate_is_presented_on_the_next_handshake() {
    let dir = Dir::new();
    let (cp_ca, edge_ca) = (Ca::new("cp-ca"), Ca::new("edge-ca"));
    let cp = control_plane(&dir, &cp_ca, &edge_ca, "required").await;
    let cfg = with_identity(managed(&cp.url), &dir, &cp_ca, &edge_ca, "edge-1");
    let client = CpClient::from_cfg(&cfg).unwrap().unwrap();
    pull(&client).await.unwrap();

    // What the watcher in `main` does when the files change.
    dir.pair("edge", &edge_ca.client("edge-1-rotated"));
    client.identity().unwrap().reload().unwrap();
    pull(&client).await.unwrap();

    let names: Vec<String> = cp
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(_, n)| n.clone())
        .collect();
    assert_eq!(names, ["edge-1", "edge-1-rotated"]);
}

#[tokio::test]
async fn the_control_plane_is_reached_through_the_configured_proxy() {
    let dir = Dir::new();
    let (cp_ca, edge_ca) = (Ca::new("cp-ca"), Ca::new("edge-ca"));
    let cp = control_plane(&dir, &cp_ca, &edge_ca, "required").await;
    let (proxy, connects) = connect_proxy().await;
    let mut cfg = with_identity(managed(&cp.url), &dir, &cp_ca, &edge_ca, "edge-1");
    cfg.outbound.proxy = format!("http://edge:s3cret@{proxy}");
    let client = CpClient::from_cfg(&cfg).unwrap().unwrap();

    assert_eq!(pull(&client).await.unwrap(), "\"v1\"");
    client.report_usage(&UsageDelta::default()).await.unwrap();

    let connects = connects.lock().unwrap().clone();
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("edge:s3cret")
    );
    assert_eq!(
        connects.len(),
        2,
        "a client that presents a certificate keeps no connection between requests: {connects:?}"
    );
    for (request, auth) in &connects {
        assert_eq!(request, &format!("CONNECT localhost:{} HTTP/1.1", cp.port));
        assert_eq!(auth.as_deref(), Some(basic.as_str()));
    }
    // Through the tunnel, TLS is end to end: the control plane saw the edge's own certificate.
    assert!(cp.seen.lock().unwrap().iter().all(|(_, n)| n == "edge-1"));
}
