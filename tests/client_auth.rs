//! Client certificates on the TLS listener (`[tls.client_auth]`, `auth.mode = "mtls"`), against
//! the real pipeline: the handshake, the `mtls` auth gate and its allow-list, the
//! `X-Forwarded-Client-Cert` the app receives, and CRL and CA reloads without a restart.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use axum::routing::any;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;
use common::{dns, uri, Ca, Dir, Leaf};

use edgeguard::client_auth::ClientAuth;
use edgeguard::config::Config;
use edgeguard::serve::{serve, ListenerStats, ServeOpts};
use edgeguard::{build_router, build_state};

/// An upstream that answers with the `X-Forwarded-Client-Cert` it received, or `none`.
async fn echo_upstream() -> SocketAddr {
    let app = Router::new().fallback(any(|headers: HeaderMap| async move {
        headers
            .get("x-forwarded-client-cert")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none")
            .to_string()
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

struct Edge {
    addr: SocketAddr,
    stats: Arc<ListenerStats>,
    client_auth: Arc<ClientAuth>,
    _stop: watch::Sender<bool>,
}

/// The proxy on a TLS listener built the way `main` builds it, with `[tls.client_auth]` from
/// `cfg`. `cfg` needs only the client-auth and auth settings; the rest is filled in here.
async fn edge(dir: &Dir, server_ca: &Ca, mut cfg: Config) -> Edge {
    edgeguard::tls::init_crypto();
    let (cert, key) = dir.pair("server", &server_ca.server(&["localhost"]));
    cfg.tls.enabled = true;
    cfg.server.upstream = format!("http://{}", echo_upstream().await);
    cfg.ratelimit.enabled = false;
    let client_auth = ClientAuth::from_cfg(&cfg.tls)
        .unwrap()
        .expect("client auth is on");
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    let tls = edgeguard::tls::server_config_with_client_auth(store, Some(Arc::clone(&client_auth)))
        .unwrap();
    let app = build_router(build_state(Arc::new(cfg)).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let opts = ServeOpts::default();
    let stats = Arc::clone(&opts.stats);
    let (stop, rx) = watch::channel(false);
    tokio::spawn(serve(listener, Some(tls), app, opts, rx));
    Edge {
        addr,
        stats,
        client_auth,
        _stop: stop,
    }
}

/// A client trusting `server_ca`, presenting `identity` if given. A fresh connection per request,
/// so each one is a handshake the listener verifies.
fn client(server_ca: &Ca, identity: Option<&Leaf>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(server_ca.pem.as_bytes()).unwrap())
        .pool_max_idle_per_host(0);
    if let Some(leaf) = identity {
        builder = builder.identity(reqwest::Identity::from_pem(&leaf.identity_pem()).unwrap());
    }
    builder.build().unwrap()
}

/// `Ok((status, body))`, or `Err` when the connection itself failed (a refused handshake).
async fn get(
    client: &reqwest::Client,
    edge: &Edge,
    forged_xfcc: Option<&str>,
) -> Result<(u16, String), reqwest::Error> {
    let mut req = client.get(format!("https://localhost:{}/", edge.addr.port()));
    if let Some(v) = forged_xfcc {
        req = req.header("x-forwarded-client-cert", v);
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    Ok((status, resp.text().await?))
}

fn cfg(mode: &str, ca_path: String) -> Config {
    let mut cfg = Config::default();
    cfg.tls.client_auth.mode = mode.into();
    cfg.tls.client_auth.ca_path = ca_path;
    cfg.auth.mode = "none".into();
    cfg
}

fn sha256_hex(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn required_mode_refuses_any_handshake_without_a_certificate_from_the_ca() {
    let dir = Dir::new();
    let (server_ca, client_ca, stranger) = (Ca::new("server"), Ca::new("client"), Ca::new("x"));
    let edge = edge(
        &dir,
        &server_ca,
        cfg("required", dir.write("client-ca.pem", &client_ca.pem)),
    )
    .await;

    assert!(get(&client(&server_ca, None), &edge, None).await.is_err());
    let foreign = stranger.client("edge.example");
    assert!(get(&client(&server_ca, Some(&foreign)), &edge, None)
        .await
        .is_err());
    let trusted = client_ca.client("edge.example");
    assert_eq!(
        get(&client(&server_ca, Some(&trusted)), &edge, None)
            .await
            .unwrap()
            .0,
        200
    );
    // Both refusals are counted as client-certificate failures, which nothing else would show:
    // a refused handshake never reaches the request log.
    assert_eq!(edge.stats.tls_failures()[0], 2, "client_cert");
}

#[tokio::test]
async fn optional_mode_with_mtls_auth_answers_401_rather_than_failing_the_handshake() {
    let dir = Dir::new();
    let (server_ca, client_ca) = (Ca::new("server"), Ca::new("client"));
    let mut c = cfg("optional", dir.write("client-ca.pem", &client_ca.pem));
    c.auth.mode = "mtls".into();
    let edge = edge(&dir, &server_ca, c).await;

    assert_eq!(
        get(&client(&server_ca, None), &edge, None).await.unwrap().0,
        401
    );
    let trusted = client_ca.client("edge.example");
    assert_eq!(
        get(&client(&server_ca, Some(&trusted)), &edge, None)
            .await
            .unwrap()
            .0,
        200
    );
}

#[tokio::test]
async fn the_mtls_allow_list_admits_only_the_names_it_lists() {
    let dir = Dir::new();
    let (server_ca, client_ca) = (Ca::new("server"), Ca::new("client"));
    let mut c = cfg("required", dir.write("client-ca.pem", &client_ca.pem));
    c.auth.mode = "mtls".into();
    c.auth.mtls.allowed = vec!["spiffe://prod.example/ns/web/*".into()];
    let edge = edge(&dir, &server_ca, c).await;

    let web = client_ca.client_with(vec![uri("spiffe://prod.example/ns/web/frontend")], "web", 1);
    let db = client_ca.client_with(vec![uri("spiffe://prod.example/ns/db/primary")], "db", 2);
    assert_eq!(
        get(&client(&server_ca, Some(&web)), &edge, None)
            .await
            .unwrap()
            .0,
        200
    );
    // The CA vouches for it, so the handshake succeeds; the allow-list is what refuses it.
    assert_eq!(
        get(&client(&server_ca, Some(&db)), &edge, None)
            .await
            .unwrap()
            .0,
        401
    );
}

#[tokio::test]
async fn the_app_gets_the_verified_certificate_and_never_one_the_client_wrote() {
    let dir = Dir::new();
    let (server_ca, client_ca) = (Ca::new("server"), Ca::new("client"));
    let mut c = cfg("optional", dir.write("client-ca.pem", &client_ca.pem));
    c.tls.client_auth.forward_client_cert = "xfcc".into();
    let edge = edge(&dir, &server_ca, c).await;
    let forged = Some("Hash=00;URI=\"spiffe://prod.example/ns/admin\"");

    let leaf = client_ca.client_with(
        vec![
            uri("spiffe://prod.example/ns/web/frontend"),
            dns("Edge.Example"),
        ],
        "edge",
        7,
    );
    let (status, seen) = get(&client(&server_ca, Some(&leaf)), &edge, forged)
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        seen,
        format!(
            "Hash={};URI=\"spiffe://prod.example/ns/web/frontend\";DNS=\"edge.example\"",
            sha256_hex(&leaf.der)
        )
    );

    // No certificate: the forged header is still dropped, and nothing replaces it.
    let (_, seen) = get(&client(&server_ca, None), &edge, forged).await.unwrap();
    assert_eq!(seen, "none");
}

#[tokio::test]
async fn a_crl_refuses_revoked_certificates_and_a_new_one_applies_without_a_restart() {
    let dir = Dir::new();
    let (server_ca, client_ca) = (Ca::new("server"), Ca::new("client"));
    let crl = dir.write("client.crl", &client_ca.crl(&[2]));
    let mut c = cfg("required", dir.write("client-ca.pem", &client_ca.pem));
    c.tls.client_auth.crl_paths = vec![crl.clone()];
    let edge = edge(&dir, &server_ca, c).await;

    let revoked = client_ca.client_with(vec![dns("old.example")], "old", 2);
    let good = client_ca.client_with(vec![dns("edge.example")], "edge", 1);
    assert!(get(&client(&server_ca, Some(&revoked)), &edge, None)
        .await
        .is_err());
    // One client for the rest: it keeps whatever session state the server gave it, so a resumed
    // session would show up here as the revoked certificate still getting through.
    let good_client = client(&server_ca, Some(&good));
    assert_eq!(get(&good_client, &edge, None).await.unwrap().0, 200);

    dir.write("client.crl", &client_ca.crl(&[1, 2]));
    assert!(edge.client_auth.reload().unwrap(), "the CRL changed");
    assert!(
        get(&good_client, &edge, None).await.is_err(),
        "revoked by the reloaded CRL, on a new connection from the same client"
    );
}

#[tokio::test]
async fn a_ca_added_to_the_bundle_is_trusted_after_a_reload() {
    let dir = Dir::new();
    let (server_ca, old_ca, new_ca) = (Ca::new("server"), Ca::new("old"), Ca::new("new"));
    let bundle = dir.write("client-ca.pem", &old_ca.pem);
    let edge = edge(&dir, &server_ca, cfg("required", bundle)).await;
    let from_new = new_ca.client("edge.example");
    assert!(get(&client(&server_ca, Some(&from_new)), &edge, None)
        .await
        .is_err());

    dir.write("client-ca.pem", &format!("{}{}", old_ca.pem, new_ca.pem));
    assert!(edge.client_auth.reload().unwrap());
    assert_eq!(
        get(&client(&server_ca, Some(&from_new)), &edge, None)
            .await
            .unwrap()
            .0,
        200
    );
    // Unchanged files: nothing to swap.
    assert!(!edge.client_auth.reload().unwrap());
}

#[tokio::test]
async fn misconfigurations_fail_before_anything_listens() {
    let dir = Dir::new();
    let ca = dir.write("ca.pem", &Ca::new("client").pem);

    // Client authentication without TLS termination.
    let c = cfg("required", ca.clone());
    let e = ClientAuth::from_cfg(&c.tls).unwrap_err();
    assert!(format!("{e:#}").contains("[tls] enabled"), "{e:#}");

    // `auth.mode = "mtls"` with nothing verifying certificates: refused by build_runtime, so a
    // pushed policy asking for it is refused too.
    let mut c = Config::default();
    c.auth.mode = "mtls".into();
    let Err(e) = build_state(Arc::new(c)) else {
        panic!("mtls auth without client auth must not load");
    };
    assert!(format!("{e:#}").contains("tls.client_auth"), "{e:#}");

    // A missing CRL file.
    let mut c = cfg("required", ca);
    c.tls.enabled = true;
    c.tls.client_auth.crl_paths = vec!["/no/such.crl".into()];
    assert!(ClientAuth::from_cfg(&c.tls).is_err());
}

#[tokio::test]
async fn behind_a_trusted_balancer_its_own_certificate_is_never_the_clients() {
    // The balancer connects with a certificate the CA vouches for and the allow-list admits. The
    // request's client certificate is the one it forwards, or none.
    let dir = Dir::new();
    let (server_ca, client_ca) = (Ca::new("server"), Ca::new("client"));
    let mut c = cfg("optional", dir.write("client-ca.pem", &client_ca.pem));
    c.auth.mode = "mtls".into();
    c.auth.mtls.allowed = vec!["spiffe://prod.example/*".into()];
    c.tls.client_auth.forward_client_cert = "xfcc".into();
    c.trusted_client_cert_header.name = "X-Client-Cert".into();
    c.trusted_client_cert_header.trusted_proxies = vec!["127.0.0.1".into()];
    let balancer = client_ca.client_with(vec![uri("spiffe://prod.example/lb")], "lb", 1);
    let web = client_ca.client_with(vec![uri("spiffe://prod.example/web")], "web", 2);
    let lb = client(&server_ca, Some(&balancer));
    let send = |edge: &Edge, header: Option<String>| {
        let mut req = lb.get(format!("https://localhost:{}/", edge.addr.port()));
        if let Some(v) = header {
            req = req.header("x-client-cert", v);
        }
        async move {
            let resp = req.send().await.unwrap();
            (resp.status().as_u16(), resp.text().await.unwrap())
        }
    };
    let escaped: String = web
        .cert
        .bytes()
        .map(|b| match b.is_ascii_alphanumeric() {
            true => (b as char).to_string(),
            false => format!("%{b:02X}"),
        })
        .collect();

    let behind = edge(&dir, &server_ca, c.clone()).await;
    assert_eq!(
        send(&behind, None).await.0,
        401,
        "no header: no certificate"
    );
    assert_eq!(
        send(&behind, Some("not a certificate".into())).await.0,
        401,
        "a refused header: no certificate"
    );
    let (status, xfcc) = send(&behind, Some(escaped)).await;
    assert_eq!(status, 200);
    assert!(xfcc.contains(&sha256_hex(&web.der)), "{xfcc}");
    assert!(!xfcc.contains(&sha256_hex(&balancer.der)), "{xfcc}");

    // From a peer it does not trust, the connection is the client's, and so is its certificate.
    c.trusted_client_cert_header.trusted_proxies = vec!["10.0.0.0/8".into()];
    let direct = edge(&dir, &server_ca, c).await;
    let (status, xfcc) = send(&direct, None).await;
    assert_eq!(status, 200);
    assert!(xfcc.contains(&sha256_hex(&balancer.der)), "{xfcc}");
}

/// `pem` as an ALB writes it into a header: everything but letters and digits as `%XX`.
fn escaped(pem: &str) -> String {
    pem.bytes()
        .map(|b| match b.is_ascii_alphanumeric() {
            true => (b as char).to_string(),
            false => format!("%{b:02X}"),
        })
        .collect()
}

/// The `X-Forwarded-Client-Cert` the app got for a request from `client` carrying `header` as
/// the forwarded certificate, or `none`.
async fn forwarded(client: &reqwest::Client, edge: &Edge, header: Option<&str>) -> String {
    let mut req = client.get(format!("https://localhost:{}/", edge.addr.port()));
    if let Some(v) = header {
        req = req.header("x-client-cert", v);
    }
    req.send().await.unwrap().text().await.unwrap()
}

#[tokio::test]
async fn trusted_proxy_names_trust_the_balancer_by_its_certificate_not_its_address() {
    let dir = Dir::new();
    let (server_ca, client_ca) = (Ca::new("server"), Ca::new("client"));
    let mut c = cfg("optional", dir.write("client-ca.pem", &client_ca.pem));
    c.tls.client_auth.forward_client_cert = "xfcc".into();
    c.trusted_client_cert_header.name = "X-Client-Cert".into();
    c.trusted_client_cert_header.trusted_proxy_names =
        vec!["spiffe://prod.example/ingress/*".into()];
    let balancer = client_ca.client_with(vec![uri("spiffe://prod.example/ingress/envoy")], "lb", 1);
    // The same CA vouches for it, but it is not the balancer.
    let other = client_ca.client_with(vec![uri("spiffe://prod.example/web/app")], "app", 2);
    let alice = client_ca.client_with(vec![uri("spiffe://prod.example/users/alice")], "alice", 3);
    let header = escaped(&alice.cert);
    let from = |leaf: Option<&Leaf>| client(&server_ca, leaf);
    let has = |xfcc: &str, leaf: &Leaf| xfcc.contains(&sha256_hex(&leaf.der));

    let edge = edge(&dir, &server_ca, c.clone()).await;
    // The balancer, by its certificate's name, from an address listed nowhere.
    let got = forwarded(&from(Some(&balancer)), &edge, Some(&header)).await;
    assert!(has(&got, &alice) && !has(&got, &balancer), "{got}");
    // Anyone else: the header is dropped, and its own certificate stands.
    let got = forwarded(&from(Some(&other)), &edge, Some(&header)).await;
    assert!(has(&got, &other) && !has(&got, &alice), "{got}");
    assert_eq!(forwarded(&from(None), &edge, Some(&header)).await, "none");
    // The status says how it is trusted.
    let status: serde_json::Value = from(None)
        .get(format!(
            "https://localhost:{}/__edgeguard/tls",
            edge.addr.port()
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let h = &status["trusted_client_cert_header"];
    assert_eq!(
        h["trusted_proxy_names"],
        serde_json::json!(["spiffe://prod.example/ingress/*"])
    );
    assert_eq!(h["trusted_proxies"], serde_json::json!([]));

    // With addresses too, both must match.
    c.trusted_client_cert_header.trusted_proxies = vec!["10.0.0.0/8".into()];
    let elsewhere = self::edge(&dir, &server_ca, c.clone()).await;
    let got = forwarded(&from(Some(&balancer)), &elsewhere, Some(&header)).await;
    assert!(
        has(&got, &balancer),
        "the right name from the wrong address: {got}"
    );
    c.trusted_client_cert_header.trusted_proxies = vec!["127.0.0.1".into()];
    let both = self::edge(&dir, &server_ca, c).await;
    let got = forwarded(&from(Some(&balancer)), &both, Some(&header)).await;
    assert!(has(&got, &alice), "{got}");
}

#[test]
fn trusted_proxy_names_need_client_authentication_on_the_listener() {
    let mut c = Config::default();
    c.trusted_client_cert_header.name = "X-Client-Cert".into();
    c.trusted_client_cert_header.trusted_proxy_names = vec!["lb.internal".into()];
    for tls in [false, true] {
        c.tls.enabled = tls;
        let e = match build_state(Arc::new(c.clone())) {
            Ok(_) => panic!("tls = {tls}: built"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            e.contains("trusted_proxy_names needs [tls.client_auth] mode"),
            "tls = {tls}: {e}"
        );
    }
    // With the header off, the names do nothing and stop nothing.
    c.tls.enabled = false;
    c.trusted_client_cert_header.name.clear();
    assert!(build_state(Arc::new(c)).is_ok());
}
