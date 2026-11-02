//! The ACME client: `obtain_certificate` against a stub ACME server behind a private CA, with the
//! proxy and trust settings of `[tls.acme]` and `[outbound]`.
//!
//! The stub serves the directory, nonces and account registration, and refuses the order. That is
//! as far as an order goes without the CA validating a challenge on `:80`, and every request that
//! far — a GET, a HEAD and signed POSTs — goes out on the client under test. A cached account
//! proves registration went through; the order's refusal proves the error comes back intact.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;
use common::{connect_proxy, Ca, Dir};

use edgeguard::config::{AcmeCfg, OutboundCfg, OutboundDefaultsCfg, TlsCfg};

/// One request the stub answered: method, path, content type, body.
type Hits = Arc<Mutex<Vec<(String, String, String, String)>>>;

struct Stub {
    base: String,
    port: u16,
    hits: Hits,
    _stop: watch::Sender<bool>,
}

/// An ACME server on TLS for `localhost`, its certificate from `ca`. It registers any account and
/// refuses every order with a problem document.
async fn acme_stub(dir: &Dir, ca: &Ca) -> Stub {
    edgeguard::tls::init_crypto();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("https://localhost:{port}");
    let hits: Hits = Arc::default();
    let seen = Arc::clone(&hits);
    let nonces = Arc::new(AtomicU64::new(0));
    let root = base.clone();
    let app = Router::new().fallback(
        move |method: Method, uri: axum::http::Uri, headers: HeaderMap, body: String| {
            let (seen, nonces, base) = (Arc::clone(&seen), Arc::clone(&nonces), root.clone());
            async move {
                let content_type = headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                seen.lock().unwrap().push((
                    method.to_string(),
                    uri.path().to_string(),
                    content_type,
                    body,
                ));
                let nonce = format!("nonce-{}", nonces.fetch_add(1, Ordering::Relaxed));
                let replay = [("replay-nonce", nonce)];
                match uri.path() {
                    "/dir" => axum::Json(serde_json::json!({
                        "newNonce": format!("{base}/nonce"),
                        "newAccount": format!("{base}/account"),
                        "newOrder": format!("{base}/order"),
                    }))
                    .into_response(),
                    // A directory that sends the client to plain http:// for the rest.
                    "/dir-http" => {
                        let plain = base.replace("https://", "http://");
                        axum::Json(serde_json::json!({
                            "newNonce": format!("{plain}/nonce"),
                            "newAccount": format!("{plain}/account"),
                            "newOrder": format!("{plain}/order"),
                        }))
                        .into_response()
                    }
                    "/nonce" => (StatusCode::OK, replay).into_response(),
                    "/account" => (
                        StatusCode::CREATED,
                        replay,
                        [(header::LOCATION, format!("{base}/acct/1"))],
                        axum::Json(serde_json::json!({ "status": "valid" })),
                    )
                        .into_response(),
                    _ => (
                        StatusCode::FORBIDDEN,
                        replay,
                        [(header::CONTENT_TYPE, "application/problem+json")],
                        serde_json::json!({
                            "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                            "detail": "the stub refuses every order",
                            "status": 403,
                        })
                        .to_string(),
                    )
                        .into_response(),
                }
            }
        },
    );
    let (cert, key) = dir.pair("acme", &ca.server(&["localhost"]));
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(store);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let (stop, rx) = watch::channel(false);
    tokio::spawn(edgeguard::serve::serve(
        listener,
        Some(Arc::new(config)),
        app,
        edgeguard::serve::ServeOpts::default(),
        rx,
    ));
    Stub {
        base,
        port,
        hits,
        _stop: stop,
    }
}

/// An order for `edge.example` from `stub`'s directory, with `outbound` as `[tls.acme]`'s
/// settings: the error it ends with, and whether it left an account behind.
async fn order(stub: &Stub, outbound: OutboundCfg) -> (String, bool) {
    order_from(stub, "/dir", outbound).await
}

async fn order_from(stub: &Stub, directory: &str, outbound: OutboundCfg) -> (String, bool) {
    let work = Dir::new();
    let acme = AcmeCfg {
        enabled: true,
        domains: vec!["edge.example".into()],
        accept_tos: true,
        directory_url: format!("{}{directory}", stub.base),
        cache_dir: work.path().join("acme").display().to_string(),
        outbound,
        ..AcmeCfg::default()
    };
    let tls = TlsCfg {
        enabled: true,
        cert_path: work.path().join("cert.pem").display().to_string(),
        key_path: work.path().join("key.pem").display().to_string(),
        acme: acme.clone(),
        ..TlsCfg::default()
    };
    let e = edgeguard::acme::obtain_certificate(&acme, &tls, None)
        .await
        .expect_err("the stub refuses every order");
    let account = work.path().join("acme").join("account.json").exists();
    (format!("{e:#}"), account)
}

fn requests(stub: &Stub) -> Vec<(String, String)> {
    stub.hits
        .lock()
        .unwrap()
        .iter()
        .map(|(m, p, _, _)| (m.clone(), p.clone()))
        .collect()
}

#[tokio::test]
async fn an_acme_order_goes_through_the_configured_proxy_and_ca() {
    let dir = Dir::new();
    let ca = Ca::new("private ACME CA");
    let stub = acme_stub(&dir, &ca).await;
    let (proxy, connects) = connect_proxy().await;
    let (e, account) = order(
        &stub,
        OutboundCfg {
            ca_path: dir.write("acme-ca.pem", &ca.pem),
            proxy: format!("http://{proxy}"),
            ..Default::default()
        },
    )
    .await;

    assert!(e.contains("the stub refuses every order"), "{e}");
    assert!(account, "the account was registered and cached");
    let seen = requests(&stub);
    for want in [
        ("GET", "/dir"),
        ("HEAD", "/nonce"),
        ("POST", "/account"),
        ("POST", "/order"),
    ] {
        assert!(
            seen.contains(&(want.0.to_string(), want.1.to_string())),
            "{want:?} not in {seen:?}"
        );
    }
    // The signed request arrived whole: a JWS, under its media type.
    let hits = stub.hits.lock().unwrap().clone();
    let (_, _, content_type, body) = hits.iter().find(|h| h.1 == "/account").unwrap();
    assert_eq!(content_type, "application/jose+json");
    let jws: serde_json::Value = serde_json::from_str(body).unwrap();
    for field in ["protected", "payload", "signature"] {
        assert!(jws[field].is_string(), "{field} in {jws}");
    }
    let connects = connects.lock().unwrap().clone();
    assert!(!connects.is_empty(), "nothing went through the proxy");
    assert!(connects
        .iter()
        .all(|(line, _)| *line == format!("CONNECT localhost:{} HTTP/1.1", stub.port)));
}

#[tokio::test]
async fn an_acme_order_takes_outbound_and_its_extra_ca_beside_the_system_store() {
    let dir = Dir::new();
    let ca = Ca::new("corporate CA");
    let stub = acme_stub(&dir, &ca).await;
    let (proxy, connects) = connect_proxy().await;
    // Nothing in [tls.acme]: all of it from [outbound], as `Config::load` copies it in.
    let inherit = OutboundCfg {
        defaults: OutboundDefaultsCfg {
            extra_ca_path: dir.write("corp-ca.pem", &ca.pem),
            proxy: format!("http://{proxy}"),
            ..Default::default()
        },
        ..Default::default()
    };
    let (e, account) = order(&stub, inherit.clone()).await;
    assert!(e.contains("the stub refuses every order"), "{e}");
    assert!(account);
    assert!(!connects.lock().unwrap().is_empty(), "the inherited proxy");

    // A section's own proxy wins: "none" goes direct.
    let before = connects.lock().unwrap().len();
    let direct = OutboundCfg {
        proxy: "none".into(),
        ..inherit
    };
    let (e, _) = order(&stub, direct).await;
    assert!(e.contains("the stub refuses every order"), "{e}");
    assert_eq!(connects.lock().unwrap().len(), before);
}

/// With nothing set, the ACME client trusts the operating system's store, as instant-acme's own
/// client did — not the roots built into the binary, which every other client uses. A private ACME
/// CA installed on the host therefore keeps working. `SSL_CERT_FILE` stands in for the host's
/// store here; nothing else in this file depends on it.
#[tokio::test]
async fn with_nothing_set_the_acme_client_trusts_the_system_store() {
    let dir = Dir::new();
    let ca = Ca::new("host-installed ACME CA");
    let stub = acme_stub(&dir, &ca).await;

    let (e, account) = order(&stub, OutboundCfg::default()).await;
    assert!(
        e.contains("UnknownIssuer") || e.contains("invalid peer certificate"),
        "{e}"
    );
    assert!(!account);
    assert!(
        requests(&stub).is_empty(),
        "no request got past the handshake"
    );

    let bundle = dir.write("system-bundle.pem", &ca.pem);
    std::env::set_var("SSL_CERT_FILE", &bundle);
    let (e, account) = order(&stub, OutboundCfg::default()).await;
    std::env::remove_var("SSL_CERT_FILE");
    assert!(e.contains("the stub refuses every order"), "{e}");
    assert!(account, "trusted through the system store");
}

/// RFC 8555 requires https of an ACME server, and instant-acme's own client enforced it on every
/// request. So does this one: a directory that points elsewhere at plain http:// gets no request.
#[tokio::test]
async fn an_acme_directory_cannot_send_the_client_to_plain_http() {
    let dir = Dir::new();
    let ca = Ca::new("private ACME CA");
    let stub = acme_stub(&dir, &ca).await;
    let ca_path = dir.write("acme-ca.pem", &ca.pem);
    let (e, account) = order_from(
        &stub,
        "/dir-http",
        OutboundCfg {
            ca_path,
            ..Default::default()
        },
    )
    .await;
    assert!(!account);
    assert!(e.contains("URL scheme is not allowed"), "{e}");
    assert_eq!(
        requests(&stub),
        [("GET".to_string(), "/dir-http".to_string())],
        "only the directory itself, over https"
    );
}

#[test]
fn acme_settings_that_cannot_work_fail_when_the_client_is_built() {
    let acme = |outbound: OutboundCfg, url: &str| AcmeCfg {
        directory_url: url.into(),
        outbound,
        ..AcmeCfg::default()
    };
    let err = |a: AcmeCfg| format!("{:#}", edgeguard::acme::http_client(&a).err().unwrap());
    let https = "https://acme.internal/directory";
    let e = err(acme(
        OutboundCfg {
            ca_path: "/no/such/ca.pem".into(),
            ..Default::default()
        },
        https,
    ));
    assert!(e.contains("tls.acme.ca_path"), "{e}");
    let e = err(acme(
        OutboundCfg {
            proxy: "socks5://egress:1080".into(),
            ..Default::default()
        },
        https,
    ));
    assert!(e.contains("tls.acme.proxy"), "{e}");
    let e = err(acme(
        OutboundCfg {
            defaults: OutboundDefaultsCfg {
                extra_ca_path: "/no/such/corp-ca.pem".into(),
                ..Default::default()
            },
            ..Default::default()
        },
        https,
    ));
    assert!(
        e.contains("outbound.extra_ca_path (inherited by tls.acme)"),
        "{e}"
    );
    let e = err(acme(
        OutboundCfg::default(),
        "http://acme.internal/directory",
    ));
    assert!(e.contains("not https://"), "{e}");
    assert!(edgeguard::acme::http_client(&acme(OutboundCfg::default(), https)).is_ok());
}
