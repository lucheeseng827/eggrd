//! TLS from the proxy to `https://` upstreams (`[upstream_tls]`), against real rustls upstreams:
//! verification against the public roots or a private CA, client certificates (mutual TLS), the
//! name to verify, per-upstream settings, and a client certificate replaced on disk.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;
use common::{Ca, Dir, Leaf};

use edgeguard::config::{
    AuthCfg, Config, RateLimitCfg, ServerCfg, UpstreamRoute, UpstreamTlsCfg, UpstreamTlsTarget,
};
use edgeguard::serve::{serve, ServeOpts};
use edgeguard::{build_router, build_state};

// ---- upstream and proxy -----------------------------------------------------------------------

/// A TLS upstream serving `leaf` that answers every request with `body`. With `client_ca`, it
/// requires a client certificate signed by that CA.
async fn tls_upstream(
    dir: &Dir,
    leaf: &Leaf,
    client_ca: Option<&Ca>,
    body: &'static str,
) -> (SocketAddr, watch::Sender<bool>) {
    let app = Router::new().fallback(move || async move { body });
    tls_upstream_with(dir, leaf, client_ca, app).await
}

/// [`tls_upstream`], serving `app`. On rustls's server defaults, so it resumes sessions.
async fn tls_upstream_with(
    dir: &Dir,
    leaf: &Leaf,
    client_ca: Option<&Ca>,
    app: Router,
) -> (SocketAddr, watch::Sender<bool>) {
    edgeguard::tls::init_crypto();
    let name = uuid::Uuid::new_v4().simple().to_string();
    let (cert, key) = dir.pair(&name, leaf);
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = match client_ca {
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            for c in rustls_pemfile::certs(&mut ca.pem.as_bytes()) {
                roots.add(c.unwrap()).unwrap();
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .unwrap();
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_cert_resolver(store);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(serve(
        listener,
        Some(Arc::new(config)),
        app,
        ServeOpts::default(),
        rx,
    ));
    (addr, tx)
}

fn proxy_cfg(upstream: String, upstream_tls: UpstreamTlsCfg) -> Config {
    Config {
        server: ServerCfg {
            upstream,
            ..Default::default()
        },
        auth: AuthCfg {
            mode: "none".into(),
            ..Default::default()
        },
        ratelimit: RateLimitCfg {
            enabled: false,
            ..Default::default()
        },
        upstream_tls,
        ..Default::default()
    }
}

/// Run the proxy with `cfg`; returns its address and the TLS settings it built.
async fn proxy(cfg: Config) -> (SocketAddr, Arc<edgeguard::upstream::UpstreamTls>) {
    let state = build_state(Arc::new(cfg)).unwrap();
    let tls = Arc::clone(&state.upstream_tls);
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (addr, tls)
}

async fn get(proxy: SocketAddr, path: &str) -> (StatusCode, String) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Body>();
    let resp = client
        .request(
            Request::get(format!("http://{proxy}{path}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

// ---- tests ------------------------------------------------------------------------------------

#[tokio::test]
async fn an_https_upstream_signed_by_the_configured_ca_is_proxied() {
    let dir = Dir::new();
    let ca = Ca::new("private CA");
    let (up, _stop) = tls_upstream(&dir, &ca.server(&["localhost"]), None, "over-tls").await;
    let (proxy, _) = proxy(proxy_cfg(
        format!("https://localhost:{}", up.port()),
        UpstreamTlsCfg {
            ca_path: dir.write("ca.pem", &ca.pem),
            ..Default::default()
        },
    ))
    .await;
    assert_eq!(get(proxy, "/").await, (StatusCode::OK, "over-tls".into()));
}

#[tokio::test]
async fn an_upstream_the_public_roots_do_not_vouch_for_is_refused() {
    // No ca_path: the public web PKI. A private CA's certificate must not pass.
    let dir = Dir::new();
    let ca = Ca::new("private CA");
    let (up, _stop) = tls_upstream(&dir, &ca.server(&["localhost"]), None, "over-tls").await;
    let (proxy, _) = proxy(proxy_cfg(
        format!("https://localhost:{}", up.port()),
        UpstreamTlsCfg::default(),
    ))
    .await;
    assert_eq!(get(proxy, "/").await.0, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn a_configured_ca_replaces_rather_than_adds_to_what_is_trusted() {
    let dir = Dir::new();
    let signer = Ca::new("the upstream's CA");
    let other = Ca::new("some other CA");
    let (up, _stop) = tls_upstream(&dir, &signer.server(&["localhost"]), None, "over-tls").await;
    let (proxy, _) = proxy(proxy_cfg(
        format!("https://localhost:{}", up.port()),
        UpstreamTlsCfg {
            ca_path: dir.write("other.pem", &other.pem),
            ..Default::default()
        },
    ))
    .await;
    assert_eq!(get(proxy, "/").await.0, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn mutual_tls_presents_the_configured_client_certificate() {
    let dir = Dir::new();
    let server_ca = Ca::new("server CA");
    let client_ca = Ca::new("client CA");
    let (up, _stop) = tls_upstream(
        &dir,
        &server_ca.server(&["localhost"]),
        Some(&client_ca),
        "mutual",
    )
    .await;
    let ca_path = dir.write("server-ca.pem", &server_ca.pem);
    let upstream = format!("https://localhost:{}", up.port());

    // Without a client certificate the upstream refuses the connection.
    let (without, _) = proxy(proxy_cfg(
        upstream.clone(),
        UpstreamTlsCfg {
            ca_path: ca_path.clone(),
            ..Default::default()
        },
    ))
    .await;
    assert_eq!(get(without, "/").await.0, StatusCode::BAD_GATEWAY);

    // With one signed by the CA it trusts, the request goes through.
    let (cert_path, key_path) = dir.pair("edge", &client_ca.client("edge.example"));
    let (with, _) = proxy(proxy_cfg(
        upstream,
        UpstreamTlsCfg {
            ca_path,
            cert_path,
            key_path,
            ..Default::default()
        },
    ))
    .await;
    assert_eq!(get(with, "/").await, (StatusCode::OK, "mutual".into()));
}

#[tokio::test]
async fn an_upstream_dialled_by_ip_is_verified_against_server_name() {
    let dir = Dir::new();
    let ca = Ca::new("private CA");
    // The certificate names a host, not the IP the proxy dials.
    let (up, _stop) = tls_upstream(&dir, &ca.server(&["upstream.internal"]), None, "by-name").await;
    let ca_path = dir.write("ca.pem", &ca.pem);
    let upstream = format!("https://127.0.0.1:{}", up.port());

    let (by_ip, _) = proxy(proxy_cfg(
        upstream.clone(),
        UpstreamTlsCfg {
            ca_path: ca_path.clone(),
            ..Default::default()
        },
    ))
    .await;
    assert_eq!(get(by_ip, "/").await.0, StatusCode::BAD_GATEWAY);

    let (named, _) = proxy(proxy_cfg(
        upstream,
        UpstreamTlsCfg {
            ca_path,
            server_name: "upstream.internal".into(),
            ..Default::default()
        },
    ))
    .await;
    assert_eq!(get(named, "/").await, (StatusCode::OK, "by-name".into()));
}

#[tokio::test]
async fn each_upstream_can_have_its_own_settings() {
    let dir = Dir::new();
    let web_ca = Ca::new("web CA");
    let api_ca = Ca::new("api CA");
    let (web, _s1) = tls_upstream(&dir, &web_ca.server(&["localhost"]), None, "web").await;
    let (api, _s2) = tls_upstream(&dir, &api_ca.server(&["127.0.0.1"]), None, "api").await;
    let api_target = format!("https://127.0.0.1:{}", api.port());

    let cfg = |targets: Vec<UpstreamTlsTarget>| {
        let mut cfg = proxy_cfg(
            format!("https://localhost:{}", web.port()),
            UpstreamTlsCfg {
                ca_path: dir.write("web-ca.pem", &web_ca.pem),
                targets,
                ..Default::default()
            },
        );
        cfg.upstreams = vec![UpstreamRoute {
            path: "/api/".into(),
            target: api_target.clone(),
            ..Default::default()
        }];
        cfg
    };

    // The default CA does not cover the API upstream...
    let (p, _) = proxy(cfg(vec![])).await;
    assert_eq!(get(p, "/").await, (StatusCode::OK, "web".into()));
    assert_eq!(get(p, "/api/items").await.0, StatusCode::BAD_GATEWAY);

    // ...until that upstream gets its own.
    let (p, _) = proxy(cfg(vec![UpstreamTlsTarget {
        target: api_target.clone(),
        ca_path: dir.write("api-ca.pem", &api_ca.pem),
        ..Default::default()
    }]))
    .await;
    assert_eq!(get(p, "/").await, (StatusCode::OK, "web".into()));
    assert_eq!(get(p, "/api/items").await, (StatusCode::OK, "api".into()));
}

#[tokio::test]
async fn a_client_certificate_replaced_on_disk_is_used_by_new_connections() {
    let dir = Dir::new();
    let server_ca = Ca::new("server CA");
    let client_ca = Ca::new("client CA");
    let stranger = Ca::new("a CA the upstream does not trust");
    let (up, _stop) = tls_upstream(
        &dir,
        &server_ca.server(&["localhost"]),
        Some(&client_ca),
        "rotated",
    )
    .await;
    let (cert_path, key_path) = dir.pair("edge", &stranger.client("edge.example"));
    let (proxy, tls) = proxy(proxy_cfg(
        format!("https://localhost:{}", up.port()),
        UpstreamTlsCfg {
            ca_path: dir.write("server-ca.pem", &server_ca.pem),
            cert_path,
            key_path,
            ..Default::default()
        },
    ))
    .await;
    assert_eq!(get(proxy, "/").await.0, StatusCode::BAD_GATEWAY);

    // Rotate to a certificate the upstream trusts. In the binary the watcher calls `reload`.
    dir.pair("edge", &client_ca.client("edge.example"));
    assert_eq!(tls.identities().len(), 1);
    tls.identities()[0].reload().unwrap();
    assert_eq!(get(proxy, "/").await, (StatusCode::OK, "rotated".into()));
}

/// A resumed TLS session carries the client certificate of the handshake it resumes, so a client
/// that resumed would go on presenting the certificate it replaced.
#[tokio::test]
async fn a_rotated_client_certificate_is_not_hidden_by_a_resumed_session() {
    let dir = Dir::new();
    let server_ca = Ca::new("server CA");
    let client_ca = Ca::new("client CA");
    // Answers with the name on the client certificate, and closes the connection, so every
    // request is a new handshake.
    let app = Router::new().fallback(
        |cert: Option<axum::Extension<Arc<edgeguard::client_auth::ClientCert>>>| async move {
            let name = cert
                .and_then(|axum::Extension(c)| c.identities().next().map(str::to_string))
                .unwrap_or_default();
            ([(axum::http::header::CONNECTION, "close")], name)
        },
    );
    let (up, _stop) = tls_upstream_with(
        &dir,
        &server_ca.server(&["localhost"]),
        Some(&client_ca),
        app,
    )
    .await;
    let (cert_path, key_path) = dir.pair("edge", &client_ca.client("before.example"));
    let (proxy, tls) = proxy(proxy_cfg(
        format!("https://localhost:{}", up.port()),
        UpstreamTlsCfg {
            ca_path: dir.write("server-ca.pem", &server_ca.pem),
            cert_path,
            key_path,
            ..Default::default()
        },
    ))
    .await;
    assert_eq!(
        get(proxy, "/").await,
        (StatusCode::OK, "before.example".into())
    );
    assert_eq!(
        get(proxy, "/").await,
        (StatusCode::OK, "before.example".into())
    );

    dir.pair("edge", &client_ca.client("after.example"));
    tls.identities()[0].reload().unwrap();
    assert_eq!(
        get(proxy, "/").await,
        (StatusCode::OK, "after.example".into())
    );
}

#[tokio::test]
async fn an_upstream_url_with_an_unknown_scheme_fails_at_load() {
    let cfg = proxy_cfg("ftp://127.0.0.1:21".into(), UpstreamTlsCfg::default());
    let Err(e) = build_state(Arc::new(cfg)) else {
        panic!("an ftp:// upstream must not load");
    };
    assert!(format!("{e:#}").contains("http:// or https://"), "{e:#}");
}
