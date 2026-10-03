//! Certificate rotation against a real TLS listener: the swap is invisible to traffic, and the
//! watcher picks up the ways certificates actually get replaced on disk.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use edgeguard::certstore::{self, CertSource, CertStore};
use tokio::net::TcpListener;
use tokio::sync::watch;

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "eg-rotation-{tag}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn localhost() -> Vec<String> {
    vec!["localhost".to_string(), "127.0.0.1".to_string()]
}

fn paths(dir: &Path) -> (String, String) {
    (
        dir.join("cert.pem").to_string_lossy().into_owned(),
        dir.join("key.pem").to_string_lossy().into_owned(),
    )
}

/// A TLS listener serving "ok" from `store`, and its address.
async fn serve(store: Arc<CertStore>) -> (SocketAddr, watch::Sender<bool>) {
    edgeguard::tls::init_crypto();
    let config = edgeguard::tls::server_config(store).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let app = Router::new().route("/", get(|| async { "ok" }));
    tokio::spawn(edgeguard::tls::serve(listener, config, app, rx));
    (addr, tx)
}

/// A client that opens a new connection (so a new handshake) for every request and reports the
/// leaf certificate the server presented.
fn new_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .pool_max_idle_per_host(0)
        .build()
        .unwrap()
}

async fn served_leaf(client: &reqwest::Client, addr: SocketAddr) -> Vec<u8> {
    let resp = client
        .get(format!("https://{addr}/"))
        .send()
        .await
        .expect("request over TLS");
    assert_eq!(resp.status(), 200);
    resp.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|i| i.peer_certificate())
        .expect("peer certificate")
        .to_vec()
}

fn leaf_der(cert_path: &str) -> Vec<u8> {
    let pem = std::fs::read(cert_path).unwrap();
    let der = rustls_pemfile::certs(&mut pem.as_slice())
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    der
}

#[tokio::test]
async fn a_swap_under_load_drops_nothing_and_new_handshakes_see_the_new_certificate() {
    let dir = tmpdir("swap");
    let (cert, key) = paths(&dir);
    edgeguard::selfsigned::write_to(&localhost(), 30, &cert, &key).unwrap();
    let first = leaf_der(&cert);
    let store = CertStore::load(&cert, &key, CertSource::File).unwrap();
    let (addr, _stop) = serve(Arc::clone(&store)).await;

    let client = new_client();
    assert_eq!(served_leaf(&client, addr).await, first);

    // Background traffic for the whole swap: every request must succeed.
    let ok = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let (done_tx, done_rx) = watch::channel(false);
    let mut workers = Vec::new();
    for _ in 0..4 {
        let (client, ok, failed, done) = (
            client.clone(),
            Arc::clone(&ok),
            Arc::clone(&failed),
            done_rx.clone(),
        );
        workers.push(tokio::spawn(async move {
            while !*done.borrow() {
                match client.get(format!("https://{addr}/")).send().await {
                    Ok(r) if r.status() == 200 => ok.fetch_add(1, Ordering::Relaxed),
                    _ => failed.fetch_add(1, Ordering::Relaxed),
                };
            }
        }));
    }

    tokio::time::sleep(Duration::from_millis(150)).await;
    edgeguard::selfsigned::write_to(&localhost(), 60, &cert, &key).unwrap();
    let second = leaf_der(&cert);
    assert_ne!(first, second);
    assert_eq!(store.reload().unwrap(), certstore::Reload::Swapped);
    tokio::time::sleep(Duration::from_millis(150)).await;

    done_tx.send(true).unwrap();
    for w in workers {
        w.await.unwrap();
    }
    assert!(ok.load(Ordering::Relaxed) > 0, "traffic actually ran");
    assert_eq!(
        failed.load(Ordering::Relaxed),
        0,
        "no request failed during the swap"
    );
    // A fresh client, so a full handshake: a client that resumes its TLS session keeps the
    // identity it originally authenticated (resumption carries no certificate), which is the
    // intended behaviour for existing sessions, not something a swap should break.
    assert_eq!(served_leaf(&new_client(), addr).await, second);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Wait until the store serves something other than `before`, or give up.
async fn wait_for_change(store: &CertStore, before: &str) -> bool {
    for _ in 0..100 {
        if store.info().serial != before {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn the_watcher_reloads_an_atomically_replaced_pair() {
    let dir = tmpdir("watch");
    let (cert, key) = paths(&dir);
    edgeguard::selfsigned::write_to(&localhost(), 30, &cert, &key).unwrap();
    let store = CertStore::load(&cert, &key, CertSource::File).unwrap();
    let before = store.info().serial;
    let (stop_tx, stop_rx) = watch::channel(false);
    let task = tokio::spawn(certstore::watch(Arc::clone(&store), stop_rx));
    tokio::time::sleep(Duration::from_millis(200)).await;

    // What cert-manager, certbot or another eggrd's renewal does: stage, then rename into place.
    edgeguard::selfsigned::write_to(&localhost(), 45, &cert, &key).unwrap();
    assert!(
        wait_for_change(&store, &before).await,
        "watcher did not reload"
    );

    stop_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Kubernetes secret volume: `tls.crt -> ..data/tls.crt`, `..data -> ..<timestamp>`. An update
/// writes a new timestamped directory and atomically flips `..data`; the files the proxy was
/// pointed at never change names, so watching by file name would miss it.
#[cfg(unix)]
#[tokio::test]
async fn the_watcher_follows_a_kubernetes_secret_symlink_flip() {
    use std::os::unix::fs::symlink;

    let dir = tmpdir("k8s");
    let gen = |name: &str, days: u32| {
        let d = dir.join(name);
        std::fs::create_dir_all(&d).unwrap();
        let c = d.join("tls.crt").to_string_lossy().into_owned();
        let k = d.join("tls.key").to_string_lossy().into_owned();
        edgeguard::selfsigned::write_to(&localhost(), days, &c, &k).unwrap();
    };
    gen("..2026_10_01_a", 30);
    symlink("..2026_10_01_a", dir.join("..data")).unwrap();
    symlink("..data/tls.crt", dir.join("tls.crt")).unwrap();
    symlink("..data/tls.key", dir.join("tls.key")).unwrap();

    let cert = dir.join("tls.crt").to_string_lossy().into_owned();
    let key = dir.join("tls.key").to_string_lossy().into_owned();
    let store = CertStore::load(&cert, &key, CertSource::File).unwrap();
    let before = store.info().serial;
    let (stop_tx, stop_rx) = watch::channel(false);
    let task = tokio::spawn(certstore::watch(Arc::clone(&store), stop_rx));
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The kubelet's update: new directory, new symlink, rename over `..data`.
    gen("..2026_10_02_b", 60);
    symlink("..2026_10_02_b", dir.join("..data_tmp")).unwrap();
    std::fs::rename(dir.join("..data_tmp"), dir.join("..data")).unwrap();

    assert!(
        wait_for_change(&store, &before).await,
        "watcher missed the symlink flip"
    );

    stop_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_half_written_pair_is_rejected_and_the_old_certificate_keeps_serving() {
    let dir = tmpdir("half");
    let (cert, key) = paths(&dir);
    edgeguard::selfsigned::write_to(&localhost(), 30, &cert, &key).unwrap();
    let first = leaf_der(&cert);
    let store = CertStore::load(&cert, &key, CertSource::File).unwrap();
    let (addr, _stop) = serve(Arc::clone(&store)).await;

    // A tool that writes the certificate first and the key a moment later.
    let other = tmpdir("half-other");
    let (other_cert, other_key) = paths(&other);
    edgeguard::selfsigned::write_to(&localhost(), 60, &other_cert, &other_key).unwrap();
    std::fs::copy(&other_cert, &cert).unwrap();
    assert!(
        store.reload().is_err(),
        "a certificate without its key is refused"
    );
    assert_eq!(served_leaf(&new_client(), addr).await, first);

    // The key lands; the next reload takes the completed pair.
    std::fs::copy(&other_key, &key).unwrap();
    assert_eq!(store.reload().unwrap(), certstore::Reload::Swapped);
    assert_eq!(
        served_leaf(&new_client(), addr).await,
        leaf_der(&other_cert)
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other);
}

/// `GET /__edgeguard/tls` describes the certificate the store serves, through the real router;
/// without a store it is a 404, not an empty body.
#[tokio::test]
async fn tls_status_endpoint_reports_the_served_certificate() {
    let dir = tmpdir("status");
    let (cert, key) = paths(&dir);
    edgeguard::selfsigned::write_to(&localhost(), 30, &cert, &key).unwrap();
    let store = CertStore::load(&cert, &key, CertSource::SelfSigned).unwrap();

    let serve_router = |state: edgeguard::proxy::AppState| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = edgeguard::build_router(state);
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        addr
    };
    let url = |addr: SocketAddr| format!("http://{addr}/__edgeguard/tls");

    // No store installed: this listener does not terminate TLS.
    let plain = edgeguard::build_state(Arc::new(edgeguard::config::Config::default())).unwrap();
    assert!(plain.metrics.cert_store().is_none());
    let resp = reqwest::get(url(serve_router(plain).await)).await.unwrap();
    assert_eq!(resp.status(), 404);

    let state = edgeguard::build_state(Arc::new(edgeguard::config::Config::default())).unwrap();
    assert!(state.metrics.set_cert_store(Arc::clone(&store)));
    assert!(
        !state.metrics.set_cert_store(Arc::clone(&store)),
        "installed once"
    );
    assert!(state.metrics.cert_store().is_some());
    let resp = reqwest::get(url(serve_router(state).await)).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "application/json"
    );
    let j: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(j["serial"], store.info().serial.as_str());
    assert_eq!(j["source"], "self_signed");
    assert_eq!(j["not_after"], store.info().not_after);
    let _ = std::fs::remove_dir_all(&dir);
}

/// One listener, several certificates: each hostname gets its own pair over a real handshake, an
/// unknown name gets the default, and replacing one pair on disk swaps only that one.
#[tokio::test]
async fn sni_serves_each_hostname_its_own_certificate_and_swaps_them_independently() {
    let dir = tmpdir("sni");
    let pair = |name: &str, hosts: &[&str]| {
        let d = dir.join(name);
        std::fs::create_dir_all(&d).unwrap();
        let (cert, key) = paths(&d);
        let hosts: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
        edgeguard::selfsigned::write_to(&hosts, 30, &cert, &key).unwrap();
        (cert, key)
    };
    let (dcert, dkey) = pair("default", &["localhost"]);
    let (acert, akey) = pair("a", &["a.test"]);
    let (bcert, bkey) = pair("b", &["b.wild.test"]);
    let default = CertStore::load(&dcert, &dkey, CertSource::File).unwrap();
    let a = CertStore::load(&acert, &akey, CertSource::File).unwrap();
    let b = CertStore::load(&bcert, &bkey, CertSource::File).unwrap();
    let resolver = certstore::SniResolver::new(
        Arc::clone(&default),
        vec![
            certstore::SniCert {
                hosts: vec!["a.test".into()],
                store: Arc::clone(&a),
            },
            certstore::SniCert {
                hosts: vec!["*.wild.test".into()],
                store: Arc::clone(&b),
            },
        ],
    )
    .unwrap();

    edgeguard::tls::init_crypto();
    let config = edgeguard::tls::server_config_with(Arc::new(resolver)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_stop, rx) = watch::channel(false);
    let app = Router::new().route("/", get(|| async { "ok" }));
    tokio::spawn(edgeguard::tls::serve(listener, config, app, rx));
    let (_wstop, wrx) = watch::channel(false);
    tokio::spawn(certstore::watch(Arc::clone(&b), wrx));

    // A fresh client per request (full handshake), sending `host` as SNI.
    let leaf_for = |host: &'static str| async move {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .tls_info(true)
            .pool_max_idle_per_host(0)
            // The names are made up and resolve to the listener: never send them to a proxy.
            .no_proxy()
            .resolve(host, addr)
            .build()
            .unwrap();
        let resp = client
            .get(format!("https://{host}:{}/", addr.port()))
            .send()
            .await
            .unwrap();
        resp.extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|i| i.peer_certificate())
            .unwrap()
            .to_vec()
    };
    assert_eq!(leaf_for("a.test").await, leaf_der(&acert));
    assert_eq!(leaf_for("x.wild.test").await, leaf_der(&bcert));
    assert_eq!(leaf_for("unknown.test").await, leaf_der(&dcert));

    // Replace the wildcard pair on disk: the watcher swaps it; the others are untouched.
    let before = leaf_der(&bcert);
    let tmp = dir.join("b-new");
    std::fs::create_dir_all(&tmp).unwrap();
    let (ncert, nkey) = paths(&tmp);
    edgeguard::selfsigned::write_to(&["b.wild.test".to_string()], 60, &ncert, &nkey).unwrap();
    std::fs::rename(&nkey, &bkey).unwrap();
    std::fs::rename(&ncert, &bcert).unwrap();
    let after = leaf_der(&bcert);
    assert_ne!(before, after);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while leaf_for("x.wild.test").await != after {
        assert!(
            std::time::Instant::now() < deadline,
            "the watcher never swapped the pair"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(leaf_for("a.test").await, leaf_der(&acert));
    assert_eq!(leaf_for("unknown.test").await, leaf_der(&dcert));
    let _ = std::fs::remove_dir_all(&dir);
}
