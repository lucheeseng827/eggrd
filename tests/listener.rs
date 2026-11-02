//! The shared accept loop (`edgeguard::serve`) on real sockets: header-read timeouts, the
//! connection cap, and the graceful drain, on plain HTTP and over TLS.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::Query;
use axum::routing::get;
use axum::Router;
use edgeguard::serve::{serve, ListenerStats, ServeOpts};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// `/` answers `ok`; `/slow?ms=N` answers `slow` after N milliseconds.
fn app() -> Router {
    #[derive(serde::Deserialize)]
    struct Delay {
        ms: u64,
    }
    Router::new().route("/", get(|| async { "ok" })).route(
        "/slow",
        get(|Query(d): Query<Delay>| async move {
            tokio::time::sleep(Duration::from_millis(d.ms)).await;
            "slow"
        }),
    )
}

fn opts(header_read_timeout: Option<Duration>) -> ServeOpts {
    ServeOpts {
        header_read_timeout,
        max_connections: 0,
        drain_delay: Duration::ZERO,
        drain_timeout: Duration::from_secs(5),
        proxy_protocol: None,
        stats: Arc::default(),
    }
}

struct Running {
    addr: SocketAddr,
    stats: Arc<ListenerStats>,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<anyhow::Result<()>>,
}

async fn start(opts: ServeOpts, tls: Option<Arc<rustls::ServerConfig>>) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::clone(&opts.stats);
    let (shutdown, rx) = watch::channel(false);
    let task = tokio::spawn(serve(listener, tls, app(), opts, rx));
    Running {
        addr,
        stats,
        shutdown,
        task,
    }
}

/// Read until the peer closes. `Some(elapsed)` if that happened within `limit`; a reset counts as
/// closed.
async fn closed_within<S: AsyncRead + Unpin>(s: &mut S, limit: Duration) -> Option<Duration> {
    let started = Instant::now();
    let mut buf = [0u8; 1024];
    tokio::time::timeout(limit, async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await
    .ok()
    .map(|_| started.elapsed())
}

/// Send one keep-alive `GET` and read exactly one response; returns (status, body).
async fn get_on<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, path: &str) -> (u16, String) {
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        let n = s.read(&mut chunk).await.unwrap();
        assert!(n > 0, "closed before a response");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let status: u16 = head[9..12].parse().unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().unwrap())
        })
        .expect("content-length");
    while buf.len() < head_end + len {
        let n = s.read(&mut chunk).await.unwrap();
        assert!(n > 0, "closed mid-body");
        buf.extend_from_slice(&chunk[..n]);
    }
    (
        status,
        String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string(),
    )
}

/// Wait until `stats` shows `n` open connections (the accept loop runs on its own task).
async fn until_open(stats: &ListenerStats, n: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while stats.open() != n {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("expected {n} open connections, saw {}", stats.open()));
}

// ---- header-read timeout ----------------------------------------------------------------------

#[tokio::test]
async fn a_connection_that_sends_nothing_is_closed_after_the_header_timeout() {
    let srv = start(opts(Some(Duration::from_millis(300))), None).await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    let took = closed_within(&mut s, Duration::from_secs(5))
        .await
        .expect("a silent connection must be closed");
    assert!(
        took >= Duration::from_millis(250),
        "closed too early: {took:?}"
    );
    until_open(&srv.stats, 0).await;
}

#[tokio::test]
async fn a_partial_request_head_is_closed_after_the_header_timeout() {
    let srv = start(opts(Some(Duration::from_millis(300))), None).await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: te").await.unwrap();
    closed_within(&mut s, Duration::from_secs(5))
        .await
        .expect("a stalled request head must be closed");
}

#[tokio::test]
async fn a_stalled_http2_preface_is_closed_after_the_header_timeout() {
    // The bytes so far match the HTTP/2 preface, so hyper's version check would wait for more —
    // with no deadline of its own.
    let srv = start(opts(Some(Duration::from_millis(300))), None).await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    s.write_all(b"PRI * HTTP/2").await.unwrap();
    closed_within(&mut s, Duration::from_secs(5))
        .await
        .expect("a stalled preface must be closed");
}

#[tokio::test]
async fn an_idle_keepalive_connection_is_closed_after_the_header_timeout() {
    let srv = start(opts(Some(Duration::from_millis(300))), None).await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    assert_eq!(get_on(&mut s, "/").await, (200, "ok".into()));
    closed_within(&mut s, Duration::from_secs(5))
        .await
        .expect("an idle keep-alive connection must be closed");
}

#[tokio::test]
async fn a_slow_response_is_not_cut_by_the_header_timeout() {
    // The deadline covers reading the request head, not producing the response.
    let srv = start(opts(Some(Duration::from_millis(200))), None).await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    assert_eq!(get_on(&mut s, "/slow?ms=600").await, (200, "slow".into()));
}

#[tokio::test]
async fn a_request_sent_in_pieces_within_the_timeout_is_served_and_the_connection_reused() {
    let srv = start(opts(Some(Duration::from_secs(2))), None).await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    s.write_all(b"G").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    s.write_all(b"ET / HTTP/1.1\r\nHost: test\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    s.write_all(b"\r\n").await.unwrap();
    let mut buf = vec![0u8; 256];
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    // The bytes read ahead of hyper were replayed exactly once: the next request parses cleanly.
    assert_eq!(get_on(&mut s, "/").await, (200, "ok".into()));
}

#[tokio::test]
async fn http2_with_prior_knowledge_still_works() {
    let srv = start(opts(Some(Duration::from_secs(2))), None).await;
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .http2_only(true)
        .build_http::<axum::body::Body>();
    let resp = client
        .get(format!("http://{}/", srv.addr).parse().unwrap())
        .await
        .expect("h2c request");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), axum::http::Version::HTTP_2);
}

#[tokio::test]
async fn header_timeout_off_keeps_a_silent_connection_open() {
    let srv = start(opts(None), None).await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    assert!(
        closed_within(&mut s, Duration::from_millis(500))
            .await
            .is_none(),
        "with the timeout disabled nothing should close it"
    );
}

// ---- connection cap ---------------------------------------------------------------------------

#[tokio::test]
async fn connections_over_the_cap_are_closed_at_accept_and_counted() {
    // Registered as `main` registers the public listener, so the cap reaches the exposition.
    let metrics = edgeguard::metrics::Metrics::new();
    let srv = start(
        ServeOpts {
            max_connections: 2,
            stats: metrics.listener_stats("public"),
            ..opts(Some(Duration::from_secs(10)))
        },
        None,
    )
    .await;
    let mut a = TcpStream::connect(srv.addr).await.unwrap();
    let _b = TcpStream::connect(srv.addr).await.unwrap();
    until_open(&srv.stats, 2).await;

    let mut over = TcpStream::connect(srv.addr).await.unwrap();
    closed_within(&mut over, Duration::from_secs(2))
        .await
        .expect("the third connection must be closed");
    assert_eq!(srv.stats.rejected(), 1);

    // A slot frees up: the next connection is served.
    assert_eq!(get_on(&mut a, "/").await, (200, "ok".into()));
    drop(a);
    until_open(&srv.stats, 1).await;
    let mut next = TcpStream::connect(srv.addr).await.unwrap();
    assert_eq!(get_on(&mut next, "/").await, (200, "ok".into()));
    assert_eq!(srv.stats.rejected(), 1);

    // The cap is exported, so an alert can say "80% of the cap" without knowing the config.
    let text = metrics.render();
    assert!(
        text.contains("edgeguard_connections_max{listener=\"public\"} 2"),
        "{text}"
    );
    assert!(text.contains("edgeguard_connections_rejected_total{listener=\"public\"} 1"));
}

#[tokio::test]
async fn a_listener_without_a_cap_exports_no_max() {
    let metrics = edgeguard::metrics::Metrics::new();
    let srv = start(
        ServeOpts {
            stats: metrics.listener_stats("public"),
            ..opts(Some(Duration::from_secs(10)))
        },
        None,
    )
    .await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    assert_eq!(get_on(&mut s, "/").await, (200, "ok".into()));
    let text = metrics.render();
    assert!(text.contains("edgeguard_connections_open{listener=\"public\"}"));
    assert!(!text.contains("edgeguard_connections_max"), "{text}");
}

// ---- drain ------------------------------------------------------------------------------------

#[tokio::test]
async fn shutdown_finishes_the_in_flight_request_then_refuses_new_connections() {
    let srv = start(opts(Some(Duration::from_secs(10))), None).await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    let in_flight = tokio::spawn(async move { get_on(&mut s, "/slow?ms=700").await });
    until_open(&srv.stats, 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    srv.shutdown.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        TcpStream::connect(srv.addr).await.is_err(),
        "the listening socket must be closed once draining"
    );
    assert!(
        !srv.task.is_finished(),
        "serve must not return while a request is in flight"
    );
    assert_eq!(in_flight.await.unwrap(), (200, "slow".into()));
    tokio::time::timeout(Duration::from_secs(2), srv.task)
        .await
        .expect("serve returns once drained")
        .unwrap()
        .unwrap();
    assert_eq!(srv.stats.open(), 0);
}

#[tokio::test]
async fn idle_keepalive_connections_do_not_hold_up_the_drain() {
    let srv = start(opts(Some(Duration::from_secs(10))), None).await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    assert_eq!(get_on(&mut s, "/").await, (200, "ok".into()));
    let started = Instant::now();
    srv.shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), srv.task)
        .await
        .expect("an idle connection closes at once")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    closed_within(&mut s, Duration::from_secs(1))
        .await
        .expect("the client sees the close");
}

#[tokio::test]
async fn the_drain_gives_up_after_drain_timeout() {
    let srv = start(
        ServeOpts {
            drain_timeout: Duration::from_millis(300),
            ..opts(Some(Duration::from_secs(10)))
        },
        None,
    )
    .await;
    let mut s = TcpStream::connect(srv.addr).await.unwrap();
    s.write_all(b"GET /slow?ms=10000 HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    until_open(&srv.stats, 1).await;
    let started = Instant::now();
    srv.shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), srv.task)
        .await
        .expect("serve returns at drain_timeout")
        .unwrap()
        .unwrap();
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(2),
        "{took:?}"
    );
}

#[tokio::test]
async fn drain_delay_keeps_accepting_before_the_drain() {
    let srv = start(
        ServeOpts {
            drain_delay: Duration::from_millis(400),
            ..opts(Some(Duration::from_secs(10)))
        },
        None,
    )
    .await;
    srv.shutdown.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut s = TcpStream::connect(srv.addr)
        .await
        .expect("still accepting during drain_delay");
    assert_eq!(get_on(&mut s, "/").await, (200, "ok".into()));
    tokio::time::timeout(Duration::from_secs(3), srv.task)
        .await
        .expect("serve returns after the delay and the drain")
        .unwrap()
        .unwrap();
    assert!(TcpStream::connect(srv.addr).await.is_err());
}

// ---- TLS --------------------------------------------------------------------------------------

struct Tls {
    server: Arc<rustls::ServerConfig>,
    client: tokio_rustls::TlsConnector,
    _dir: PathBuf,
}

fn tls() -> Tls {
    edgeguard::tls::init_crypto();
    let dir = std::env::temp_dir().join(format!(
        "eg-listener-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("cert.pem").to_string_lossy().into_owned();
    let key = dir.join("key.pem").to_string_lossy().into_owned();
    edgeguard::selfsigned::write_to(&["localhost".to_string()], 30, &cert, &key).unwrap();
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    let server = edgeguard::tls::server_config(store).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&cert).unwrap();
    for c in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots.add(c.unwrap()).unwrap();
    }
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    Tls {
        server,
        client: tokio_rustls::TlsConnector::from(Arc::new(client)),
        _dir: dir,
    }
}

async fn tls_connect(t: &Tls, addr: SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    t.client
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("TLS handshake")
}

#[tokio::test]
async fn tls_a_handshaken_connection_that_sends_nothing_is_closed_after_the_header_timeout() {
    let t = tls();
    let srv = start(
        opts(Some(Duration::from_millis(300))),
        Some(Arc::clone(&t.server)),
    )
    .await;
    let mut s = tls_connect(&t, srv.addr).await;
    closed_within(&mut s, Duration::from_secs(5))
        .await
        .expect("a silent TLS connection must be closed");
}

#[tokio::test]
async fn tls_shutdown_finishes_the_in_flight_request() {
    // The bug this replaces: the TLS listener returned on shutdown without waiting, and the
    // process exited under its in-flight requests.
    let t = tls();
    let srv = start(
        opts(Some(Duration::from_secs(10))),
        Some(Arc::clone(&t.server)),
    )
    .await;
    let mut s = tls_connect(&t, srv.addr).await;
    let in_flight = tokio::spawn(async move { get_on(&mut s, "/slow?ms=700").await });
    until_open(&srv.stats, 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    srv.shutdown.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !srv.task.is_finished(),
        "serve must not return while a request is in flight"
    );
    assert_eq!(in_flight.await.unwrap(), (200, "slow".into()));
    tokio::time::timeout(Duration::from_secs(3), srv.task)
        .await
        .expect("serve returns once drained")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tls_shutdown_does_not_wait_for_a_handshake_in_progress() {
    let t = tls();
    let srv = start(
        opts(Some(Duration::from_secs(10))),
        Some(Arc::clone(&t.server)),
    )
    .await;
    // Connected, but never sends a ClientHello: the handshake would wait its full 10s.
    let _s = TcpStream::connect(srv.addr).await.unwrap();
    until_open(&srv.stats, 1).await;
    srv.shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), srv.task)
        .await
        .expect("a pending handshake is abandoned on drain")
        .unwrap()
        .unwrap();
}
