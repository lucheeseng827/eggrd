//! `[[upstreams]] targets = [...]` through the real pipeline: requests go to the first target in
//! rotation, or each in turn with round-robin, and to `backup` only when the rest will not take
//! them. A request that cannot connect is sent to the next, and targets leave rotation by failing
//! connections or their health check and come back by passing it. A reload keeps what is known,
//! and the pool series say which targets take requests.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;
use common::{Ca, Dir};

use edgeguard::config::{Config, HealthCheckCfg, TargetCfg, UpstreamRoute, UpstreamTlsTarget};
use edgeguard::metrics::Metrics;
use edgeguard::{build_router, build_state};

/// An upstream that answers `<name>:<body length>` with the status in `status`, and has a
/// `/healthz` answering `health`.
struct Up {
    url: String,
    health: Arc<AtomicU16>,
    status: Arc<AtomicU16>,
    hits: Arc<AtomicUsize>,
}

async fn up(name: &'static str) -> Up {
    let health = Arc::new(AtomicU16::new(200));
    let status = Arc::new(AtomicU16::new(200));
    let hits = Arc::new(AtomicUsize::new(0));
    let (h, st, n) = (Arc::clone(&health), Arc::clone(&status), Arc::clone(&hits));
    let app = Router::new()
        .route(
            "/healthz",
            get(move || {
                let h = Arc::clone(&h);
                async move { StatusCode::from_u16(h.load(Ordering::Relaxed)).unwrap() }
            }),
        )
        .fallback(move |body: Bytes| {
            let (n, st) = (Arc::clone(&n), Arc::clone(&st));
            async move {
                n.fetch_add(1, Ordering::Relaxed);
                (
                    StatusCode::from_u16(st.load(Ordering::Relaxed)).unwrap(),
                    format!("{name}:{}", body.len()),
                )
            }
        });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Up {
        url: format!("http://{addr}"),
        health,
        status,
        hits,
    }
}

/// A port nothing listens on: connections are refused.
async fn dead() -> String {
    let socket = reserved();
    let url = format!("http://{}", socket.local_addr().unwrap());
    // Held bound for the rest of the run. Freed, the port could be handed to another test's
    // upstream running alongside, and the "dead" target would answer.
    std::mem::forget(socket);
    url
}

/// A port bound but not listening: connections to it are refused, and no other socket is given
/// it. `listen` on it brings it up.
fn reserved() -> tokio::net::TcpSocket {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    socket
}

fn cfg(targets: &[&str]) -> Config {
    let mut cfg = Config::default();
    cfg.ratelimit.enabled = false;
    cfg.upstreams = vec![UpstreamRoute {
        path: "/".into(),
        name: "app".into(),
        targets: targets.iter().map(|t| (*t).into()).collect(),
        ..Default::default()
    }];
    cfg
}

fn checked(mut cfg: Config) -> Config {
    cfg.upstreams[0].health_check = HealthCheckCfg {
        path: "/healthz".into(),
        interval: "50ms".into(),
        timeout: "1s".into(),
        healthy_after: 2,
        unhealthy_after: 2,
        ..Default::default()
    };
    cfg
}

struct Edge {
    url: String,
    state: edgeguard::proxy::AppState,
    metrics: Arc<Metrics>,
    _stop: watch::Sender<bool>,
}

/// The pipeline on a listener, with the health checker running as `main` runs it.
async fn edge(cfg: Config) -> Edge {
    let state = build_state(Arc::new(cfg)).unwrap();
    let (stop, rx) = watch::channel(false);
    edgeguard::pool::spawn_health_checks(&state, rx);
    let metrics = Arc::clone(&state.metrics);
    let app = build_router(state.clone());
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
    Edge {
        url: format!("http://{addr}"),
        state,
        metrics,
        _stop: stop,
    }
}

async fn get_body(edge: &Edge) -> (u16, String) {
    let resp = reqwest::get(format!("{}/orders", edge.url)).await.unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

fn series(metrics: &Metrics, line: &str) -> Option<u64> {
    metrics
        .render()
        .lines()
        .find_map(|l| l.strip_prefix(line)?.trim().parse().ok())
}

fn requests(metrics: &Metrics, upstream: &str, result: &str) -> u64 {
    let label = upstream.trim_start_matches("http://");
    let scheme = if upstream.starts_with("https") {
        ""
    } else {
        "http://"
    };
    series(
        metrics,
        &format!(
            "edgeguard_upstream_requests_total{{upstream=\"{scheme}{label}\",result=\"{result}\"}}"
        ),
    )
    .unwrap_or(0)
}

fn in_rotation(metrics: &Metrics, upstream: &str) -> Option<u64> {
    series(
        metrics,
        &format!("edgeguard_upstream_in_rotation{{route=\"app\",upstream=\"{upstream}\"}}"),
    )
}

/// Wait up to 10s for `cond`. Generous because a refused connect to loopback takes about two
/// seconds on Windows (the SYN is retried after the RST), and a health check that has to see two
/// of them in a row takes twice that.
async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let started = Instant::now();
    while !cond() {
        assert!(started.elapsed() < Duration::from_secs(10), "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_refused_connection_is_retried_on_the_next_target_and_ejects_its_own() {
    let (a, b, gone) = (up("a").await, up("b").await, dead().await);
    let edge = edge(cfg(&[&gone, &a.url, &b.url])).await;
    assert_eq!(get_body(&edge).await, (200, "a:0".into()));
    assert_eq!(requests(&edge.metrics, &gone, "connect_error"), 1);
    assert_eq!(requests(&edge.metrics, &a.url, "ok"), 1);

    // Ejected: the next requests go straight to `a`, without trying it.
    for _ in 0..3 {
        assert_eq!(get_body(&edge).await, (200, "a:0".into()));
    }
    assert_eq!(requests(&edge.metrics, &gone, "connect_error"), 1);
    assert_eq!(in_rotation(&edge.metrics, &gone), Some(0));
    assert_eq!(in_rotation(&edge.metrics, &a.url), Some(1));
    assert_eq!(in_rotation(&edge.metrics, &b.url), Some(1));
    assert_eq!(
        b.hits.load(Ordering::Relaxed),
        0,
        "priority order, not spread"
    );
}

#[tokio::test]
async fn a_buffered_body_is_sent_again_and_a_streamed_one_is_not() {
    let (a, gone) = (up("a").await, dead().await);
    let edge = edge(cfg(&[&gone, &a.url])).await;
    let post = |edge: &Edge| {
        reqwest::Client::new()
            .post(format!("{}/orders", edge.url))
            .body("hello")
            .send()
    };
    let resp = post(&edge).await.unwrap();
    assert_eq!(
        resp.text().await.unwrap(),
        "a:5",
        "the whole body, to the next target"
    );

    // Streamed, the body was read as it was sent: there is no second copy to send.
    let gone = dead().await;
    let mut c = cfg(&[&gone, &a.url]);
    c.validation.stream_requests = true;
    let edge = self::edge(c).await;
    assert_eq!(post(&edge).await.unwrap().status(), 502);
    // But the target that refused it is out, so the next one goes to `a`.
    let resp = post(&edge).await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "a:5");
}

/// A target that reads the request and then drops the connection without answering.
async fn hangs_up() -> String {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            drop(s);
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn a_request_that_reached_its_target_is_never_sent_again() {
    let (b, rude) = (up("b").await, hangs_up().await);
    let edge = edge(cfg(&[&rude, &b.url])).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/orders", edge.url))
        .body("charge the card")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502, "it may have acted on it");
    assert_eq!(b.hits.load(Ordering::Relaxed), 0);
    assert_eq!(
        in_rotation(&edge.metrics, &rude),
        Some(1),
        "not a connect failure"
    );

    // An answer, even an error, is the target's to give.
    let a = up("a").await;
    a.health.store(503, Ordering::Relaxed);
    let edge = self::edge(cfg(&[&a.url, &b.url])).await;
    let resp = reqwest::get(format!("{}/healthz", edge.url)).await.unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(b.hits.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_failing_health_check_takes_a_target_out_and_passing_brings_it_back() {
    let (a, b) = (up("a").await, up("b").await);
    let edge = edge(checked(cfg(&[&a.url, &b.url]))).await;
    assert_eq!(get_body(&edge).await.1, "a:0");

    // A redirect passes: it is an answer, and many health endpoints send one.
    a.health.store(302, Ordering::Relaxed);
    let passes = |edge: &Edge| {
        series(
            &edge.metrics,
            &format!(
                "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{}\",result=\"pass\"}}",
                a.url
            ),
        )
        .unwrap_or(0)
    };
    let before = passes(&edge);
    until("three more checks of a", || passes(&edge) >= before + 3).await;
    assert_eq!(in_rotation(&edge.metrics, &a.url), Some(1));

    a.health.store(503, Ordering::Relaxed);
    until("a out of rotation", || {
        in_rotation(&edge.metrics, &a.url) == Some(0)
    })
    .await;
    let before = a.hits.load(Ordering::Relaxed);
    assert_eq!(get_body(&edge).await.1, "b:0");
    assert_eq!(
        a.hits.load(Ordering::Relaxed),
        before,
        "not tried while out"
    );

    a.health.store(200, Ordering::Relaxed);
    until("a back in rotation", || {
        in_rotation(&edge.metrics, &a.url) == Some(1)
    })
    .await;
    assert_eq!(get_body(&edge).await.1, "a:0");
    let text = edge.metrics.render();
    assert!(text.contains(&format!(
        "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{}\",result=\"fail\"}}",
        a.url
    )));
    let passed = series(
        &edge.metrics,
        &format!(
            "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{}\",result=\"pass\"}}",
            b.url
        ),
    )
    .unwrap();
    assert!(passed >= 2, "b checked too: {passed}");
}

#[tokio::test]
async fn with_no_target_in_rotation_requests_try_them_all_and_readiness_fails() {
    let (a, b) = (up("a").await, up("b").await);
    let edge = edge(checked(cfg(&[&a.url, &b.url]))).await;
    let ready = || async {
        reqwest::get(format!("{}/__edgeguard/ready", edge.url))
            .await
            .unwrap()
            .status()
            .as_u16()
    };
    assert_eq!(ready().await, 200);
    a.health.store(500, Ordering::Relaxed);
    b.health.store(500, Ordering::Relaxed);
    until("both out", || {
        in_rotation(&edge.metrics, &a.url) == Some(0)
            && in_rotation(&edge.metrics, &b.url) == Some(0)
    })
    .await;
    // A health check can be wrong; refusing every request is sure to be.
    assert_eq!(get_body(&edge).await, (200, "a:0".into()));
    assert_eq!(
        ready().await,
        503,
        "nothing in rotation: take this edge out"
    );

    b.health.store(200, Ordering::Relaxed);
    until("b back", || in_rotation(&edge.metrics, &b.url) == Some(1)).await;
    assert_eq!(ready().await, 200);
    assert_eq!(get_body(&edge).await.1, "b:0");
}

#[tokio::test]
async fn with_every_target_ejected_the_one_that_answers_is_back_at_once() {
    let first = dead().await;
    // Nothing listens here yet: refused, like `first`.
    let spare = reserved();
    let second = format!("http://{}", spare.local_addr().unwrap());
    let edge = edge(cfg(&[&first, &second])).await;
    assert_eq!(get_body(&edge).await.0, 502, "both refused, both ejected");
    assert_eq!(in_rotation(&edge.metrics, &second), Some(0));

    // The second comes up. Nothing is in rotation, so the next request tries both, and the
    // second answers.
    let listener = spare.listen(64).unwrap();
    let app = Router::new().fallback(|| async { "second:0" });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    assert_eq!(get_body(&edge).await, (200, "second:0".into()));
    assert_eq!(requests(&edge.metrics, &first, "connect_error"), 2);

    // It answered, so it is back now, not when eject_for ends: `first` is not tried again.
    assert_eq!(in_rotation(&edge.metrics, &second), Some(1));
    assert_eq!(get_body(&edge).await.1, "second:0");
    assert_eq!(requests(&edge.metrics, &first, "connect_error"), 2);
}

fn hits(ups: &[&Up]) -> Vec<usize> {
    ups.iter().map(|u| u.hits.load(Ordering::Relaxed)).collect()
}

#[tokio::test]
async fn round_robin_spreads_requests_over_the_targets_in_rotation() {
    let (a, b, c) = (up("a").await, up("b").await, up("c").await);
    let mut cfg = checked(cfg(&[&a.url, &b.url, &c.url]));
    cfg.upstreams[0].balance = "round_robin".into();
    let edge = edge(cfg).await;
    for _ in 0..9 {
        assert_eq!(get_body(&edge).await.0, 200);
    }
    assert_eq!(hits(&[&a, &b, &c]), [3, 3, 3]);

    // b out: a and c share its turns.
    b.health.store(503, Ordering::Relaxed);
    until("b out", || in_rotation(&edge.metrics, &b.url) == Some(0)).await;
    for _ in 0..6 {
        assert_eq!(get_body(&edge).await.0, 200);
    }
    assert_eq!(hits(&[&a, &b, &c]), [6, 3, 6]);
}

#[tokio::test]
async fn weighted_round_robin_gives_each_target_its_share() {
    let (a, b, c) = (up("a").await, up("b").await, up("c").await);
    let mut cfg = checked(cfg(&[]));
    cfg.upstreams[0].balance = "round_robin".into();
    cfg.upstreams[0].targets = vec![
        TargetCfg {
            url: a.url.clone(),
            weight: Some(3),
            check_host: None,
        },
        b.url.clone().into(),
        TargetCfg {
            url: c.url.clone(),
            weight: Some(2),
            check_host: None,
        },
    ];
    let edge = edge(cfg).await;
    let mut order = Vec::new();
    for _ in 0..12 {
        order.push(get_body(&edge).await.1);
    }
    assert_eq!(hits(&[&a, &b, &c]), [6, 2, 4]);
    // Interleaved, not bunched: a's turns are spread through each cycle.
    assert_eq!(order[..6], ["a:0", "b:0", "c:0", "a:0", "c:0", "a:0"]);

    // The heavy one out: the others keep their 1 : 2.
    a.health.store(503, Ordering::Relaxed);
    until("a out", || in_rotation(&edge.metrics, &a.url) == Some(0)).await;
    for _ in 0..9 {
        get_body(&edge).await;
    }
    assert_eq!(hits(&[&a, &b, &c]), [6, 5, 10]);
    let j = status(&edge).await;
    assert_eq!(target_named(route_named(&j, "app"), &a.url)["weight"], 3);
}

#[tokio::test]
async fn round_robin_moves_on_from_a_refused_connection_like_priority_does() {
    let (a, c, gone) = (up("a").await, up("c").await, dead().await);
    let mut cfg = cfg(&[&a.url, &gone, &c.url]);
    cfg.upstreams[0].balance = "round_robin".into();
    let edge = edge(cfg).await;
    for _ in 0..6 {
        assert_eq!(get_body(&edge).await.0, 200, "never a 502");
    }
    assert_eq!(
        requests(&edge.metrics, &gone, "connect_error"),
        1,
        "then ejected"
    );
    assert_eq!(hits(&[&a, &c]).iter().sum::<usize>(), 6);
}

#[tokio::test]
async fn backup_targets_take_requests_only_when_the_others_will_not() {
    let (a, b, standby) = (up("a").await, up("b").await, up("standby").await);
    let mut c = checked(cfg(&[&a.url, &b.url]));
    c.upstreams[0].balance = "round_robin".into();
    c.upstreams[0].backup = vec![standby.url.clone().into()];
    let edge = edge(c).await;
    for _ in 0..4 {
        get_body(&edge).await;
    }
    assert_eq!(hits(&[&a, &b, &standby]), [2, 2, 0], "the backup stands by");
    assert_eq!(
        in_rotation(&edge.metrics, &standby.url),
        Some(1),
        "and is checked"
    );

    a.health.store(503, Ordering::Relaxed);
    b.health.store(503, Ordering::Relaxed);
    until("a and b out", || {
        in_rotation(&edge.metrics, &a.url) == Some(0)
            && in_rotation(&edge.metrics, &b.url) == Some(0)
    })
    .await;
    assert_eq!(get_body(&edge).await.1, "standby:0");

    // Both main targets refusing within one request: it reaches the backup all the same.
    let (gone1, gone2) = (dead().await, dead().await);
    let mut c = cfg(&[&gone1, &gone2]);
    c.upstreams[0].backup = vec![standby.url.clone().into()];
    let edge = self::edge(c).await;
    assert_eq!(get_body(&edge).await, (200, "standby:0".into()));
    assert_eq!(requests(&edge.metrics, &gone1, "connect_error"), 1);
    assert_eq!(requests(&edge.metrics, &gone2, "connect_error"), 1);
}

#[tokio::test]
async fn a_reload_keeps_what_is_known_about_the_targets_it_keeps() {
    let (a, b, gone) = (up("a").await, up("b").await, dead().await);
    let c = cfg(&[&gone, &a.url]);
    let edge = edge(c.clone()).await;
    let policy = edgeguard::policy::Policy::new(
        Arc::new(c.clone()),
        Arc::clone(&edge.state.runtime),
        Arc::default(),
    )
    .unwrap();
    assert_eq!(get_body(&edge).await.1, "a:0");
    assert_eq!(requests(&edge.metrics, &gone, "connect_error"), 1);

    // The file changes: same route, one more target.
    let mut reloaded = cfg(&[&gone, &a.url, &b.url]);
    reloaded.validation.max_body = "1MiB".into();
    policy.set_local(reloaded).unwrap();
    assert_eq!(get_body(&edge).await.1, "a:0");
    assert_eq!(
        requests(&edge.metrics, &gone, "connect_error"),
        1,
        "still ejected after the reload: not tried again"
    );
    assert_eq!(
        in_rotation(&edge.metrics, &b.url),
        Some(1),
        "a new target starts in"
    );
}

/// A port whose accept queue is full: the kernel drops new connection attempts, so they hang as
/// they would to a host behind a firewall that drops packets. Hold the returned sockets.
async fn blackhole() -> (String, Vec<tokio::net::TcpStream>, tokio::net::TcpListener) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(0).unwrap();
    let addr = listener.local_addr().unwrap();
    // Never accepted: these fill the queue.
    let mut held = Vec::new();
    for _ in 0..4 {
        if let Ok(Ok(s)) = tokio::time::timeout(
            Duration::from_millis(200),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            held.push(s);
        }
    }
    (format!("http://{addr}"), held, listener)
}

#[tokio::test]
async fn a_target_that_drops_packets_is_given_up_on_after_the_connect_timeout() {
    let a = up("a").await;
    let (hole, _held, _listener) = blackhole().await;
    let mut c = cfg(&[&hole, &a.url]);
    c.validation.upstream_connect_timeout = "300ms".into();
    let edge = edge(c).await;
    let started = Instant::now();
    assert_eq!(get_body(&edge).await, (200, "a:0".into()));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(3),
        "the connect timeout, not the 30s upstream_timeout: {took:?}"
    );
    assert_eq!(requests(&edge.metrics, &hole, "connect_error"), 1);
}

/// An `https://` upstream whose certificate `ca` issued for `localhost`.
async fn tls_up(dir: &Dir, ca: &Ca) -> (String, watch::Sender<bool>) {
    edgeguard::tls::init_crypto();
    let (cert, key) = dir.pair("up", &ca.server(&["localhost"]));
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    let tls = edgeguard::tls::server_config(store).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, rx) = watch::channel(false);
    let app = Router::new().fallback(|| async { "tls:0" });
    tokio::spawn(edgeguard::serve::serve(
        listener,
        Some(tls),
        app,
        edgeguard::serve::ServeOpts::default(),
        rx,
    ));
    (format!("https://localhost:{port}"), stop)
}

#[tokio::test]
async fn each_https_target_takes_its_own_upstream_tls_settings() {
    let dir = Dir::new();
    let ca = Ca::new("private CA");
    let (secure, _stop) = tls_up(&dir, &ca).await;
    let a = up("a").await;

    // Without its CA, the TLS target fails its handshake: retried on the next, like a refusal.
    let edge = edge(cfg(&[&secure, &a.url])).await;
    assert_eq!(get_body(&edge).await.1, "a:0");
    assert_eq!(requests(&edge.metrics, &secure, "tls_error"), 1);

    let mut c = cfg(&[&dead().await, &secure]);
    c.upstream_tls.targets = vec![UpstreamTlsTarget {
        target: secure.clone(),
        ca_path: dir.write("ca.pem", &ca.pem),
        ..Default::default()
    }];
    let edge = self::edge(c).await;
    assert_eq!(get_body(&edge).await, (200, "tls:0".into()));
}

/// A management port on TLS, its certificate from `ca`, answering `GET /healthz` with `200`.
async fn tls_health(dir: &Dir, ca: &Ca) -> (u16, watch::Sender<bool>) {
    tls_health_at(dir, ca, ("127.0.0.1", 0)).await
}

/// [`tls_health`] on `addr`. Its certificate names `localhost` only.
async fn tls_health_at(dir: &Dir, ca: &Ca, addr: (&str, u16)) -> (u16, watch::Sender<bool>) {
    edgeguard::tls::init_crypto();
    let (cert, key) = dir.pair("mgmt", &ca.server(&["localhost"]));
    let store =
        edgeguard::certstore::CertStore::load(&cert, &key, edgeguard::certstore::CertSource::File)
            .unwrap();
    let tls = edgeguard::tls::server_config(store).unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, rx) = watch::channel(false);
    let app = Router::new().route("/healthz", get(|| async { StatusCode::OK }));
    tokio::spawn(edgeguard::serve::serve(
        listener,
        Some(tls),
        app,
        edgeguard::serve::ServeOpts::default(),
        rx,
    ));
    (port, stop)
}

/// The check dials the management port, but verifies as requests to the target do: with the
/// target's own `[[upstream_tls.targets]]` entry, not the defaults the port alone would get.
#[tokio::test]
async fn a_check_on_another_port_keeps_the_targets_tls_settings() {
    let dir = Dir::new();
    let ca = Ca::new("private CA");
    let (secure, _stop) = tls_up(&dir, &ca).await;
    let (port, _mgmt) = tls_health(&dir, &ca).await;
    let mut c = checked(cfg(&[&secure]));
    c.upstreams[0].health_check.port = port;
    c.upstream_tls.targets = vec![UpstreamTlsTarget {
        target: secure.clone(),
        ca_path: dir.write("ca.pem", &ca.pem),
        ..Default::default()
    }];
    let edge = edge(c).await;
    let passes = format!(
        "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{secure}\",result=\"pass\"}}"
    );
    until("checks on the TLS management port pass", || {
        series(&edge.metrics, &passes).unwrap_or(0) >= 2
    })
    .await;
    assert_eq!(last_check(&edge, &secure).await, "answered 200");
    assert_eq!(get_body(&edge).await, (200, "tls:0".into()));
}

/// A plain-HTTP management port answering `GET /healthz` with `200`.
async fn plain_health() -> u16 {
    let app = Router::new().route("/healthz", get(|| async { StatusCode::OK }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

#[tokio::test]
async fn a_tls_target_can_be_checked_on_a_plain_http_management_port() {
    let dir = Dir::new();
    let ca = Ca::new("private CA");
    let (secure, _stop) = tls_up(&dir, &ca).await;
    let port = plain_health().await;
    let with_scheme = |scheme: &str| {
        let mut c = checked(cfg(&[&secure]));
        c.upstreams[0].health_check.port = port;
        c.upstreams[0].health_check.scheme = scheme.into();
        c.upstream_tls.targets = vec![UpstreamTlsTarget {
            target: secure.clone(),
            ca_path: dir.write("ca.pem", &ca.pem),
            ..Default::default()
        }];
        c
    };
    let edge = edge(with_scheme("http")).await;
    until("the plain-HTTP check passes", || {
        in_rotation_is(&edge.metrics, &secure, 1)
            && series(
                &edge.metrics,
                &format!(
                    "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{secure}\",result=\"pass\"}}"
                ),
            )
            .unwrap_or(0)
                >= 2
    })
    .await;
    assert_eq!(last_check(&edge, &secure).await, "answered 200");
    assert_eq!(
        get_body(&edge).await,
        (200, "tls:0".into()),
        "requests still go over TLS"
    );

    // Over the target's own scheme, the check speaks TLS to a port that does not.
    let tls_check = self::edge(with_scheme("")).await;
    until("out", || in_rotation_is(&tls_check.metrics, &secure, 0)).await;
    assert_ne!(last_check(&tls_check, &secure).await, "answered 200");
}

#[tokio::test]
async fn a_plain_target_can_be_checked_over_https() {
    let dir = Dir::new();
    let ca = Ca::new("management CA");
    let a = up("a").await;
    // By the name the management certificate carries.
    let target = a.url.replace("127.0.0.1", "localhost");
    let (port, _mgmt) = tls_health(&dir, &ca).await;
    let with_scheme = |scheme: &str| {
        let mut c = checked(cfg(&[&target]));
        c.upstreams[0].health_check.port = port;
        c.upstreams[0].health_check.scheme = scheme.into();
        // The target has no TLS settings of its own: the check takes [upstream_tls]'s.
        c.upstream_tls.ca_path = dir.write("ca.pem", &ca.pem);
        c
    };
    let edge = edge(with_scheme("https")).await;
    until("the TLS check passes", || {
        series(
            &edge.metrics,
            &format!(
                "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{target}\",result=\"pass\"}}"
            ),
        )
        .unwrap_or(0)
            >= 2
    })
    .await;
    assert_eq!(last_check(&edge, &target).await, "answered 200");
    let j = status(&edge).await;
    assert_eq!(route_named(&j, "app")["health_check"]["scheme"], "https");

    let plain_check = self::edge(with_scheme("")).await;
    until("out", || in_rotation_is(&plain_check.metrics, &target, 0)).await;

    // The CA in an entry for where the check goes, not in [upstream_tls]: the check, dialling
    // that host and port, takes it.
    let mut c = with_scheme("https");
    c.upstream_tls.ca_path.clear();
    c.upstream_tls.targets = vec![UpstreamTlsTarget {
        target: format!("https://localhost:{port}"),
        ca_path: dir.write("entry-ca.pem", &ca.pem),
        ..Default::default()
    }];
    let by_entry = self::edge(c).await;
    until("the check passes with the entry's CA", || {
        series(
            &by_entry.metrics,
            &format!(
                "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{target}\",result=\"pass\"}}"
            ),
        )
        .unwrap_or(0)
            >= 2
    })
    .await;
}

/// A target's health on another address of the same machine: requests to `127.0.0.1`, its
/// health on `127.0.0.2` (both loopback on Linux), at the same port number.
#[tokio::test]
async fn a_check_can_go_to_another_host_of_the_target() {
    let a = up("a").await;
    let port: u16 = a.url.rsplit(':').next().unwrap().parse().unwrap();
    // It answers 200 only to the target's own name: the check sends that, not the address it
    // dials.
    let want = format!("127.0.0.1:{port}");
    let health = Router::new().route(
        "/healthz",
        get(move |headers: axum::http::HeaderMap| {
            let ok = headers.get("host").is_some_and(|h| *h == want.as_str());
            async move {
                if ok {
                    StatusCode::OK
                } else {
                    StatusCode::MISDIRECTED_REQUEST
                }
            }
        }),
    );
    let listener = TcpListener::bind(("127.0.0.2", port)).await.unwrap();
    tokio::spawn(async move { axum::serve(listener, health).await.unwrap() });
    // The request port has /healthz too; take it down, so only the other host can pass.
    a.health.store(503, Ordering::Relaxed);
    let with_host = |host: Option<&str>| {
        let mut c = checked(cfg(&[]));
        c.upstreams[0].targets = vec![TargetCfg {
            url: a.url.clone(),
            weight: None,
            check_host: host.map(str::to_string),
        }];
        c
    };
    let edge = edge(with_host(Some("127.0.0.2"))).await;
    let passes = format!(
        "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{}\",result=\"pass\"}}",
        a.url
    );
    until("checks at the other host pass", || {
        series(&edge.metrics, &passes).unwrap_or(0) >= 2
    })
    .await;
    assert!(in_rotation_is(&edge.metrics, &a.url, 1));
    let j = status(&edge).await;
    assert_eq!(
        target_named(route_named(&j, "app"), &a.url)["check_host"],
        "127.0.0.2"
    );

    let own = self::edge(with_host(None)).await;
    until("its own host says 503", || {
        in_rotation_is(&own.metrics, &a.url, 0)
    })
    .await;
}

/// Dialling an address the certificate does not name, the check still verifies the target's own
/// name, as the target's requests do: it is the same server. The health listens only on
/// 127.0.0.2, so a check that ignored `check_host` would go to 127.0.0.1 and be refused.
#[tokio::test]
async fn a_tls_check_at_another_host_verifies_the_targets_name() {
    let dir = Dir::new();
    let ca = Ca::new("private CA");
    // The target: https://localhost:<port>, listening on 127.0.0.1, its certificate for localhost.
    let (secure, _stop) = tls_up(&dir, &ca).await;
    let own_port: u16 = secure.rsplit(':').next().unwrap().parse().unwrap();
    let passes = format!(
        "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{secure}\",result=\"pass\"}}"
    );
    let with = |port: u16| {
        let mut c = checked(cfg(&[]));
        c.upstreams[0].targets = vec![TargetCfg {
            url: secure.clone(),
            weight: None,
            check_host: Some("127.0.0.2".into()),
        }];
        c.upstreams[0].health_check.port = port;
        c.upstream_tls.targets = vec![UpstreamTlsTarget {
            target: secure.clone(),
            ca_path: dir.write("ca.pem", &ca.pem),
            ..Default::default()
        }];
        c
    };

    // On another port of the other host.
    let (mgmt_port, _mgmt) = tls_health_at(&dir, &ca, ("127.0.0.2", 0)).await;
    let edge = edge(with(mgmt_port)).await;
    until(
        "the check at 127.0.0.2 passes, verified as localhost",
        || series(&edge.metrics, &passes).unwrap_or(0) >= 2,
    )
    .await;
    assert_eq!(last_check(&edge, &secure).await, "answered 200");

    // On the target's own port of the other host: the host alone keeps the target's settings.
    let (_, _same) = tls_health_at(&dir, &ca, ("127.0.0.2", own_port)).await;
    let same_port = self::edge(with(0)).await;
    until("the check on the target's port at 127.0.0.2 passes", || {
        series(&same_port.metrics, &passes).unwrap_or(0) >= 2
    })
    .await;
}

#[tokio::test]
async fn a_websocket_upgrade_fails_over_too() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo = ws_echo().await;
    let mut c = cfg(&[&dead().await, &echo]);
    c.validation.websocket_passthrough = true;
    let edge = edge(c).await;
    let mut s = tokio::net::TcpStream::connect(edge.url.trim_start_matches("http://"))
        .await
        .unwrap();
    s.write_all(b"GET /ws HTTP/1.1\r\nHost: edge\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_ne!(
            s.read(&mut byte).await.unwrap(),
            0,
            "closed before the head"
        );
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

/// Answers an `Upgrade` with `101`, then echoes.
async fn ws_echo() -> String {
    use axum::body::Body;
    use axum::http::{header, HeaderValue, Request, Response};
    async fn handler(req: Request<Body>) -> Response<Body> {
        let on_upgrade = hyper::upgrade::on(req);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if let Ok(upgraded) = on_upgrade.await {
                let mut io = hyper_util::rt::TokioIo::new(upgraded);
                let mut buf = [0u8; 64];
                while let Ok(n) = io.read(&mut buf).await {
                    if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        });
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        resp.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        resp.headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("echo"));
        resp
    }
    let app = Router::new().fallback(axum::routing::any(handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn only_pools_export_the_pool_series() {
    let a = up("a").await;
    let mut single = Config::default();
    single.server.upstream = a.url.clone();
    let edge = edge(single).await;
    get_body(&edge).await;
    let text = edge.metrics.render();
    assert!(!text.contains("edgeguard_upstream_in_rotation"));
    assert!(!text.contains("edgeguard_upstream_health_checks_total"));

    // A pool without active checks has the rotation gauge, not the check counter.
    let edge = self::edge(cfg(&[&a.url])).await;
    let text = edge.metrics.render();
    assert!(text.contains("# TYPE edgeguard_upstream_in_rotation gauge"));
    assert!(!text.contains("edgeguard_upstream_health_checks_total"));
}

fn ejections(metrics: &Metrics, upstream: &str, reason: &str) -> Option<u64> {
    series(
        metrics,
        &format!(
            "edgeguard_upstream_ejections_total{{route=\"app\",upstream=\"{upstream}\",reason=\"{reason}\"}}"
        ),
    )
}

#[tokio::test]
async fn a_target_answering_5xx_in_a_row_is_ejected_when_eject_after_5xx_is_set() {
    let (a, b) = (up("a").await, up("b").await);
    a.status.store(503, Ordering::Relaxed);
    let mut c = cfg(&[&a.url, &b.url]);
    c.upstreams[0].eject_after_5xx = 3;
    let edge = edge(c).await;
    // An answer is the target's to give: the client gets each 503, nothing is retried.
    for _ in 0..3 {
        assert_eq!(get_body(&edge).await, (503, "a:0".into()));
    }
    assert_eq!(b.hits.load(Ordering::Relaxed), 0);
    // The third ejected it.
    assert_eq!(get_body(&edge).await, (200, "b:0".into()));
    assert_eq!(ejections(&edge.metrics, &a.url, "http_5xx"), Some(1));
    assert_eq!(ejections(&edge.metrics, &a.url, "connect_error"), Some(0));
    assert_eq!(in_rotation(&edge.metrics, &a.url), Some(0));
    let j = status(&edge).await;
    let t = target_named(route_named(&j, "app"), &a.url);
    assert_eq!(t["ejected"]["reason"], "http_5xx");
    assert_eq!(t["ejections"]["http_5xx"], 1);

    // Off by default: the same answers eject nothing.
    let (a, b) = (up("a").await, up("b").await);
    a.status.store(500, Ordering::Relaxed);
    let edge = self::edge(cfg(&[&a.url, &b.url])).await;
    for _ in 0..10 {
        assert_eq!(get_body(&edge).await.0, 500);
    }
    assert_eq!(ejections(&edge.metrics, &a.url, "http_5xx"), Some(0));
}

#[tokio::test]
async fn with_round_robin_each_target_counts_only_its_own_answers() {
    let (a, b) = (up("a").await, up("b").await);
    a.status.store(500, Ordering::Relaxed);
    let mut c = cfg(&[&a.url, &b.url]);
    c.upstreams[0].balance = "round_robin".into();
    c.upstreams[0].eject_after_5xx = 2;
    let edge = edge(c).await;
    // a, b, a: a's second 500 in a row, though b answered 200 in between.
    let statuses: Vec<u16> = {
        let mut v = Vec::new();
        for _ in 0..3 {
            v.push(get_body(&edge).await.0);
        }
        v
    };
    assert_eq!(statuses, [500, 200, 500]);
    for _ in 0..4 {
        assert_eq!(get_body(&edge).await, (200, "b:0".into()));
    }
}

#[tokio::test]
async fn when_every_target_answers_5xx_the_last_one_stays_in_rotation() {
    let (a, b) = (up("a").await, up("b").await);
    a.status.store(500, Ordering::Relaxed);
    b.status.store(500, Ordering::Relaxed);
    let mut c = cfg(&[&a.url, &b.url]);
    c.upstreams[0].eject_after_5xx = 2;
    let edge = edge(c).await;
    for _ in 0..8 {
        assert_eq!(get_body(&edge).await.0, 500, "the app's own answer");
    }
    assert_eq!(ejections(&edge.metrics, &a.url, "http_5xx"), Some(1));
    assert_eq!(ejections(&edge.metrics, &b.url, "http_5xx"), Some(0));
    assert_eq!(in_rotation(&edge.metrics, &b.url), Some(1));
    // A broken app is not the edge's fault: it stays ready.
    let ready = reqwest::get(format!("{}/__edgeguard/ready", edge.url))
        .await
        .unwrap()
        .status();
    assert_eq!(ready, 200);
}

// ---- GET /__edgeguard/upstreams ---------------------------------------------------------------

async fn status(edge: &Edge) -> serde_json::Value {
    reqwest::get(format!("{}/__edgeguard/upstreams", edge.url))
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn route_named<'a>(j: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    j["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["route"] == name)
        .unwrap_or_else(|| panic!("no route {name}: {j}"))
}

fn target_named<'a>(route: &'a serde_json::Value, upstream: &str) -> &'a serde_json::Value {
    route["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["upstream"] == upstream)
        .unwrap_or_else(|| panic!("no target {upstream}: {route}"))
}

#[tokio::test]
async fn the_status_endpoint_says_which_targets_take_requests_and_why_not() {
    let (a, b, gone) = (up("a").await, up("b").await, dead().await);
    let mut c = checked(cfg(&[&gone, &a.url]));
    c.upstreams[0].backup = vec![b.url.clone().into()];
    // A plain prefix whose URL carries credentials: never shown.
    c.upstreams.push(UpstreamRoute {
        path: "/static/".into(),
        target: a.url.replace("http://", "http://deploy:hunter2@"),
        ..Default::default()
    });
    let edge = edge(c).await;
    assert_eq!(get_body(&edge).await.1, "a:0");
    until("gone failing its checks", || {
        in_rotation(&edge.metrics, &gone) == Some(0)
            && series(
                &edge.metrics,
                &format!(
                    "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{gone}\",result=\"fail\"}}"
                ),
            )
            .is_some_and(|n| n >= 2)
    })
    .await;

    let j = status(&edge).await;
    let default = &j["routes"][0];
    assert_eq!(default["route"], "default");
    assert_eq!(default["path"], serde_json::Value::Null);
    assert_eq!(default["pool"], false);
    assert!(
        default["targets"][0].get("in_rotation").is_none(),
        "nothing tracked"
    );

    let app = route_named(&j, "app");
    assert_eq!(app["path"], "/");
    assert_eq!(
        (&app["pool"], &app["balance"], &app["state"]),
        (
            &serde_json::json!(true),
            &serde_json::json!("priority"),
            &serde_json::json!("normal")
        )
    );
    assert_eq!(app["health_check"]["path"], "/healthz");
    assert_eq!(app["eject_after"], 1);
    assert_eq!(app["eject_for_s"], 30.0);

    let g = target_named(app, &gone);
    assert_eq!(g["in_rotation"], false);
    let left = g["ejected"]["remaining_s"].as_f64().unwrap();
    assert!(left > 0.0 && left <= 30.0, "{g}");
    assert!(
        g["last_connect_error"]["error"]
            .as_str()
            .unwrap()
            .contains("refused"),
        "{g}"
    );
    assert_eq!(g["health_check"]["passing"], false);
    assert_eq!(g["health_check"]["last"]["ok"], false);
    assert_eq!(g["requests"]["connect_error"], 1);

    let t = target_named(app, &a.url);
    assert_eq!(
        (&t["in_rotation"], &t["backup"]),
        (&serde_json::json!(true), &serde_json::json!(false))
    );
    assert_eq!(t["requests"]["ok"], 1);
    assert_eq!(t["health_check"]["last"]["result"], "answered 200");
    assert_eq!(t["ejected"], serde_json::Value::Null);
    assert_eq!(target_named(app, &b.url)["backup"], true);
    assert_eq!(target_named(app, &b.url)["requests"]["ok"], 0);

    let plain = route_named(&j, "/static/");
    assert_eq!(plain["pool"], false);
    assert!(
        !j.to_string().contains("hunter2"),
        "credentials in the status: {j}"
    );

    // The main targets out: only the backup takes requests. Then nothing does.
    a.health.store(503, Ordering::Relaxed);
    until("a out", || in_rotation(&edge.metrics, &a.url) == Some(0)).await;
    assert_eq!(route_named(&status(&edge).await, "app")["state"], "backup");
    b.health.store(503, Ordering::Relaxed);
    until("b out", || in_rotation(&edge.metrics, &b.url) == Some(0)).await;
    assert_eq!(route_named(&status(&edge).await, "app")["state"], "all_out");
}

#[tokio::test]
async fn reading_the_status_does_not_take_a_round_robin_turn() {
    let (a, b) = (up("a").await, up("b").await);
    let mut c = cfg(&[&a.url, &b.url]);
    c.upstreams[0].balance = "round_robin".into();
    let edge = edge(c).await;
    for _ in 0..3 {
        status(&edge).await;
    }
    assert_eq!(get_body(&edge).await.1, "a:0", "still the first turn");
    assert_eq!(get_body(&edge).await.1, "b:0");
}

#[tokio::test]
async fn in_split_mode_the_status_is_on_the_admin_listener_only() {
    let a = up("a").await;
    let state = build_state(Arc::new(cfg(&[&a.url]))).unwrap();
    let serve = |app: Router| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap()
        });
        addr
    };
    let public = serve(edgeguard::build_public_router(state.clone())).await;
    let admin = serve(edgeguard::build_admin_router(state)).await;
    let code = |addr: SocketAddr| async move {
        reqwest::get(format!("http://{addr}/__edgeguard/upstreams"))
            .await
            .unwrap()
            .status()
            .as_u16()
    };
    assert_eq!(code(public).await, 404);
    assert_eq!(code(admin).await, 200);
}

// ---- least_conn, growing ejections, expect_status ----------------------------------------------

/// An upstream whose `/hold` and `/stream` wait for `release` (the stream after its first chunk),
/// and whose other paths answer `<name>` at once.
struct Gated {
    url: String,
    release: Arc<tokio::sync::Notify>,
    hits: Arc<AtomicUsize>,
}

async fn gated(name: &'static str) -> Gated {
    use axum::body::Body;
    let release = Arc::new(tokio::sync::Notify::new());
    let hits = Arc::new(AtomicUsize::new(0));
    let (r1, r2, n) = (
        Arc::clone(&release),
        Arc::clone(&release),
        Arc::clone(&hits),
    );
    let app = Router::new()
        .route(
            "/hold",
            get(move || {
                let r = Arc::clone(&r1);
                async move {
                    r.notified().await;
                    "held"
                }
            }),
        )
        .route(
            "/stream",
            get(move || {
                let r = Arc::clone(&r2);
                async move {
                    let wait: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
                        Box::pin(async move { r.notified().await });
                    Body::new(GatedBody { sent: 0, wait })
                }
            }),
        )
        .fallback(move || {
            let n = Arc::clone(&n);
            async move {
                n.fetch_add(1, Ordering::Relaxed);
                name
            }
        });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Gated {
        url: format!("http://{addr}"),
        release,
        hits,
    }
}

/// `first,` at once, then `last` once `wait` is done.
struct GatedBody {
    sent: u8,
    wait: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}

impl hyper::body::Body for GatedBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
        use std::task::Poll;
        let chunk =
            |text: &'static str| Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(text)))));
        match self.sent {
            0 => {
                self.sent = 1;
                chunk("first,")
            }
            1 => match self.wait.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    self.sent = 2;
                    chunk("last")
                }
                Poll::Pending => Poll::Pending,
            },
            _ => Poll::Ready(None),
        }
    }
}

fn in_flight(metrics: &Metrics, upstream: &str) -> Option<u64> {
    series(
        metrics,
        &format!("edgeguard_upstream_in_flight{{route=\"app\",upstream=\"{upstream}\"}}"),
    )
}

#[tokio::test]
async fn least_conn_sends_requests_away_from_a_busy_target_until_its_exchange_ends() {
    let (a, b) = (gated("a").await, gated("b").await);
    let mut c = cfg(&[&a.url, &b.url]);
    c.upstreams[0].balance = "least_conn".into();
    let edge = edge(c).await;

    // The first request goes to a (all idle: taken in turn) and stays there.
    let url = format!("{}/hold", edge.url);
    let held = tokio::spawn(async move { reqwest::get(url).await.unwrap().text().await.unwrap() });
    until("a busy", || in_flight(&edge.metrics, &a.url) == Some(1)).await;
    for _ in 0..4 {
        assert_eq!(get_body(&edge).await.1, "b", "a is busy");
    }
    assert_eq!(a.hits.load(Ordering::Relaxed), 0);
    a.release.notify_one();
    assert_eq!(held.await.unwrap(), "held");
    until("a idle", || in_flight(&edge.metrics, &a.url) == Some(0)).await;
    assert_eq!(b.hits.load(Ordering::Relaxed), 4);
    let j = status(&edge).await;
    assert_eq!(route_named(&j, "app")["balance"], "least_conn");
    assert_eq!(target_named(route_named(&j, "app"), &a.url)["in_flight"], 0);
}

#[tokio::test]
async fn a_streamed_response_counts_until_its_last_byte() {
    let (a, b) = (gated("a").await, gated("b").await);
    let mut c = cfg(&[&a.url, &b.url]);
    c.upstreams[0].balance = "least_conn".into();
    c.validation.stream_responses = true;
    let edge = edge(c).await;
    let mut resp = reqwest::get(format!("{}/stream", edge.url)).await.unwrap();
    assert_eq!(resp.chunk().await.unwrap().unwrap(), "first,");
    // The headers and a chunk have arrived; the exchange is not over.
    assert_eq!(in_flight(&edge.metrics, &a.url), Some(1));
    assert_eq!(get_body(&edge).await.1, "b");
    a.release.notify_one();
    assert_eq!(resp.chunk().await.unwrap().unwrap(), "last");
    assert!(resp.chunk().await.unwrap().is_none());
    until("a idle", || in_flight(&edge.metrics, &a.url) == Some(0)).await;
}

#[tokio::test]
async fn a_websocket_tunnel_counts_until_it_closes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (one, two) = (ws_echo().await, ws_echo().await);
    let mut c = cfg(&[&one, &two]);
    c.upstreams[0].balance = "least_conn".into();
    c.validation.websocket_passthrough = true;
    let edge = edge(c).await;
    let mut s = tokio::net::TcpStream::connect(edge.url.trim_start_matches("http://"))
        .await
        .unwrap();
    s.write_all(b"GET /ws HTTP/1.1\r\nHost: edge\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_ne!(s.read(&mut byte).await.unwrap(), 0);
        head.push(byte[0]);
    }
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(in_flight(&edge.metrics, &one), Some(1), "open tunnel");
    drop(s);
    until("tunnel closed", || {
        in_flight(&edge.metrics, &one) == Some(0)
    })
    .await;
}

#[tokio::test]
async fn an_ejection_soon_after_the_last_lasts_longer() {
    let (a, gone) = (up("a").await, dead().await);
    let mut c = cfg(&[&gone, &a.url]);
    c.upstreams[0].eject_for = "200ms".into();
    // The streak is judged when the failure is seen, which on Windows is about two seconds after
    // the connect (the SYN is retried after the RST): a cap under that would end it every time.
    c.upstreams[0].eject_for_max = "5s".into();
    let edge = edge(c).await;
    let ejected = |j: &serde_json::Value| target_named(route_named(j, "app"), &gone).clone();

    assert_eq!(get_body(&edge).await.1, "a:0");
    let t = ejected(&status(&edge).await);
    assert_eq!(t["ejected"]["length_s"], 0.2);
    assert_eq!(t["ejections_in_a_row"], 1);

    until("back", || in_rotation(&edge.metrics, &gone) == Some(1)).await;
    assert_eq!(get_body(&edge).await.1, "a:0");
    let t = ejected(&status(&edge).await);
    assert_eq!(t["ejected"]["length_s"], 0.4, "twice as long");
    assert_eq!(t["ejections_in_a_row"], 2);
    assert_eq!(
        route_named(&status(&edge).await, "app")["eject_for_max_s"],
        5.0
    );
}

#[tokio::test]
async fn a_health_check_passes_only_on_expect_status() {
    let (a, b) = (up("a").await, up("b").await);
    let mut c = checked(cfg(&[&a.url, &b.url]));
    c.upstreams[0].health_check.expect_status = "204".into();
    // b's /healthz answers 204, a's 200: only b passes.
    b.health.store(204, Ordering::Relaxed);
    let edge = edge(c).await;
    until("a out", || in_rotation(&edge.metrics, &a.url) == Some(0)).await;
    assert_eq!(in_rotation(&edge.metrics, &b.url), Some(1));
    let j = status(&edge).await;
    let app = route_named(&j, "app");
    assert_eq!(app["health_check"]["expect_status"], "204");
    assert_eq!(
        target_named(app, &a.url)["health_check"]["last"]["result"],
        "answered 200, expected 204"
    );
    assert_eq!(get_body(&edge).await.1, "b:0");
}

fn hashing(targets: &[&str], on: &str) -> Config {
    let mut c = cfg(targets);
    c.upstreams[0].balance = "hash".into();
    c.upstreams[0].hash_on = on.into();
    c
}

async fn get_with(edge: &Edge, headers: &[(&str, &str)]) -> reqwest::Response {
    let mut req = reqwest::Client::new().get(format!("{}/orders", edge.url));
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    req.send().await.unwrap()
}

async fn body_with(edge: &Edge, headers: &[(&str, &str)]) -> String {
    get_with(edge, headers).await.text().await.unwrap()
}

#[tokio::test]
async fn hash_on_a_header_sends_each_key_to_one_target_and_spreads_the_keys() {
    let (a, b, c) = (up("a").await, up("b").await, up("c").await);
    let edge = edge(hashing(&[&a.url, &b.url, &c.url], "header:x-user")).await;
    let mut used = std::collections::BTreeSet::new();
    for user in 0..30 {
        let user = format!("user-{user}");
        let first = body_with(&edge, &[("x-user", &user)]).await;
        for _ in 0..2 {
            assert_eq!(
                body_with(&edge, &[("x-user", &user)]).await,
                first,
                "{user}"
            );
        }
        used.insert(first);
    }
    assert_eq!(used.len(), 3, "{used:?}");
    // Without the header, in turn.
    let mut keyless = Vec::new();
    for _ in 0..3 {
        keyless.push(body_with(&edge, &[]).await);
    }
    assert_eq!(keyless, ["a:0", "b:0", "c:0"]);
}

#[tokio::test]
async fn hash_on_a_query_parameter_keeps_each_value_on_one_target() {
    let (a, b, c) = (up("a").await, up("b").await, up("c").await);
    let edge = edge(hashing(&[&a.url, &b.url, &c.url], "query:tenant")).await;
    let at = |query: String| {
        let url = format!("{}/orders?{query}", edge.url);
        async move { reqwest::get(url).await.unwrap().text().await.unwrap() }
    };
    let mut used = std::collections::BTreeSet::new();
    for tenant in 0..30 {
        let first = at(format!("tenant=t{tenant}")).await;
        // Wherever it sits among the other parameters.
        assert_eq!(at(format!("page=2&tenant=t{tenant}&x=1")).await, first);
        used.insert(first);
    }
    assert_eq!(used.len(), 3, "{used:?}");
    let keyless = [
        at("page=1".into()).await,
        at("page=1".into()).await,
        at("tenant=".into()).await,
    ];
    assert_eq!(keyless, ["a:0", "b:0", "c:0"], "without it, in turn");
}

#[tokio::test]
async fn a_dead_targets_keys_go_where_a_pool_without_it_sends_them() {
    // Two edges with no state in common agree on every key, and a key whose target cannot be
    // reached moves to its next choice: where it goes when that target was never listed.
    let (a, b, gone) = (up("a").await, up("b").await, dead().await);
    let with_gone = edge(hashing(&[&a.url, &gone, &b.url], "header:x-user")).await;
    let without = edge(hashing(&[&a.url, &b.url], "header:x-user")).await;
    for user in 0..40 {
        let user = format!("user-{user}");
        let h = [("x-user", user.as_str())];
        assert_eq!(
            body_with(&with_gone, &h).await,
            body_with(&without, &h).await,
            "{user}"
        );
    }
    assert_eq!(
        requests(&with_gone.metrics, &gone, "connect_error"),
        1,
        "then ejected"
    );
}

#[tokio::test]
async fn hash_on_client_ip_follows_the_address_the_edge_resolved() {
    let (a, b) = (up("a").await, up("b").await);
    let mut c = hashing(&[&a.url, &b.url], "");
    c.server.trust_forwarded_for = true;
    let edge = edge(c).await;
    let mut used = std::collections::BTreeSet::new();
    for i in 1..=20 {
        let ip = format!("203.0.113.{i}");
        let first = body_with(&edge, &[("x-forwarded-for", &ip)]).await;
        assert_eq!(body_with(&edge, &[("x-forwarded-for", &ip)]).await, first);
        // What a client writes on the left, ahead of the balancer's entry, moves nothing: the
        // hash is on the address the balancer appended.
        for spoof in 1..=5 {
            let chain = format!("198.51.100.{spoof}, {ip}");
            assert_eq!(
                body_with(&edge, &[("x-forwarded-for", &chain)]).await,
                first,
                "{chain}"
            );
        }
        used.insert(first);
    }
    assert_eq!(used.len(), 2, "{used:?}");
}

/// An upstream that sets its own cookie, `app=<name>`.
async fn cookie_up(name: &'static str) -> String {
    let app = Router::new().fallback(move || async move {
        (
            [(axum::http::header::SET_COOKIE, format!("app={name}"))],
            format!("{name}:0"),
        )
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn sticky(targets: &[&str]) -> Config {
    let mut c = cfg(targets);
    c.upstreams[0].balance = "round_robin".into();
    c.upstreams[0].sticky_cookie = "eg".into();
    c
}

fn set_cookies(resp: &reqwest::Response) -> Vec<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn a_sticky_cookie_keeps_a_client_on_the_target_that_answered_it() {
    let (a, b) = (cookie_up("a").await, cookie_up("b").await);
    let edge = edge(sticky(&[&a, &b])).await;
    let first = get_with(&edge, &[]).await;
    let cookies = set_cookies(&first);
    let answered = first.text().await.unwrap();
    assert_eq!(
        cookies.len(),
        2,
        "the upstream's and the edge's: {cookies:?}"
    );
    assert!(cookies
        .iter()
        .any(|c| c.starts_with(&format!("app={}", &answered[..1]))));
    let eg = cookies
        .iter()
        .find(|c| c.starts_with("eg="))
        .unwrap_or_else(|| panic!("{cookies:?}"));
    assert!(eg.contains("; Path=/; HttpOnly; SameSite=Lax"), "{eg}");
    assert!(eg.contains("Secure"), "hardened like any cookie: {eg}");
    let pair = eg.split(';').next().unwrap().to_string();

    for _ in 0..4 {
        let resp = get_with(&edge, &[("cookie", &pair)]).await;
        let again = set_cookies(&resp);
        assert_eq!(
            resp.text().await.unwrap(),
            answered,
            "round-robin would alternate"
        );
        assert!(!again.iter().any(|c| c.starts_with("eg=")), "{again:?}");
    }
}

#[tokio::test]
async fn a_sticky_cookie_naming_a_target_out_of_rotation_is_replaced() {
    let (a, gone) = (up("a").await, dead().await);
    let edge = edge(sticky(&[&gone, &a.url])).await;
    let j = status(&edge).await;
    let app = route_named(&j, "app");
    assert_eq!(app["sticky_cookie"], "eg");
    let id = |url: &str| {
        target_named(app, url)["sticky_cookie_value"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let resp = get_with(&edge, &[("cookie", &format!("eg={}", id(&gone)))]).await;
    let cookies = set_cookies(&resp);
    assert_eq!(resp.text().await.unwrap(), "a:0");
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with(&format!("eg={};", id(&a.url)))),
        "{cookies:?}"
    );
}

#[tokio::test]
async fn a_websocket_upgrade_follows_the_sticky_cookie() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (one, two) = (ws_echo().await, ws_echo().await);
    let mut c = sticky(&[&one, &two]);
    c.validation.websocket_passthrough = true;
    let edge = edge(c).await;
    let j = status(&edge).await;
    let value = target_named(route_named(&j, "app"), &two)["sticky_cookie_value"]
        .as_str()
        .unwrap()
        .to_string();
    for _ in 0..3 {
        let mut s = tokio::net::TcpStream::connect(edge.url.trim_start_matches("http://"))
            .await
            .unwrap();
        s.write_all(
            format!(
                "GET /ws HTTP/1.1\r\nHost: edge\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\
                 Cookie: eg={value}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut head = [0u8; 12];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 101");
    }
    assert_eq!(requests(&edge.metrics, &two, "ok"), 3);
    assert_eq!(requests(&edge.metrics, &one, "ok"), 0);
}

#[tokio::test]
async fn a_websocket_upgrade_hashes_on_the_client_the_balancer_appended() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (one, two) = (ws_echo().await, ws_echo().await);
    let mut c = hashing(&[&one, &two], "");
    c.server.trust_forwarded_for = true;
    c.validation.websocket_passthrough = true;
    let edge = edge(c).await;
    // The same real client (the last entry), whatever it writes on the left: one target.
    for spoof in 1..=6 {
        let mut s = tokio::net::TcpStream::connect(edge.url.trim_start_matches("http://"))
            .await
            .unwrap();
        s.write_all(
            format!(
                "GET /ws HTTP/1.1\r\nHost: edge\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\
                 X-Forwarded-For: 198.51.100.{spoof}, 203.0.113.9\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut head = [0u8; 12];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 101");
    }
    let (a, b) = (
        requests(&edge.metrics, &one, "ok"),
        requests(&edge.metrics, &two, "ok"),
    );
    assert!((a, b) == (6, 0) || (a, b) == (0, 6), "{a}, {b}");
}

/// An upstream that records the `Cookie` header of every request it gets, answering a `101` to
/// an upgrade and a `200` otherwise.
async fn cookie_recorder() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use axum::body::Body;
    use axum::http::{header, HeaderValue, Request, Response};
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let record = Arc::clone(&seen);
    let app = Router::new().fallback(axum::routing::any(move |req: Request<Body>| {
        let record = Arc::clone(&record);
        async move {
            let cookie = req
                .headers()
                .get_all(header::COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect::<Vec<_>>()
                .join(" | ");
            record.lock().unwrap().push(cookie);
            let mut resp = Response::new(Body::from("ok"));
            if req.headers().contains_key(header::UPGRADE) {
                *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                resp.headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
                resp.headers_mut()
                    .insert(header::UPGRADE, HeaderValue::from_static("echo"));
            }
            resp
        }
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

#[tokio::test]
async fn a_sticky_cookie_can_last_a_while_and_be_kept_from_the_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (one, seen) = cookie_recorder().await;
    let mut c = sticky(&[&one]);
    c.upstreams[0].sticky_cookie_max_age = "8h".into();
    c.upstreams[0].sticky_cookie_strip = true;
    c.validation.websocket_passthrough = true;
    let edge = edge(c).await;

    let first = get_with(&edge, &[("cookie", "session=abc")]).await;
    let eg = set_cookies(&first)
        .into_iter()
        .find(|c| c.starts_with("eg="))
        .unwrap();
    assert!(eg.contains("; Max-Age=28800;"), "{eg}");
    let pair = eg.split(';').next().unwrap().to_string();

    get_with(
        &edge,
        &[("cookie", &format!("session=abc; {pair}; theme=dark"))],
    )
    .await;
    get_with(&edge, &[("cookie", &pair)]).await;
    // A WebSocket upgrade is stripped too.
    let mut s = tokio::net::TcpStream::connect(edge.url.trim_start_matches("http://"))
        .await
        .unwrap();
    s.write_all(
        format!(
            "GET /ws HTTP/1.1\r\nHost: edge\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\
             Cookie: {pair}; session=abc\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut head = [0u8; 12];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 101");

    assert_eq!(
        *seen.lock().unwrap(),
        ["session=abc", "session=abc; theme=dark", "", "session=abc"],
        "the upstream never sees eg"
    );
}

fn in_rotation_is(metrics: &Metrics, upstream: &str, want: u64) -> bool {
    in_rotation(metrics, upstream) == Some(want)
}

async fn last_check(edge: &Edge, upstream: &str) -> String {
    let j = status(edge).await;
    target_named(route_named(&j, "app"), upstream)["health_check"]["last"]["result"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn a_tcp_check_only_connects() {
    let a = up("a").await;
    let x = reserved();
    let url = format!("http://{}", x.local_addr().unwrap());
    let mut c = cfg(&[&url, &a.url]);
    c.upstreams[0].health_check = HealthCheckCfg {
        kind: "tcp".into(),
        interval: "50ms".into(),
        // Past the two seconds a refused connect takes on Windows, so it is reported as refused.
        timeout: "5s".into(),
        ..Default::default()
    };
    let edge = edge(c).await;
    until("refused connections take it out", || {
        in_rotation_is(&edge.metrics, &url, 0)
    })
    .await;
    assert!(last_check(&edge, &url).await.starts_with("connecting:"));
    // Listening, but never answering: an HTTP check would time out, and a TCP check passes.
    let _listening = x.listen(16).unwrap();
    until("accepted connections bring it back", || {
        in_rotation_is(&edge.metrics, &url, 1)
    })
    .await;
    assert_eq!(last_check(&edge, &url).await, "connected");
    assert_eq!(
        a.hits.load(Ordering::Relaxed),
        0,
        "no request to the other one"
    );
}

/// An upstream whose every answer is `200` with these chunks, sent apart so a reader gets each
/// as its own frame.
async fn saying(chunks: &[&str]) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let says = Arc::new(std::sync::Mutex::new(
        chunks.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let said = Arc::clone(&says);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let chunks = said.lock().unwrap().clone();
            tokio::spawn(async move {
                let (mut head, mut buf) = (Vec::new(), [0u8; 1024]);
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
                    )
                    .await;
                for c in chunks {
                    let _ = s
                        .write_all(format!("{:x}\r\n{c}\r\n", c.len()).as_bytes())
                        .await;
                    let _ = s.flush().await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let _ = s.write_all(b"0\r\n\r\n").await;
            });
        }
    });
    (url, says)
}

#[tokio::test]
async fn expect_body_takes_out_a_target_that_answers_200_while_saying_it_is_down() {
    // The other target passes the same check: it says so in one frame.
    let (b, _) = saying(&["{\"status\":\"ok\",\"name\":\"b\"}"]).await;
    // The text it looks for arrives split over two frames.
    let (x, says) = saying(&["{\"status\":", "\"ok\"}"]).await;
    let mut c = checked(cfg(&[&x, &b]));
    c.upstreams[0].health_check.expect_body = "\"status\":\"ok\"".into();
    let edge = edge(c).await;
    let passes = format!(
        "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{x}\",result=\"pass\"}}"
    );
    until("checks pass", || {
        series(&edge.metrics, &passes).unwrap_or(0) >= 2
    })
    .await;
    assert_eq!(
        last_check(&edge, &x).await,
        "answered 200 with \"\\\"status\\\":\\\"ok\\\"\""
    );
    assert!(in_rotation_is(&edge.metrics, &x, 1));

    *says.lock().unwrap() = vec!["{\"status\":\"degraded\"}".into()];
    until("a 200 saying otherwise takes it out", || {
        in_rotation_is(&edge.metrics, &x, 0)
    })
    .await;
    assert!(last_check(&edge, &x).await.contains("do not contain"));
    assert!(in_rotation_is(&edge.metrics, &b, 1));
    assert_eq!(
        get_body(&edge).await,
        (200, "{\"status\":\"ok\",\"name\":\"b\"}".into())
    );

    *says.lock().unwrap() = vec!["{\"status\":\"ok\"}".into()];
    until("back", || in_rotation_is(&edge.metrics, &x, 1)).await;
    // Past the first 64 KiB is not looked at: here it ends 8 bytes in.
    *says.lock().unwrap() = vec!["x".repeat(65_536 - 8), "\"status\":\"ok\"".into()];
    until("too late in the body", || {
        in_rotation_is(&edge.metrics, &x, 0)
    })
    .await;
    assert!(last_check(&edge, &x)
        .await
        .contains("first 65536 bytes do not contain"));
}

#[tokio::test]
async fn expect_body_regex_judges_the_whole_body_as_read() {
    let (b, _) = saying(&["{\"status\":\"ok\"}"]).await;
    let (x, says) = saying(&["{\"status\": ", "\"degraded\"}"]).await;
    let mut c = checked(cfg(&[&x, &b]));
    c.upstreams[0].health_check.expect_body_regex = r#""status":\s*"(ok|degraded)""#.into();
    let edge = edge(c).await;
    let passes = format!(
        "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{x}\",result=\"pass\"}}"
    );
    until("checks pass", || {
        series(&edge.metrics, &passes).unwrap_or(0) >= 2
    })
    .await;
    assert!(
        last_check(&edge, &x)
            .await
            .starts_with("answered 200 matching"),
        "{}",
        last_check(&edge, &x).await
    );
    *says.lock().unwrap() = vec!["{\"status\":\"down\"}".into()];
    until("a body that does not match takes it out", || {
        in_rotation_is(&edge.metrics, &x, 0)
    })
    .await;
    assert!(last_check(&edge, &x).await.contains("do not match"));
    assert!(in_rotation_is(&edge.metrics, &b, 1));
}

#[tokio::test]
async fn an_anchored_regex_is_not_passed_by_the_start_of_a_longer_body() {
    // `ok$` would match the first frame alone; the body goes on.
    let (x, says) = saying(&["ok", ", then not"]).await;
    let a = up("a").await;
    let mut c = checked(cfg(&[&x, &a.url]));
    c.upstreams[0].health_check.expect_body_regex = "^ok$".into();
    let edge = edge(c).await;
    until("out", || in_rotation_is(&edge.metrics, &x, 0)).await;
    assert!(last_check(&edge, &x)
        .await
        .contains("first 12 bytes do not match"));
    // The same text, whole, in two frames.
    *says.lock().unwrap() = vec!["o".into(), "k".into()];
    until("back", || in_rotation_is(&edge.metrics, &x, 1)).await;
}

/// An upstream whose health endpoint answers `200` only to `HEAD /healthz` with `Host:
/// app.internal`, `404` to anything else, recording each request's head.
async fn picky() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let heads: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::clone(&heads);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let (mut head, mut buf) = (Vec::new(), [0u8; 1024]);
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let ok = head.starts_with("head /healthz ")
                    && head.contains("\r\nhost: app.internal\r\n");
                seen.lock().unwrap().push(head);
                let status = if ok { "200 OK" } else { "404 Not Found" };
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (url, heads)
}

#[tokio::test]
async fn a_check_sends_its_method_and_headers() {
    let (x, heads) = picky().await;
    let a = up("a").await;
    let mut c = checked(cfg(&[&x, &a.url]));
    c.upstreams[0].health_check.method = "HEAD".into();
    c.upstreams[0].health_check.headers = vec![
        ("Host".into(), "app.internal".into()),
        ("X-Probe".into(), "edge".into()),
    ];
    let edge = edge(c).await;
    let passes = format!(
        "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{x}\",result=\"pass\"}}"
    );
    until("checks pass", || {
        series(&edge.metrics, &passes).unwrap_or(0) >= 2
    })
    .await;
    let head = heads.lock().unwrap()[0].clone();
    assert!(head.contains("\r\nx-probe: edge\r\n"), "{head}");
    assert!(
        head.contains("\r\nuser-agent: edgeguard-health-check/"),
        "{head}"
    );
    let j = status(&edge).await;
    assert_eq!(route_named(&j, "app")["health_check"]["method"], "HEAD");

    // The same target, checked with a plain GET, fails.
    let (y, _) = picky().await;
    let edge = edge_plain_check(&y, &a.url).await;
    until("out", || in_rotation_is(&edge.metrics, &y, 0)).await;
    assert_eq!(
        last_check(&edge, &y).await,
        "answered 404, expected 200-399"
    );
}

async fn edge_plain_check(x: &str, other: &str) -> Edge {
    edge(checked(cfg(&[x, other]))).await
}

/// An app with requests on one port and its health on another: the request port has no
/// `/healthz` (`404`), the management port answers it with `health`. Returns the request URL and
/// the management port.
async fn managed(health: Arc<AtomicU16>) -> (String, u16, watch::Sender<bool>) {
    let traffic = Router::new()
        .route("/healthz", get(|| async { StatusCode::NOT_FOUND }))
        .fallback(|| async { "x:0" });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, traffic).await.unwrap() });
    let management = Router::new().route(
        "/healthz",
        get(move || {
            let h = Arc::clone(&health);
            async move { StatusCode::from_u16(h.load(Ordering::Relaxed)).unwrap() }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        axum::serve(listener, management)
            .with_graceful_shutdown(async move {
                let _ = rx.changed().await;
            })
            .await
            .unwrap()
    });
    (url, port, stop)
}

#[tokio::test]
async fn a_check_can_go_to_another_port_of_the_target() {
    let health = Arc::new(AtomicU16::new(200));
    let (x, port, _stop) = managed(Arc::clone(&health)).await;
    let mut c = checked(cfg(&[&x]));
    c.upstreams[0].health_check.port = port;
    let edge = edge(c).await;
    let passes = format!(
        "edgeguard_upstream_health_checks_total{{route=\"app\",upstream=\"{x}\",result=\"pass\"}}"
    );
    until("checks on the management port pass", || {
        series(&edge.metrics, &passes).unwrap_or(0) >= 2
    })
    .await;
    assert!(in_rotation_is(&edge.metrics, &x, 1));
    assert_eq!(last_check(&edge, &x).await, "answered 200");
    // The target is still named by the port requests go to.
    assert_eq!(get_body(&edge).await, (200, "x:0".into()));
    let j = status(&edge).await;
    assert_eq!(route_named(&j, "app")["health_check"]["port"], port);

    health.store(503, Ordering::Relaxed);
    until("the management port says it is down", || {
        in_rotation_is(&edge.metrics, &x, 0)
    })
    .await;
    assert_eq!(
        last_check(&edge, &x).await,
        "answered 503, expected 200-399"
    );

    // Checked on its own port, the same target fails: that port has no /healthz.
    let plain = edge_plain_check(&x, &up("a").await.url).await;
    until("404 on the request port", || {
        in_rotation_is(&plain.metrics, &x, 0)
    })
    .await;
    assert_eq!(
        last_check(&plain, &x).await,
        "answered 404, expected 200-399"
    );
}

#[tokio::test]
async fn a_tcp_check_can_go_to_another_port_of_the_target() {
    let (x, port, stop) = managed(Arc::new(AtomicU16::new(200))).await;
    let mut c = cfg(&[&x]);
    c.upstreams[0].health_check = HealthCheckCfg {
        kind: "tcp".into(),
        port,
        interval: "50ms".into(),
        // Past the two seconds a refused connect takes on Windows, so it is reported as refused.
        timeout: "5s".into(),
        ..Default::default()
    };
    let edge = edge(c).await;
    until("connected", || in_rotation_is(&edge.metrics, &x, 1)).await;
    assert_eq!(last_check(&edge, &x).await, "connected");
    // The management port closes; the request port still listens.
    stop.send(true).unwrap();
    until("refused on the management port", || {
        in_rotation_is(&edge.metrics, &x, 0)
    })
    .await;
    assert!(last_check(&edge, &x).await.starts_with("connecting:"));
}

#[tokio::test]
async fn a_target_that_never_finishes_its_tls_handshake_is_given_up_on_after_the_connect_timeout() {
    // It accepts the connection, then says nothing: no ServerHello ever comes.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stalled = format!("https://{}", silent.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = silent.accept().await {
            held.push(s);
        }
    });
    let a = up("a").await;
    let mut c = cfg(&[&stalled, &a.url]);
    c.validation.upstream_connect_timeout = "300ms".into();
    let edge = edge(c).await;
    let started = Instant::now();
    assert_eq!(get_body(&edge).await, (200, "a:0".into()));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(3),
        "the connect timeout, not the 30s upstream_timeout: {took:?}"
    );
    assert_eq!(requests(&edge.metrics, &stalled, "connect_error"), 1);
    assert_eq!(in_rotation(&edge.metrics, &stalled), Some(0), "ejected");
}
