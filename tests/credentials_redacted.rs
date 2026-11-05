//! Credentials in a configured URL (`http://user:pass@host`) never reach a log line, the status
//! page or `doctor`'s output: the upstream failure warnings, a pool's failover and health-check
//! logs, `/__edgeguard/upstreams`, and the errors a bad target URL raises.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use edgeguard::config::{Config, HealthCheckCfg, UpstreamRoute};
use edgeguard::{build_router, build_state};
use tokio::net::TcpListener;
use tokio::sync::watch;

const SECRET: &str = "secretpw";

/// Every log line written while it is installed (this thread's default subscriber; a
/// `#[tokio::test]` runs its tasks on one thread).
///
/// The limit of that: a line logged on another thread (the blocking pool, e.g. a DNS lookup)
/// goes to the global subscriber and is not captured, so these tests use IP literals and assert
/// that the warning they look for *was* captured before asserting what it lacks. The tests that
/// run the binary ([`run_bounded`]) read the whole process's output instead.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        let out = self.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || out.clone())
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// The pipeline on a listener, with the health checker running as `main` runs it.
async fn edge(cfg: Config) -> (String, watch::Sender<bool>) {
    let state = build_state(Arc::new(cfg)).unwrap();
    let (stop, rx) = watch::channel(false);
    edgeguard::pool::spawn_health_checks(&state, rx);
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
    (format!("http://{addr}"), stop)
}

fn base() -> Config {
    let mut cfg = Config::default();
    cfg.ratelimit.enabled = false;
    cfg.auth.mode = "none".into();
    cfg
}

/// A port bound and never listening: connections are refused.
fn refused() -> String {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    format!("http://user:{SECRET}@127.0.0.1:{port}")
}

/// A port that accepts connections and never answers: requests time out.
async fn blackhole() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });
    format!("http://user:{SECRET}@{addr}")
}

async fn status_of(url: String) -> u16 {
    reqwest::get(url).await.unwrap().status().as_u16()
}

#[tokio::test]
async fn an_unreachable_or_timed_out_upstream_logs_no_password() {
    let logs = Captured::default();
    let _guard = logs.install();

    let mut cfg = base();
    cfg.server.upstream = refused();
    let (url, _stop) = edge(cfg).await;
    assert_eq!(status_of(format!("{url}/orders?page=2")).await, 502);

    let mut cfg = base();
    cfg.server.upstream = blackhole().await;
    cfg.validation.upstream_timeout = "300ms".into();
    let (url, _stop2) = edge(cfg).await;
    assert_eq!(status_of(format!("{url}/orders")).await, 504);

    let text = logs.text();
    assert!(text.contains("upstream unreachable"), "{text}");
    assert!(text.contains("upstream timed out"), "{text}");
    // Every level, the HTTP client's own trace logs included: the request is built from the URL
    // without its credentials.
    assert!(!text.contains(SECRET), "{text}");
    assert!(!text.contains("//user:"), "{text}");
}

#[tokio::test]
async fn an_at_sign_in_the_path_keeps_the_upstream_host_in_the_warning() {
    let logs = Captured::default();
    let _guard = logs.install();
    let mut cfg = base();
    cfg.server.upstream = refused();
    let host = cfg.server.upstream.rsplit('@').next().unwrap().to_string();
    let (url, _stop) = edge(cfg).await;
    assert_eq!(status_of(format!("{url}/u/bob@example.com")).await, 502);
    let text = logs.text();
    // Only the configured URL is redacted, never the client's path: an email address in it does
    // not swallow the host the edge failed to reach.
    assert!(
        text.contains(&format!("http://{host}/u/bob@example.com")),
        "{text}"
    );
    assert!(!text.contains(SECRET), "{text}");
}

#[tokio::test]
async fn a_pools_failover_health_checks_and_status_page_show_no_password() {
    let logs = Captured::default();
    let _guard = logs.install();

    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live = up.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(up, axum::Router::new().fallback(|| async { "ok" }))
            .await
            .unwrap()
    });
    let mut cfg = base();
    cfg.upstreams = vec![UpstreamRoute {
        path: "/".into(),
        name: "app".into(),
        targets: vec![
            refused().as_str().into(),
            format!("http://user:{SECRET}@{live}").as_str().into(),
        ],
        ..Default::default()
    }];
    let (url, _stop) = edge(cfg.clone()).await;
    // The first target refuses: the request fails over, and the failure is logged.
    assert_eq!(status_of(format!("{url}/x")).await, 200);
    let status = reqwest::get(format!("{url}/__edgeguard/upstreams"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(status.contains("last_connect_error"), "{status}");
    assert!(!status.contains(SECRET), "{status}");

    // Active health checks against a target that refuses.
    let mut checked = cfg;
    checked.upstreams[0].health_check = HealthCheckCfg {
        path: "/healthz".into(),
        interval: "50ms".into(),
        timeout: "1s".into(),
        healthy_after: 2,
        unhealthy_after: 1,
        ..Default::default()
    };
    let (url, _stop2) = edge(checked).await;
    // A refused connect takes about 2 s on Windows: wait for the failure itself.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !logs
        .text()
        .contains("upstream target failed its health check")
    {
        assert!(tokio::time::Instant::now() < deadline, "{}", logs.text());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let status = reqwest::get(format!("{url}/__edgeguard/upstreams"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(status.contains("\"health_check\""), "{status}");
    assert!(!status.contains(SECRET), "{status}");

    let text = logs.text();
    assert!(text.contains("trying the next target"), "{text}");
    assert!(!text.contains(SECRET), "{text}");
}

/// Whether an upstream received credentials from a target URL's userinfo: what its requests and
/// health checks carried as `Authorization`.
#[tokio::test]
async fn an_upstream_gets_no_credentials_from_its_url_as_before() {
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let keep = Arc::clone(&seen);
    let app = axum::Router::new().fallback(
        move |uri: axum::http::Uri, headers: axum::http::HeaderMap| {
            let keep = Arc::clone(&keep);
            async move {
                let auth = headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_string())
                    .unwrap_or_else(|| "-".into());
                keep.lock().unwrap().push((uri.path().to_string(), auth));
                "ok"
            }
        },
    );
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live = up.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(up, app).await.unwrap() });
    let mut cfg = base();
    cfg.upstreams = vec![UpstreamRoute {
        path: "/".into(),
        name: "app".into(),
        targets: vec![format!("http://user:{SECRET}@{live}").as_str().into()],
        health_check: HealthCheckCfg {
            path: "/healthz".into(),
            interval: "50ms".into(),
            timeout: "1s".into(),
            ..Default::default()
        },
        ..Default::default()
    }];
    let (url, _stop) = edge(cfg).await;
    assert_eq!(status_of(format!("{url}/x")).await, 200);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !seen.lock().unwrap().iter().any(|(p, _)| p == "/healthz") {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no health check arrived"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let seen = seen.lock().unwrap().clone();
    assert!(seen.iter().any(|(p, _)| p == "/x"), "{seen:?}");
    // hyper sends no `Authorization` from URL userinfo, before and after it is stripped from the
    // target's URL: requests and checks alike reach the upstream without credentials.
    assert!(seen.iter().all(|(_, auth)| auth == "-"), "{seen:?}");
}

/// Runs the binary with `args` until it exits, `done` says so (it sees everything printed so
/// far, every 100 ms), or `limit` passes, then kills it: its exit status (`None` if it was still
/// running) and everything it printed. A server that should have refused to start cannot hang
/// the test.
fn run_bounded(
    args: &[&std::ffi::OsStr],
    env: &[(&str, &str)],
    limit: Duration,
    mut done: impl FnMut(&str) -> bool,
) -> (Option<std::process::ExitStatus>, String) {
    let dir = std::env::temp_dir().join(format!(
        "eg-redact-out-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (out, err) = (dir.join("out"), dir.join("err"));
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_edgeguard"))
        .args(args)
        .envs(env.iter().copied())
        .stdout(std::fs::File::create(&out).unwrap())
        .stderr(std::fs::File::create(&err).unwrap())
        .spawn()
        .unwrap();
    let printed = || {
        format!(
            "{}{}",
            std::fs::read_to_string(&out).unwrap_or_default(),
            std::fs::read_to_string(&err).unwrap_or_default()
        )
    };
    let deadline = std::time::Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline || done(&printed()) {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let text = printed();
    let _ = std::fs::remove_dir_all(&dir);
    (status, text)
}

/// The port of the `EdgeGuard listening` line's `listen` address, once it is printed.
fn listening_port(text: &str) -> Option<u16> {
    let line = text.lines().find(|l| l.contains("EdgeGuard listening"))?;
    let (_, rest) = line
        .split_once("\"listen\":\"")
        .or_else(|| line.split_once("listen="))?;
    let addr = rest.split(['"', ' ']).next()?;
    addr.rsplit(':').next()?.parse().ok()
}

#[test]
fn doctor_and_startup_errors_name_a_target_without_its_password() {
    let dir = std::env::temp_dir().join(format!("eg-redact-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("edgeguard.toml");
    // The same target twice: refused at load, naming it.
    std::fs::write(
        &cfg,
        format!(
            "[server]\nport = 0\n[[upstreams]]\npath = \"/\"\ntargets = [\"http://user:{SECRET}@app:1\", \
             \"http://user:{SECRET}@app:1\"]\n"
        ),
    )
    .unwrap();
    for args in [vec!["doctor", "--config"], vec!["--config"]] {
        let mut argv: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_ref()).collect();
        argv.push(cfg.as_os_str());
        let (status, text) = run_bounded(&argv, &[], Duration::from_secs(30), |_| false);
        // `None`: still running at the deadline, i.e. it served instead of refusing the config.
        assert!(status.is_some_and(|s| !s.success()), "{args:?}: {text}");
        assert!(text.contains("twice"), "{args:?}: {text}");
        assert!(text.contains("***@app:1"), "{args:?}: {text}");
        assert!(!text.contains(SECRET), "{args:?}: {text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_collector_that_fails_logs_no_password() {
    // Log shipping, span shipping and the OTLP metrics push all use reqwest, whose send error
    // quotes the URL ("error sending request for url (…)"; reqwest has already moved the userinfo
    // into Basic auth). Each failure warning also goes through `upstream::error_chain`, which
    // redacts any that remains. The whole process's output is read.
    // The edge binds port 0 and the test reads the port it got from its startup line. `dead`
    // is a port bound and released: nothing listens there, so every send is refused.
    let dead = {
        let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let dir = std::env::temp_dir().join(format!("eg-redact-collectors-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("edgeguard.toml");
    let collector = format!("http://user:{SECRET}@127.0.0.1:{dead}");
    std::fs::write(
        &cfg,
        format!(
            r#"[server]
port = 0
upstream = "http://127.0.0.1:{dead}"
[auth]
mode = "none"
[ratelimit]
enabled = false
[log.ship]
enabled = true
url = "{collector}/logs"
batch = 1
interval_secs = 1
[tracing]
enabled = true
endpoint = "{collector}/v1/traces"
sample_rate = 1.0
batch = 1
interval_secs = 1
[metrics.otlp]
enabled = true
endpoint = "{collector}/v1/metrics"
interval_secs = 1
"#
        ),
    )
    .unwrap();
    let failures = [
        "shipping a log batch failed",
        "shipping a span batch failed",
        "OTLP metrics push failed",
    ];
    // Until all three shippers have failed at least once: a request each round, so there are
    // log records and spans to ship. The limit only bounds a run that never gets there.
    let (_, text) = run_bounded(
        &["--config".as_ref(), cfg.as_os_str()],
        &[("RUST_LOG", "info,edgeguard=debug")],
        Duration::from_secs(60),
        |printed| {
            if let Some(port) = listening_port(printed) {
                if let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                    let request = b"GET / HTTP/1.1\r\nHost: edge\r\nConnection: close\r\n\r\n";
                    let _ = s.write_all(request);
                    let _ = std::io::Read::read_to_end(&mut s, &mut Vec::new());
                }
            }
            failures.iter().all(|f| printed.contains(f))
        },
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(listening_port(&text).is_some(), "{text}");
    for failed in failures {
        assert!(text.contains(failed), "no {failed:?} in: {text}");
    }
    assert!(text.contains("***@127.0.0.1"), "{text}");
    assert!(!text.contains(SECRET), "{text}");
}
