//! Managed mode's last-known-good policy (`control_plane.cache_path`,
//! `control_plane.boot_without_policy`), against a stub control plane and the real pipeline: a
//! restart while the control plane is down, the first pull after it, `refuse`, a config-file edit
//! under a pushed policy, and caches that must not be used.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::net::TcpListener;
use tokio::sync::watch;

use edgeguard::config::Config;
use edgeguard::cp::{poll_loop, CpClient};
use edgeguard::policy::{Policy, Pushed};
use edgeguard::{build_router, build_state};

/// A pushed policy this edge can tell apart from its local config: an API key is required.
const LOCKED: &str = "[auth]\nmode = \"apikey\"\napi_keys = [\"k1\"]\n";

/// What the stub control plane serves, and every `If-None-Match` it was sent.
#[derive(Default)]
struct CpState {
    policy: Option<(String, String)>,
    if_none_match: Vec<String>,
    served: usize,
}

struct StubCp {
    url: String,
    state: Arc<Mutex<CpState>>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl StubCp {
    async fn start(etag: &str, body: &str) -> StubCp {
        async fn policy(State(st): State<Arc<Mutex<CpState>>>, headers: HeaderMap) -> Response {
            let mut st = st.lock().unwrap();
            let inm = headers
                .get("if-none-match")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            if let Some(v) = &inm {
                st.if_none_match.push(v.clone());
            }
            match st.policy.clone() {
                Some((etag, _)) if inm.as_deref() == Some(etag.as_str()) => {
                    StatusCode::NOT_MODIFIED.into_response()
                }
                Some((etag, body)) => {
                    st.served += 1;
                    Json(serde_json::json!({ "etag": etag, "body": body })).into_response()
                }
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
        let state = Arc::new(Mutex::new(CpState {
            policy: Some((etag.into(), body.into())),
            ..Default::default()
        }));
        let app = Router::new()
            .route("/v3/edge/:tenant/policy", get(policy))
            .with_state(Arc::clone(&state));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (stop, mut rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.wait_for(|v| *v).await;
                })
                .await
                .unwrap();
        });
        StubCp {
            url,
            state,
            stop,
            task,
        }
    }

    /// Stop answering, for good: the port is closed when this returns.
    async fn shut_down(self) {
        let _ = self.stop.send(true);
        self.task.await.unwrap();
    }
}

async fn upstream() -> SocketAddr {
    let app = Router::new().fallback(|| async { "hello" });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// A managed-mode config: no auth locally, `cp_url`/tenant `t1`, the cache at `cache_path`.
fn managed(upstream: SocketAddr, cp_url: &str, cache_path: &str) -> Config {
    let mut cfg = Config::default();
    cfg.server.upstream = format!("http://{upstream}");
    cfg.auth.mode = "none".into();
    cfg.ratelimit.enabled = false;
    cfg.control_plane.enabled = true;
    cfg.control_plane.url = cp_url.into();
    cfg.control_plane.tenant_id = "t1".into();
    cfg.control_plane.edge_token = "edge-token".into();
    cfg.control_plane.cache_path = cache_path.into();
    cfg
}

/// The proxy, booted the way `main` boots it: state, then the policy (restoring the cache).
/// Returns its address, the policy, and what was restored.
async fn edge(cfg: Config) -> (SocketAddr, Arc<Policy>, Option<Pushed>) {
    let cfg = Arc::new(cfg);
    let state = build_state(Arc::clone(&cfg)).unwrap();
    let policy = Policy::new(cfg, state.runtime.clone(), state.policy_pending.clone()).unwrap();
    let restored = policy.restore_cached();
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
    (addr, policy, restored)
}

/// Run the poller for `cfg` against its control plane, until the returned sender is dropped.
fn poll(cfg: &Config, policy: &Arc<Policy>, etag: Option<String>) -> watch::Sender<bool> {
    let client = CpClient::from_cfg(&cfg.control_plane).unwrap().unwrap();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(poll_loop(
        client,
        Arc::clone(policy),
        Duration::from_millis(50),
        etag,
        rx,
    ));
    stop
}

async fn status(addr: SocketAddr, path: &str) -> u16 {
    reqwest::get(format!("http://{addr}{path}"))
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn until_status(addr: SocketAddr, want: u16) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while status(addr, "/").await != want {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("never answered {want}"));
}

fn scratch() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "eg-policy-cache-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn a_restart_while_the_control_plane_is_down_starts_on_the_cached_policy() {
    let dir = scratch();
    let cache = dir.join("policy.json").to_string_lossy().into_owned();
    let up = upstream().await;
    let cp = StubCp::start("\"v1\"", LOCKED).await;
    let cfg = managed(up, &cp.url, &cache);

    // First life: the pulled policy is applied and kept.
    let (first, policy, restored) = edge(cfg.clone()).await;
    assert!(restored.is_none(), "nothing cached yet");
    assert_eq!(status(first, "/").await, 200, "local config: no auth");
    let _poller = poll(&cfg, &policy, None);
    until_status(first, 401).await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the cache holds the policy's secrets");
    }

    // The control plane goes away, and the edge restarts.
    cp.shut_down().await;
    let (second, _, restored) = edge(cfg.clone()).await;
    assert_eq!(restored.map(|p| p.etag).as_deref(), Some("\"v1\""));
    assert_eq!(
        status(second, "/").await,
        401,
        "the pushed policy, not the config file"
    );

    // Without the cache, the same restart serves the looser local config: the gap this closes.
    let (uncached, _, _) = edge(managed(up, &cfg.control_plane.url, "")).await;
    assert_eq!(status(uncached, "/").await, 200);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_first_pull_after_a_restart_sends_the_cached_etag() {
    let dir = scratch();
    let cache = dir.join("policy.json").to_string_lossy().into_owned();
    let up = upstream().await;
    let cp = StubCp::start("\"v1\"", LOCKED).await;
    let cfg = managed(up, &cp.url, &cache);

    let (_, policy, _) = edge(cfg.clone()).await;
    policy
        .apply_pushed(Pushed {
            etag: "\"v1\"".into(),
            body: LOCKED.into(),
        })
        .unwrap();

    let (restarted, policy, restored) = edge(cfg.clone()).await;
    let _poller = poll(&cfg, &policy, restored.map(|p| p.etag));
    tokio::time::timeout(Duration::from_secs(5), async {
        while cp.state.lock().unwrap().if_none_match.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let (first_inm, served) = {
        let st = cp.state.lock().unwrap();
        (st.if_none_match[0].clone(), st.served)
    };
    assert_eq!(first_inm, "\"v1\"");
    assert_eq!(served, 0, "nothing changed, so a 304 and no policy body");
    assert_eq!(status(restarted, "/").await, 401);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn refuse_answers_503_until_a_policy_arrives() {
    let up = upstream().await;
    let mut cfg = managed(up, "http://127.0.0.1:9", "");
    cfg.control_plane.boot_without_policy = "refuse".into();
    let (addr, policy, _) = edge(cfg).await;

    let resp = reqwest::get(format!("http://{addr}/")).await.unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.headers()["retry-after"], "5");
    assert_eq!(status(addr, "/__edgeguard/ready").await, 503);
    assert_eq!(status(addr, "/__edgeguard/health").await, 200);
    // A config-file reload while waiting must not let the file's policy through.
    let mut edited = managed(up, "http://127.0.0.1:9", "");
    edited.control_plane.boot_without_policy = "refuse".into();
    policy.set_local(edited).unwrap();
    assert_eq!(status(addr, "/").await, 503);

    policy
        .apply_pushed(Pushed {
            etag: "\"v1\"".into(),
            body: LOCKED.into(),
        })
        .unwrap();
    assert_eq!(status(addr, "/").await, 401, "served, under the policy");
    assert_eq!(status(addr, "/__edgeguard/ready").await, 200);
}

#[tokio::test]
async fn refuse_with_a_cached_policy_serves_it_at_once() {
    let dir = scratch();
    let cache = dir.join("policy.json").to_string_lossy().into_owned();
    let up = upstream().await;
    let mut cfg = managed(up, "http://127.0.0.1:9", &cache);
    cfg.control_plane.boot_without_policy = "refuse".into();
    let (_, policy, _) = edge(cfg.clone()).await;
    policy
        .apply_pushed(Pushed {
            etag: "\"v1\"".into(),
            body: LOCKED.into(),
        })
        .unwrap();

    let (addr, policy, _) = edge(cfg).await;
    assert!(!policy.pending());
    assert_eq!(status(addr, "/").await, 401);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_config_file_edit_keeps_the_pushed_policy() {
    let up = upstream().await;
    let cfg = managed(up, "http://127.0.0.1:9", "");
    let (addr, policy, _) = edge(cfg.clone()).await;
    policy
        .apply_pushed(Pushed {
            etag: "\"v1\"".into(),
            body: LOCKED.into(),
        })
        .unwrap();
    assert_eq!(status(addr, "/").await, 401);

    // An edge-local edit. It used to rebuild from the file alone and drop the pushed auth until
    // the control plane published something new.
    let mut edited = cfg;
    edited.log.ship.queue_size = 1234;
    policy.set_local(edited).unwrap();
    assert_eq!(status(addr, "/").await, 401);
}

#[tokio::test]
async fn a_cache_for_another_tenant_or_one_that_does_not_parse_is_ignored() {
    let dir = scratch();
    let cache = dir.join("policy.json").to_string_lossy().into_owned();
    let up = upstream().await;
    let cfg = managed(up, "http://127.0.0.1:9", &cache);
    let (_, policy, _) = edge(cfg.clone()).await;
    policy
        .apply_pushed(Pushed {
            etag: "\"v1\"".into(),
            body: LOCKED.into(),
        })
        .unwrap();

    let mut other = cfg.clone();
    other.control_plane.tenant_id = "t2".into();
    let (addr, _, restored) = edge(other).await;
    assert!(
        restored.is_none(),
        "another tenant's policy is not this edge's"
    );
    assert_eq!(status(addr, "/").await, 200);

    std::fs::write(&cache, "{ not json").unwrap();
    let (addr, _, restored) = edge(cfg).await;
    assert!(restored.is_none());
    assert_eq!(status(addr, "/").await, 200, "a corrupt cache is not fatal");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_policy_the_edge_rejects_is_neither_applied_nor_cached() {
    let dir = scratch();
    let cache = dir.join("policy.json").to_string_lossy().into_owned();
    let up = upstream().await;
    let cfg = managed(up, "http://127.0.0.1:9", &cache);
    let (addr, policy, _) = edge(cfg.clone()).await;
    policy
        .apply_pushed(Pushed {
            etag: "\"v1\"".into(),
            body: LOCKED.into(),
        })
        .unwrap();
    let kept = std::fs::read_to_string(&cache).unwrap();

    let bad = Pushed {
        etag: "\"v2\"".into(),
        body: "[ratelimit]\nenabled = true\nrate = \"0/sec\"\n".into(),
    };
    assert!(policy.apply_pushed(bad).is_err());
    assert_eq!(status(addr, "/").await, 401, "still on v1");
    assert_eq!(
        std::fs::read_to_string(&cache).unwrap(),
        kept,
        "the cache still holds v1"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
