//! Upstream pools: several targets behind one `[[upstreams]]` prefix.
//!
//! Every route, the default included, is a [`Pool`]. One built from `target` has a single target
//! and keeps no health. One built from `targets` keeps a [`TargetHealth`] per target, from two
//! sources:
//!
//! * **Active:** [`spawn_health_checks`] asks for `health_check.path` on each target every
//!   `interval` (`GET`, or `method`, with `headers`), judging its status and, with `expect_body`
//!   or `expect_body_regex`, its body; or, with `type = "tcp"`, only connects. A target leaves rotation after `unhealthy_after` failures in a row, and
//!   returns after `healthy_after` passes.
//! * **Passive:** a request that fails to connect counts against its target. After `eject_after`
//!   in a row the target is out for `eject_for`. An answer, any answer, resets the count. With
//!   `eject_after_5xx`, so many `5xx` answers in a row eject it too, unless it is the last target
//!   in rotation: when every target answers `5xx`, taking them out cannot help.
//!
//! A request tries the targets in rotation in an order [`Pool::order_for`] gives: `targets` first,
//! then `backup`, each tier in the order listed (`balance = "priority"`), starting from the next
//! one in turn (`"round_robin"`), from the least loaded (`"least_conn"`), or by how a key the
//! request carries ranks them (`"hash"`: its address, path, a header, a cookie or a query
//! parameter). A `sticky_cookie` naming a target in rotation puts that target first; with
//! `sticky_cookie_strip` the upstream never sees it. A request moves to the next only when it could not connect, so nothing reached
//! the upstream, and only when its body can be sent again. When no target is in rotation it tries
//! them all, in the same order, anyway: a health check can be wrong, and refusing the request is
//! certain to be.
//!
//! A target's health lives as long as its route lists it. A config reload carries it over
//! ([`crate::proxy::Runtime::carry_health_from`]), so a reload neither forgets a dead target nor
//! restarts its checks.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, Uri};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{parse_duration, UpstreamRoute};
use crate::proxy::AppState;

/// One upstream a route can forward to.
#[derive(Clone, Debug)]
pub struct Target {
    /// The base URL without a trailing `/`: a request's path is appended to it.
    pub base: Arc<String>,
    /// As the logs and the per-upstream series name it (`scheme://host:port`).
    pub label: String,
    /// Listed under `backup`: only for when no other target will take the request.
    pub backup: bool,
    /// Its round-robin turns for each one a weight-1 target gets.
    pub weight: u32,
    /// A hash of `base`: what `balance = "hash"` ranks it by, and what a sticky cookie naming it
    /// holds. The same on every edge, so any of them reads another's cookie.
    pub id: u64,
    pub health: Arc<TargetHealth>,
}

/// `balance`: how a pool picks among its targets in rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Balance {
    /// The first in the order listed; the others stand by.
    Priority,
    /// Each in turn, as many turns as its weight.
    RoundRobin,
    /// The one with the fewest requests in flight for its weight; ties in turn.
    LeastConn,
    /// The one a key the request carries ranks first, so the same key goes to the same target
    /// while it is in rotation; requests without the key in turn.
    Hash,
}

impl Balance {
    pub fn label(self) -> &'static str {
        match self {
            Balance::Priority => "priority",
            Balance::RoundRobin => "round_robin",
            Balance::LeastConn => "least_conn",
            Balance::Hash => "hash",
        }
    }
}

/// `hash_on`: the key a `balance = "hash"` pool picks by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashOn {
    /// The client's address, as the edge resolved it (`trust_forwarded_for`, PROXY protocol).
    ClientIp,
    /// The request's path, without the query.
    Path,
    /// A request header's value.
    Header(HeaderName),
    /// A cookie's value.
    Cookie(String),
    /// A query parameter's value, as sent (not percent-decoded), the first if it repeats.
    Query(String),
}

impl HashOn {
    fn parse(text: &str) -> Result<HashOn> {
        let on = match text.split_once(':') {
            None if text == "client_ip" => HashOn::ClientIp,
            None if text == "path" => HashOn::Path,
            Some(("header", name)) => HashOn::Header(
                HeaderName::from_bytes(name.as_bytes())
                    .with_context(|| format!("{name:?} is not a header name"))?,
            ),
            Some(("cookie", name)) if is_cookie_name(name) => HashOn::Cookie(name.to_string()),
            Some(("cookie", name)) => anyhow::bail!("{name:?} is not a cookie name"),
            // Compared with the name as sent, so it must be one a query can carry as it is.
            Some(("query", name))
                if !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_graphic() && !b"&=#%+".contains(&b)) =>
            {
                HashOn::Query(name.to_string())
            }
            Some(("query", name)) => anyhow::bail!(
                "{name:?} is not a query parameter name this matches as sent: visible ASCII, \
                 without '&', '=', '#', '%' or '+'"
            ),
            _ => anyhow::bail!(
                "expected \"client_ip\", \"path\", \"header:<name>\", \"cookie:<name>\" or \
                 \"query:<name>\""
            ),
        };
        Ok(on)
    }

    pub fn label(&self) -> String {
        match self {
            HashOn::ClientIp => "client_ip".into(),
            HashOn::Path => "path".into(),
            HashOn::Header(name) => format!("header:{name}"),
            HashOn::Cookie(name) => format!("cookie:{name}"),
            HashOn::Query(name) => format!("query:{name}"),
        }
    }
}

/// `sticky_cookie`: the cookie that keeps a client on the target that answered it.
#[derive(Clone, Debug)]
struct Sticky {
    name: String,
    /// The route's prefix, as the cookie's `Path`, so each route keeps its own.
    path: String,
    /// `sticky_cookie_max_age`; `None` for a session cookie.
    max_age: Option<Duration>,
    /// `sticky_cookie_strip`.
    strip: bool,
}

/// What one request brings to its pool's pick: the key `hash_on` reads, and the target its
/// sticky cookie names. Empty for a pool that uses neither, so its requests read nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Affinity {
    key: Option<u64>,
    /// The [`Target::id`] of a target in this pool.
    stuck: Option<u64>,
}

/// A request in flight to a target of a `least_conn` pool: counted while this lives, which is
/// until the upstream's response has been read (streamed or not), or a tunnel to it has closed.
#[derive(Debug)]
pub struct InFlight(Arc<TargetHealth>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `health_check.type`: what a check asks of a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckKind {
    /// `GET path`, judged by its status and, with `expect_body`, its body.
    Http,
    /// A TCP connection to the target's host and port.
    Tcp,
}

/// How much of a check's answer `expect_body` looks through.
pub const CHECK_BODY_LIMIT: usize = 64 * 1024;

/// `[upstreams.health_check]`, parsed.
#[derive(Clone, Debug)]
pub struct HealthCheck {
    pub kind: CheckKind,
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub healthy_after: u32,
    pub unhealthy_after: u32,
    /// `expect_status` as written, for the logs and the status endpoint.
    pub expect_status: String,
    /// It parsed: inclusive ranges.
    expect: Vec<(u16, u16)>,
    /// Text the body must contain; empty for none.
    pub expect_body: String,
    /// The regular expression the body must match, as written; empty for none.
    pub expect_body_regex: String,
    /// What the body is checked for, if anything: one of the two above, compiled.
    body: Option<BodyMatch>,
    pub method: Method,
    /// `headers`, with the edge's `User-Agent` unless they name one.
    headers: HeaderMap,
    /// The names `headers` sets, lowercase and sorted, for the status endpoint: not the values,
    /// which may be a token.
    pub header_names: Vec<String>,
    /// `port`: the port each target is checked on, when not its own.
    pub port: Option<u16>,
}

/// What a check's body must hold.
#[derive(Clone, Debug)]
enum BodyMatch {
    /// `expect_body`: found as soon as it arrives.
    Text(Vec<u8>),
    /// `expect_body_regex`: searched once, in the body as read.
    Regex(regex::bytes::Regex),
}

/// Headers a check may not set: they describe a body or a connection the check does not have.
const CHECK_HEADERS_REFUSED: [&str; 9] = [
    "connection",
    "content-length",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "expect",
];

impl HealthCheck {
    /// What each check does, for the logs: `"GET /healthz"`, `"HEAD /"`, `"tcp"`, and on another
    /// port `"GET :8081/healthz"` or `"tcp :8081"`.
    pub fn label(&self) -> String {
        let port = self.port.map(|p| format!(":{p}")).unwrap_or_default();
        match self.kind {
            CheckKind::Http => format!("{} {port}{}", self.method, self.path),
            CheckKind::Tcp if port.is_empty() => "tcp".into(),
            CheckKind::Tcp => format!("tcp {port}"),
        }
    }

    /// The base URL `target` is checked at: its own, or with `port`, the same on that port.
    fn base_for(&self, target: &Target) -> String {
        match self.port {
            // `check_url` let the base in only with a scheme and a host, which is all this needs.
            Some(port) => on_port(&target.base, port).unwrap_or_else(|_| target.base.to_string()),
            None => target.base.to_string(),
        }
    }

    /// Whether a check answered `status` passes.
    pub fn passes(&self, status: u16) -> bool {
        self.expect
            .iter()
            .any(|(lo, hi)| (*lo..=*hi).contains(&status))
    }
}

/// `expect_body` or `expect_body_regex`, compiled: at most one.
fn check_body(hc: &crate::config::HealthCheckCfg) -> Result<Option<BodyMatch>> {
    match (hc.expect_body.as_str(), hc.expect_body_regex.as_str()) {
        ("", "") => Ok(None),
        (text, "") => Ok(Some(BodyMatch::Text(text.as_bytes().to_vec()))),
        ("", pattern) => regex::bytes::Regex::new(pattern)
            .map(|re| Some(BodyMatch::Regex(re)))
            .with_context(|| format!("health_check.expect_body_regex = {pattern:?}")),
        _ => anyhow::bail!("set health_check.expect_body or expect_body_regex, not both"),
    }
}

/// `method`, parsed. `HEAD` gets no body to check, and `CONNECT` asks for a tunnel.
fn check_method(hc: &crate::config::HealthCheckCfg) -> Result<Method> {
    let text = hc.method.trim().to_ascii_uppercase();
    let method = Method::from_bytes(text.as_bytes())
        .ok()
        .filter(|_| !text.is_empty())
        .with_context(|| format!("health_check.method = {:?} is not a method", hc.method))?;
    anyhow::ensure!(
        method != Method::CONNECT,
        "health_check.method = \"CONNECT\" asks for a tunnel, not an answer"
    );
    anyhow::ensure!(
        method != Method::HEAD || (hc.expect_body.is_empty() && hc.expect_body_regex.is_empty()),
        "health_check.method = \"HEAD\" gets no body, so it takes no expect_body or \
         expect_body_regex"
    );
    Ok(method)
}

/// `headers`, parsed, with the edge's `User-Agent` unless they name one.
fn check_headers(hc: &crate::config::HealthCheckCfg) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in &hc.headers {
        let header = HeaderName::from_bytes(name.trim().as_bytes())
            .with_context(|| format!("health_check.headers: {name:?} is not a header name"))?;
        anyhow::ensure!(
            !CHECK_HEADERS_REFUSED.contains(&header.as_str()),
            "health_check.headers: {name:?} describes a body or a connection, which the check \
             manages itself"
        );
        let value = HeaderValue::from_str(value).with_context(|| {
            format!("health_check.headers: the value for {name:?} is not a header value")
        })?;
        headers.append(header, value);
    }
    if !headers.contains_key(header::USER_AGENT) {
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static(concat!(
                "edgeguard-health-check/",
                env!("CARGO_PKG_VERSION")
            )),
        );
    }
    Ok(headers)
}

/// `expect_status`: `"200"`, `"200-299"`, `"2xx"`, comma-separated.
fn parse_statuses(text: &str) -> Result<Vec<(u16, u16)>> {
    let mut out = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        let code = |s: &str| -> Result<u16> {
            s.parse::<u16>()
                .ok()
                .filter(|c| (100..=599).contains(c))
                .with_context(|| format!("{s:?} is not an HTTP status (100-599)"))
        };
        let range = if let Some(class) = part.strip_suffix("xx") {
            let d = code(&format!("{class}00"))?;
            (d, d + 99)
        } else if let Some((lo, hi)) = part.split_once('-') {
            let (lo, hi) = (code(lo.trim())?, code(hi.trim())?);
            anyhow::ensure!(lo <= hi, "{part:?} runs backwards");
            (lo, hi)
        } else {
            let c = code(part)?;
            (c, c)
        };
        out.push(range);
    }
    Ok(out)
}

/// The upstreams of one route.
#[derive(Debug)]
pub struct Pool {
    /// The route's label, for the pool series and the logs.
    pub route: String,
    pub targets: Vec<Target>,
    /// Built from `targets`: health is kept and acted on.
    managed: bool,
    pub balance: Balance,
    /// Round-robin's turn: which target in rotation the next request starts from.
    turn: AtomicUsize,
    pub health_check: Option<HealthCheck>,
    eject_after: u32,
    eject_for: Duration,
    /// What `eject_for` grows to with ejections in a row.
    eject_for_max: Duration,
    eject_after_5xx: u32,
    /// Held while deciding a `5xx` ejection, so two targets crossing the threshold at once
    /// cannot both leave, the last one in rotation included.
    eject_lock: Mutex<()>,
    /// What `balance = "hash"` hashes; `None` for any other balance.
    pub hash_on: Option<HashOn>,
    sticky: Option<Sticky>,
}

/// Why a target was ejected: the `reason` of `edgeguard_upstream_ejections_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ejection {
    /// Requests failed to connect to it.
    ConnectError = 1,
    /// It answered `5xx`, `eject_after_5xx` times in a row.
    Http5xx = 2,
}

impl Ejection {
    pub const ALL: [Ejection; 2] = [Ejection::ConnectError, Ejection::Http5xx];

    pub fn label(self) -> &'static str {
        match self {
            Ejection::ConnectError => "connect_error",
            Ejection::Http5xx => "http_5xx",
        }
    }

    fn index(self) -> usize {
        self as usize - 1
    }
}

impl Pool {
    /// A route with one upstream and no health to keep: `server.upstream`, or a `target`.
    pub fn single(base: &str) -> Pool {
        Pool {
            route: crate::metrics::DEFAULT_ROUTE.to_string(),
            targets: vec![target(base, false)],
            managed: false,
            balance: Balance::Priority,
            turn: AtomicUsize::new(0),
            health_check: None,
            eject_after: 0,
            eject_for: Duration::ZERO,
            eject_for_max: Duration::ZERO,
            eject_after_5xx: 0,
            eject_lock: Mutex::new(()),
            hash_on: None,
            sticky: None,
        }
    }

    /// An `[[upstreams]]` entry, labelled `route` in the series. Fails on what would otherwise
    /// surface as a `502`, or a setting that would do nothing: both `target` and `targets`,
    /// neither, a URL that is not `http(s)://host`, a target listed twice, pool settings on a
    /// single `target`, or health, hash or cookie settings that do not parse.
    pub fn from_route(cfg: &UpstreamRoute, route: &str) -> Result<Pool> {
        let path = &cfg.path;
        anyhow::ensure!(
            cfg.target.is_empty() || cfg.targets.is_empty(),
            "upstreams[] (path {path:?}) sets both target and targets: one upstream, or a pool"
        );
        if cfg.targets.is_empty() {
            anyhow::ensure!(
                !cfg.target.is_empty(),
                "upstreams[].target must not be empty (path {path:?})"
            );
            check_url(&cfg.target)
                .with_context(|| format!("upstreams[].target (path {path:?})"))?;
            let pool_only = [
                (
                    "health_check",
                    !cfg.health_check.path.is_empty() || cfg.health_check.kind == "tcp",
                ),
                ("backup", !cfg.backup.is_empty()),
                ("balance", cfg.balance != "priority"),
                ("eject_after_5xx", cfg.eject_after_5xx != 0),
                ("hash_on", !cfg.hash_on.is_empty()),
                ("sticky_cookie", !cfg.sticky_cookie.is_empty()),
                (
                    "sticky_cookie_max_age",
                    !cfg.sticky_cookie_max_age.is_empty(),
                ),
                ("sticky_cookie_strip", cfg.sticky_cookie_strip),
            ];
            if let Some((setting, _)) = pool_only.iter().find(|(_, set)| *set) {
                anyhow::bail!(
                    "upstreams[] (path {path:?}): {setting} needs a pool; write targets = [{:?}]",
                    cfg.target
                );
            }
            let mut single = Pool::single(&cfg.target);
            single.route = route.to_string();
            return Ok(single);
        }
        let balance = match cfg.balance.as_str() {
            "priority" => Balance::Priority,
            "round_robin" => Balance::RoundRobin,
            "least_conn" => Balance::LeastConn,
            "hash" => Balance::Hash,
            other => anyhow::bail!(
                "upstreams[] (path {path:?}) balance = {other:?}: expected \"priority\", \
                 \"round_robin\", \"least_conn\" or \"hash\""
            ),
        };
        let hash_on = match (balance, cfg.hash_on.as_str()) {
            (Balance::Hash, "") => Some(HashOn::ClientIp),
            (Balance::Hash, on) => Some(
                HashOn::parse(on)
                    .with_context(|| format!("upstreams[] (path {path:?}) hash_on = {on:?}"))?,
            ),
            (_, "") => None,
            (_, on) => anyhow::bail!(
                "upstreams[] (path {path:?}) hash_on = {on:?} needs balance = \"hash\""
            ),
        };
        let sticky = match cfg.sticky_cookie.as_str() {
            "" => {
                let unused = [
                    (
                        "sticky_cookie_max_age",
                        !cfg.sticky_cookie_max_age.is_empty(),
                    ),
                    ("sticky_cookie_strip", cfg.sticky_cookie_strip),
                ];
                if let Some((setting, _)) = unused.iter().find(|(_, set)| *set) {
                    anyhow::bail!("upstreams[] (path {path:?}) {setting} needs sticky_cookie");
                }
                None
            }
            name => {
                anyhow::ensure!(
                    is_cookie_name(name),
                    "upstreams[] (path {path:?}) sticky_cookie = {name:?} is not a cookie name"
                );
                // A cookie's Path runs to the next `;`, so one in the prefix would end it early.
                anyhow::ensure!(
                    path.bytes().all(|b| b.is_ascii_graphic() && b != b';'),
                    "upstreams[] (path {path:?}) sticky_cookie needs a path that can be a cookie's \
                     Path: no spaces, ';' or control characters"
                );
                let max_age = match cfg.sticky_cookie_max_age.as_str() {
                    "" => None,
                    text => {
                        let d = parse_duration(text).with_context(|| {
                            format!("upstreams[] (path {path:?}) sticky_cookie_max_age = {text:?}")
                        })?;
                        // Under a second is `Max-Age=0`: a cookie deleted as it is set.
                        anyhow::ensure!(
                            d.as_secs() > 0,
                            "upstreams[] (path {path:?}) sticky_cookie_max_age must be at least \
                             1s; leave it empty for a session cookie"
                        );
                        Some(d)
                    }
                };
                Some(Sticky {
                    name: name.to_string(),
                    path: path.clone(),
                    max_age,
                    strip: cfg.sticky_cookie_strip,
                })
            }
        };

        let mut targets: Vec<Target> = Vec::with_capacity(cfg.targets.len() + cfg.backup.len());
        let listed = cfg
            .targets
            .iter()
            .map(|u| (u, false, "targets"))
            .chain(cfg.backup.iter().map(|u| (u, true, "backup")));
        for (entry, backup, key) in listed {
            let url = &entry.url;
            check_url(url).with_context(|| format!("upstreams[].{key} (path {path:?})"))?;
            let mut t = target(url, backup);
            anyhow::ensure!(
                !targets.iter().any(|o| o.base == t.base),
                "upstreams[] (path {path:?}) lists {url:?} twice (targets and backup together)"
            );
            if let Some(weight) = entry.weight {
                anyhow::ensure!(
                    balance != Balance::Priority,
                    "upstreams[] (path {path:?}) gives {url:?} a weight, but weights only apply \
                     to balance = \"round_robin\", \"least_conn\" or \"hash\""
                );
                anyhow::ensure!(
                    weight > 0,
                    "upstreams[] (path {path:?}) gives {url:?} weight 0: a target that should take \
                     no requests belongs in backup, or out of the pool"
                );
                t.weight = weight;
            }
            targets.push(t);
        }
        let duration = |name: &str, value: &str| -> Result<Duration> {
            let d = parse_duration(value)
                .with_context(|| format!("upstreams[] (path {path:?}) {name} = {value:?}"))?;
            anyhow::ensure!(
                !d.is_zero(),
                "upstreams[] (path {path:?}) {name} must be more than 0"
            );
            Ok(d)
        };
        let hc = &cfg.health_check;
        let kind = match hc.kind.as_str() {
            "http" => CheckKind::Http,
            "tcp" => CheckKind::Tcp,
            other => anyhow::bail!(
                "upstreams[] (path {path:?}) health_check.type = {other:?}: expected \"http\" or \
                 \"tcp\""
            ),
        };
        // Settings only an HTTP check with a path uses.
        let http_only = [
            ("expect_body", !hc.expect_body.is_empty()),
            ("expect_body_regex", !hc.expect_body_regex.is_empty()),
            ("method", hc.method.trim() != "GET"),
            ("headers", !hc.headers.is_empty()),
        ];
        if kind == CheckKind::Tcp {
            // A TCP check sends nothing and reads nothing: these would be ignored.
            let set = [
                ("path", !hc.path.is_empty()),
                ("expect_status", hc.expect_status != "200-399"),
            ]
            .into_iter()
            .chain(http_only)
            .find(|(_, set)| *set);
            if let Some((setting, _)) = set {
                anyhow::bail!(
                    "upstreams[] (path {path:?}) health_check.{setting} does nothing with type = \
                     \"tcp\", which only connects"
                );
            }
        }
        let health_check = if kind == CheckKind::Http && hc.path.is_empty() {
            let set = http_only
                .into_iter()
                .chain([("port", hc.port != 0)])
                .find(|(_, set)| *set);
            if let Some((setting, _)) = set {
                anyhow::bail!(
                    "upstreams[] (path {path:?}) health_check.{setting} needs health_check.path"
                );
            }
            None
        } else {
            anyhow::ensure!(
                kind == CheckKind::Tcp || hc.path.starts_with('/'),
                "upstreams[] (path {path:?}) health_check.path must start with '/' (got {:?})",
                hc.path
            );
            anyhow::ensure!(
                hc.healthy_after > 0 && hc.unhealthy_after > 0,
                "upstreams[] (path {path:?}) health_check.healthy_after and unhealthy_after must \
                 be at least 1"
            );
            Some(HealthCheck {
                kind,
                path: hc.path.clone(),
                interval: duration("health_check.interval", &hc.interval)?,
                timeout: duration("health_check.timeout", &hc.timeout)?,
                healthy_after: hc.healthy_after,
                unhealthy_after: hc.unhealthy_after,
                expect_status: hc.expect_status.clone(),
                expect: parse_statuses(&hc.expect_status).with_context(|| {
                    format!(
                        "upstreams[] (path {path:?}) health_check.expect_status = {:?}",
                        hc.expect_status
                    )
                })?,
                expect_body: hc.expect_body.clone(),
                expect_body_regex: hc.expect_body_regex.clone(),
                body: check_body(hc).with_context(|| format!("upstreams[] (path {path:?})"))?,
                method: check_method(hc).with_context(|| format!("upstreams[] (path {path:?})"))?,
                headers: check_headers(hc)
                    .with_context(|| format!("upstreams[] (path {path:?})"))?,
                port: (hc.port != 0).then_some(hc.port),
                header_names: {
                    let mut names: Vec<String> = hc
                        .headers
                        .iter()
                        .map(|(name, _)| name.trim().to_ascii_lowercase())
                        .collect();
                    names.sort_unstable();
                    names.dedup();
                    names
                },
            })
        };
        let (eject_for, eject_for_max) = if cfg.eject_after == 0 && cfg.eject_after_5xx == 0 {
            (Duration::ZERO, Duration::ZERO)
        } else {
            let base = duration("eject_for", &cfg.eject_for)?;
            let max = if cfg.eject_for_max.is_empty() {
                base.max(Duration::from_secs(300))
            } else {
                let max = duration("eject_for_max", &cfg.eject_for_max)?;
                anyhow::ensure!(
                    max >= base,
                    "upstreams[] (path {path:?}) eject_for_max = {:?} is shorter than eject_for = \
                     {:?}",
                    cfg.eject_for_max,
                    cfg.eject_for
                );
                max
            };
            (base, max)
        };
        Ok(Pool {
            route: route.to_string(),
            targets,
            managed: true,
            balance,
            turn: AtomicUsize::new(0),
            health_check,
            eject_after: cfg.eject_after,
            eject_for,
            eject_for_max,
            eject_after_5xx: cfg.eject_after_5xx,
            eject_lock: Mutex::new(()),
            hash_on,
            sticky,
        })
    }

    /// The first target's base URL.
    pub fn primary(&self) -> &str {
        &self.targets[0].base
    }

    /// Whether this route has a pool (`targets`), whose health is kept and reported.
    pub fn is_pool(&self) -> bool {
        self.managed
    }

    /// [`Pool::order_for`] a request that carries neither a hash key nor a sticky cookie.
    pub fn order(&self) -> Vec<&Target> {
        self.order_for(&Affinity::default())
    }

    /// What `request` brings to this pool's pick: the key `hash_on` names, from the request's
    /// `headers`, its `uri` (path or query) or its `client` address, and the target its sticky
    /// cookie names. Reads nothing for a pool that uses neither.
    pub fn affinity(&self, headers: &HeaderMap, uri: &Uri, client: IpAddr) -> Affinity {
        let key = self.hash_on.as_ref().and_then(|on| match on {
            HashOn::ClientIp => Some(match client.to_canonical() {
                IpAddr::V4(a) => hash64(&a.octets()),
                IpAddr::V6(a) => hash64(&a.octets()),
            }),
            HashOn::Path => Some(hash64(uri.path().as_bytes())),
            HashOn::Query(name) => query_param(uri.query()?, name).map(|v| hash64(v.as_bytes())),
            HashOn::Header(name) => headers
                .get(name)
                .map(HeaderValue::as_bytes)
                .filter(|v| !v.is_empty())
                .map(hash64),
            HashOn::Cookie(name) => cookies(headers, name).next().map(|v| hash64(v.as_bytes())),
        });
        let stuck = self.sticky.as_ref().and_then(|s| {
            cookies(headers, &s.name)
                .filter_map(|v| u64::from_str_radix(v, 16).ok())
                .find(|id| self.targets.iter().any(|t| t.id == *id))
        });
        Affinity { key, stuck }
    }

    /// The targets a request tries, in order: those in rotation, `targets` before `backup`, or
    /// every one in that order when none is. Within each tier, the order listed; with round-robin
    /// the same order starting from the next target in turn; with least-connections from the
    /// least loaded; with hashing, by how the request's key ranks them, or in turn without one.
    /// The target the request's sticky cookie names goes first, if it is in the first tier.
    pub fn order_for(&self, affinity: &Affinity) -> Vec<&Target> {
        if !self.managed {
            return self.targets.iter().collect();
        }
        let now = now_ms();
        let key = affinity.key.filter(|_| self.balance == Balance::Hash);
        let turn = match self.balance {
            Balance::Priority => 0,
            Balance::Hash if key.is_some() => 0,
            Balance::RoundRobin | Balance::LeastConn | Balance::Hash => {
                self.turn.fetch_add(1, Ordering::Relaxed)
            }
        };
        let tiers = |in_rotation_only: bool| {
            let mut out = Vec::with_capacity(self.targets.len());
            for backup in [false, true] {
                let start = out.len();
                out.extend(self.targets.iter().filter(|t| {
                    t.backup == backup && (!in_rotation_only || t.health.in_rotation(now))
                }));
                let tier = &mut out[start..];
                if let Some(key) = key {
                    // Positive scores order as their bits do.
                    tier.sort_by_cached_key(|t| std::cmp::Reverse(score(key, t).to_bits()));
                } else if !tier.is_empty() {
                    let k = match self.balance {
                        Balance::LeastConn => least_loaded(tier, turn),
                        _ => weighted_turn(tier, turn),
                    };
                    tier.rotate_left(k);
                }
            }
            out
        };
        let up = tiers(true);
        let mut out = if up.is_empty() { tiers(false) } else { up };
        if let Some(i) = affinity
            .stuck
            .and_then(|id| out.iter().position(|t| t.id == id))
        {
            // Never a backup ahead of a target that is not.
            if out[i].backup == out[0].backup {
                let stuck = out.remove(i);
                out.insert(0, stuck);
            }
        }
        out
    }

    /// `sticky_cookie`, when set.
    pub fn sticky_cookie_name(&self) -> Option<&str> {
        self.sticky.as_ref().map(|s| s.name.as_str())
    }

    /// The `Set-Cookie` that keeps this client on `target`, which answered it, or `None`: no
    /// `sticky_cookie`, or the request's cookie already names `target`. `Secure` comes from
    /// `headers.force_secure_cookies`, as for every cookie.
    pub fn sticky_cookie(&self, affinity: &Affinity, target: &Target) -> Option<HeaderValue> {
        let sticky = self.sticky.as_ref()?;
        if affinity.stuck == Some(target.id) {
            return None;
        }
        let max_age = sticky
            .max_age
            .map(|d| format!("; Max-Age={}", d.as_secs()))
            .unwrap_or_default();
        HeaderValue::from_str(&format!(
            "{}={:016x}; Path={}{max_age}; HttpOnly; SameSite=Lax",
            sticky.name, target.id, sticky.path
        ))
        .ok()
    }

    /// With `sticky_cookie_strip`, remove the sticky cookie from the `Cookie` header(s) of a
    /// request about to be forwarded, keeping the client's others. What is left goes as one
    /// header, as an HTTP/1.1 upstream expects; with nothing left, none goes. Headers without the
    /// cookie are left as they are.
    pub fn strip_sticky_cookie(&self, headers: &mut HeaderMap) {
        let Some(sticky) = self.sticky.as_ref().filter(|s| s.strip) else {
            return;
        };
        let name = sticky.name.as_bytes();
        // Bytes, not text: a cookie value may carry bytes that are not UTF-8, and they pass as is.
        let is_ours = |pair: &[u8]| {
            pair.strip_prefix(name)
                .is_some_and(|rest| rest.first() == Some(&b'='))
        };
        let values: Vec<HeaderValue> = headers.get_all(header::COOKIE).iter().cloned().collect();
        let pairs: Vec<&[u8]> = values
            .iter()
            .flat_map(|v| v.as_bytes().split(|b| *b == b';'))
            .map(<[u8]>::trim_ascii)
            .filter(|p| !p.is_empty())
            .collect();
        if !pairs.iter().any(|p| is_ours(p)) {
            return;
        }
        headers.remove(header::COOKIE);
        let kept: Vec<&[u8]> = pairs.into_iter().filter(|p| !is_ours(p)).collect();
        if kept.is_empty() {
            return;
        }
        if let Ok(v) = HeaderValue::from_bytes(&kept.join(&b"; "[..])) {
            headers.insert(header::COOKIE, v);
        }
    }

    /// Whether any target is in rotation. A route with one target always is: nothing tracks it.
    pub fn any_in_rotation(&self) -> bool {
        let now = now_ms();
        !self.managed || self.targets.iter().any(|t| t.health.in_rotation(now))
    }

    /// A request is about to be sent to `target`: counted in flight while the result lives, for a
    /// `least_conn` pool. Other pools count nothing, so their requests pay nothing.
    pub(crate) fn start(&self, target: &Target) -> Option<InFlight> {
        if self.balance != Balance::LeastConn {
            return None;
        }
        target.health.in_flight.fetch_add(1, Ordering::AcqRel);
        Some(InFlight(Arc::clone(&target.health)))
    }

    /// A request reached `target`, which answered with `status`.
    pub(crate) fn answered(&self, target: &Target, status: u16) {
        if !self.managed {
            return;
        }
        let h = &target.health;
        h.connected();
        if status < 500 {
            h.answered_ok();
            return;
        }
        if self.eject_after_5xx == 0 {
            return;
        }
        let n = h.http_5xx.fetch_add(1, Ordering::AcqRel) + 1;
        if n < self.eject_after_5xx {
            return;
        }
        let _one_at_a_time = lock(&self.eject_lock);
        let now = now_ms();
        if !h.in_rotation(now) {
            return;
        }
        let others = self
            .targets
            .iter()
            .any(|t| !Arc::ptr_eq(&t.health, h) && t.health.in_rotation(now));
        if !others {
            if n == self.eject_after_5xx {
                warn!(
                    route = %self.route,
                    upstream = %target.label,
                    answers = n,
                    "upstream target answers 5xx, but it is the last in rotation: kept"
                );
            }
            return;
        }
        h.http_5xx.store(0, Ordering::Relaxed);
        let (in_a_row, length) =
            h.eject(now, self.eject_for, self.eject_for_max, Ejection::Http5xx);
        warn!(
            route = %self.route,
            upstream = %target.label,
            status,
            answers = n,
            eject_for = ?length,
            ejections_in_a_row = in_a_row,
            "upstream target ejected: it answered 5xx too many times in a row"
        );
    }

    /// A request could not connect to `target`; `error` is why, for the log.
    pub(crate) fn connect_failed(&self, target: &Target, error: &str) {
        if !self.managed {
            return;
        }
        *lock(&target.health.last_connect_error) = Some(Event::now(false, error));
        if self.eject_after == 0 {
            return;
        }
        if let Some((in_a_row, length)) =
            target
                .health
                .connect_failed(self.eject_after, self.eject_for, self.eject_for_max)
        {
            warn!(
                route = %self.route,
                upstream = %target.label,
                error,
                failures = self.eject_after,
                eject_for = ?length,
                ejections_in_a_row = in_a_row,
                "upstream target ejected: requests failed to connect to it"
            );
        }
    }

    /// Whether requests go to the main targets (`"normal"`), only to `backup` ones (`"backup"`), or,
    /// with nothing in rotation, to every target in turn (`"all_out"`).
    pub fn state(&self) -> &'static str {
        let now = now_ms();
        let up = |backup: bool| {
            self.targets
                .iter()
                .any(|t| t.backup == backup && t.health.in_rotation(now))
        };
        if !self.managed || up(false) {
            "normal"
        } else if up(true) {
            "backup"
        } else {
            "all_out"
        }
    }

    /// This route for `GET /__edgeguard/upstreams`: `path` is its prefix (`None` for the default),
    /// and `requests` gives a target's request counts by its label. Targets are named by label,
    /// never by the configured URL, which may carry credentials.
    pub fn status_json(
        &self,
        path: Option<&str>,
        requests: impl Fn(&str) -> serde_json::Value,
    ) -> serde_json::Value {
        use serde_json::{json, Value};
        let now = now_ms();
        let targets: Vec<Value> = self
            .targets
            .iter()
            .map(|t| {
                let mut j = json!({ "upstream": t.label, "requests": requests(&t.label) });
                if !self.managed {
                    return j;
                }
                let h = &t.health;
                j["backup"] = json!(t.backup);
                j["weight"] = json!(t.weight);
                if self.sticky.is_some() {
                    j["sticky_cookie_value"] = json!(format!("{:016x}", t.id));
                }
                if self.balance == Balance::LeastConn {
                    j["in_flight"] = json!(h.in_flight.load(Ordering::Acquire));
                }
                j["in_rotation"] = json!(h.in_rotation(now));
                if self.health_check.is_some() {
                    let (passed, failed) = h.checks();
                    j["health_check"] = json!({
                        "passing": h.passing.load(Ordering::Acquire),
                        "passed": passed,
                        "failed": failed,
                        "last": lock(&h.last_check).as_ref().map(|e| e.json("result")),
                    });
                }
                let until = h.ejected_until.load(Ordering::Acquire);
                j["ejected"] = if until > now {
                    json!({
                        "remaining_s": (until - now) as f64 / 1000.0,
                        "length_s": h.last_ejection_ms.load(Ordering::Relaxed) as f64 / 1000.0,
                        "reason": h.ejected_reason().map(Ejection::label),
                    })
                } else {
                    Value::Null
                };
                j["ejections"] = Value::Object(
                    Ejection::ALL
                        .iter()
                        .map(|e| (e.label().to_string(), json!(h.ejections(*e))))
                        .collect(),
                );
                j["connect_failures_in_a_row"] = json!(h.connect_failures.load(Ordering::Relaxed));
                j["http_5xx_in_a_row"] = json!(h.http_5xx.load(Ordering::Relaxed));
                j["ejections_in_a_row"] = json!(h.ejections_in_a_row(now, self.eject_for_max));
                j["last_connect_error"] = json!(lock(&h.last_connect_error)
                    .as_ref()
                    .map(|e| e.json("error")));
                j
            })
            .collect();
        let mut j = json!({
            "route": self.route,
            "path": path,
            "pool": self.managed,
            "targets": targets,
        });
        if self.managed {
            j["balance"] = json!(self.balance.label());
            if let Some(on) = &self.hash_on {
                j["hash_on"] = json!(on.label());
            }
            j["sticky_cookie"] = json!(self.sticky_cookie_name());
            j["state"] = json!(self.state());
            j["health_check"] = json!(self.health_check.as_ref().map(|hc| json!({
                "type": match hc.kind {
                    CheckKind::Http => "http",
                    CheckKind::Tcp => "tcp",
                },
                "path": hc.path,
                "interval_s": hc.interval.as_secs_f64(),
                "timeout_s": hc.timeout.as_secs_f64(),
                "healthy_after": hc.healthy_after,
                "unhealthy_after": hc.unhealthy_after,
                "port": hc.port,
                "method": hc.method.as_str(),
                // Names only: a value may be a token.
                "headers": hc.header_names,
                "expect_status": hc.expect_status,
                "expect_body": hc.expect_body,
                "expect_body_regex": hc.expect_body_regex,
            })));
            j["eject_after"] = json!(self.eject_after);
            j["eject_after_5xx"] = json!(self.eject_after_5xx);
            j["eject_for_s"] = json!(self.eject_for.as_secs_f64());
            j["eject_for_max_s"] = json!(self.eject_for_max.as_secs_f64());
        }
        j
    }

    /// Take over the health of the targets `old` shares with this pool, so a reload keeps it.
    /// Without active checks, a failed check's verdict is not kept: nothing would ever undo it.
    pub(crate) fn carry_health_from(&mut self, old: &Pool) {
        if !(self.managed && old.managed) {
            return;
        }
        for t in &mut self.targets {
            if let Some(o) = old.targets.iter().find(|o| o.base == t.base) {
                t.health = Arc::clone(&o.health);
                if self.health_check.is_none() {
                    t.health.passing.store(true, Ordering::Release);
                    t.health.streak.store(0, Ordering::Relaxed);
                }
            }
        }
    }
}

fn target(url: &str, backup: bool) -> Target {
    let base = url.trim_end_matches('/').to_string();
    Target {
        label: crate::proxy::upstream_for_log(&base),
        id: hash64(base.as_bytes()),
        base: Arc::new(base),
        backup,
        weight: 1,
        health: Arc::default(),
    }
}

/// 64-bit FNV-1a, finished with [`mix`]. Fixed rather than std's hasher, which may change between
/// Rust releases: every edge, whatever it was built with, must send a key to the same target and
/// read the same sticky cookie. Changing it moves every key, so a test pins it.
fn hash64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    mix(h)
}

/// MurmurHash3's 64-bit finalizer: every input bit reaches every output bit.
fn mix(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

/// `target`'s rank for `key` by weighted rendezvous hashing: the highest takes the key. A hash
/// of the two, as `u` in (0, 1), scored `-weight / ln(u)`: each target wins a share of keys in
/// proportion to its weight, and a target leaving rotation moves only the keys it had.
fn score(key: u64, target: &Target) -> f64 {
    // The top 52 bits, exact as a float and short of 1, so the logarithm is negative and the
    // score finite: `0` at worst, never negative, so scores order as their bits do.
    let u = (mix(key ^ target.id) >> 12) as f64 / (1u64 << 52) as f64;
    -f64::from(target.weight) / u.ln()
}

/// The values of every cookie called `name` in the request's `Cookie` headers, in order.
fn cookies<'h>(headers: &'h HeaderMap, name: &'h str) -> impl Iterator<Item = &'h str> + 'h {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(move |pair| {
            let (n, v) = pair.trim().split_once('=')?;
            (n == name && !v.is_empty()).then_some(v)
        })
}

/// The value of the first `name=` in `query`, as sent: `a=1&a=2` gives `1`. An empty one (`a=`)
/// gives nothing, so the request is balanced in turn as one without the key is.
fn query_param<'q>(query: &'q str, name: &str) -> Option<&'q str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
}

/// A cookie name: an RFC 6265 token (visible ASCII, no separators).
fn is_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b))
}

/// Which of `tier` (the targets in rotation, in order) has the fewest requests in flight for its
/// weight: the least `(in flight + 1) / weight`, as HAProxy's leastconn weighs it, so with none in
/// flight the heaviest goes first. Ties are taken in turn, so an idle pool still spreads requests.
fn least_loaded(tier: &[&Target], turn: usize) -> usize {
    let load = |t: &Target| {
        (
            u64::from(t.health.in_flight.load(Ordering::Acquire)) + 1,
            u64::from(t.weight),
        )
    };
    // a / b against c / d, without division: a * d against c * b.
    let (best_n, best_w) = tier
        .iter()
        .map(|t| load(t))
        .min_by(|(a, b), (c, d)| (a * d).cmp(&(c * b)))
        .expect("a tier is never empty here");
    let tied = |t: &&&Target| {
        let (n, w) = load(t);
        n * best_w == best_n * w
    };
    let count = tier.iter().filter(tied).count();
    tier.iter()
        .enumerate()
        .filter(|(_, t)| tied(t))
        .nth(turn % count)
        .map(|(i, _)| i)
        // A count changed under us (another request finished): the lightest found will do.
        .unwrap_or(0)
}

/// Which of `tier` (the targets in rotation, in order) takes `turn`, by interleaved weighted
/// round-robin. Round `r` of a cycle gives one turn to each target whose weight is over `r`, in
/// order, so weights 3, 1, 2 go a, b, c, a, c, a. Every cycle gives each target exactly its
/// weight's share of the turns, whichever targets are in rotation, and spreads a heavy target's
/// turns out rather than bunching them. With equal weights it is plain round-robin.
///
/// Rounds in which the same targets take part are skipped over together, so the cost is a few
/// passes over the tier, not one per round.
fn weighted_turn(tier: &[&Target], turn: usize) -> usize {
    let total: u64 = tier.iter().map(|t| u64::from(t.weight)).sum();
    let mut k = turn as u64 % total;
    // Rounds before `done` are already counted out of `k`.
    let mut done = 0u32;
    loop {
        let taking = || tier.iter().filter(move |t| t.weight > done);
        let count = taking().count() as u64;
        // Until the lightest of them runs out, every round has these same `count` turns.
        let next = taking()
            .map(|t| t.weight)
            .min()
            .expect("k < total leaves a round to take");
        let span = u64::from(next - done) * count;
        if k < span {
            let nth = (k % count) as usize;
            return tier
                .iter()
                .enumerate()
                .filter(|(_, t)| t.weight > done)
                .nth(nth)
                .expect("nth < count")
                .0;
        }
        k -= span;
        done = next;
    }
}

/// An upstream URL: `http://` or `https://`, with a host.
pub(crate) fn check_url(url: &str) -> Result<()> {
    let uri: axum::http::Uri = url
        .parse()
        .with_context(|| format!("{url:?} is not a URL"))?;
    anyhow::ensure!(
        matches!(uri.scheme_str(), Some("http" | "https")),
        "{url:?} must start with http:// or https://"
    );
    anyhow::ensure!(uri.host().is_some(), "{url:?} has no host");
    Ok(())
}

/// Something that happened to a target, for the status endpoint.
#[derive(Debug, Clone)]
struct Event {
    at: SystemTime,
    ok: bool,
    detail: String,
}

impl Event {
    fn now(ok: bool, detail: &str) -> Event {
        Event {
            at: SystemTime::now(),
            ok,
            detail: detail.to_string(),
        }
    }

    /// `{"at": RFC 3339, "ok": …, <detail_key>: detail}`.
    fn json(&self, detail_key: &str) -> serde_json::Value {
        let secs = self
            .at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut j = serde_json::json!({ "at": crate::proxy::rfc3339(secs), "ok": self.ok });
        j[detail_key] = serde_json::json!(self.detail);
        j
    }
}

/// A poisoned lock still holds the last value written, which is all these hold.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Milliseconds since the first call: a clock an atomic can hold.
fn now_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    // Plus one, so `0` can mean "never" below.
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

/// What is known about one target of a pool. Lock-free: a request reads it on every attempt.
#[derive(Debug)]
pub struct TargetHealth {
    /// The active checks' verdict. `true` until they say otherwise, and always without them.
    passing: AtomicBool,
    /// Checks in a row that disagree with `passing`: failures while passing, passes while not.
    streak: AtomicU32,
    /// Requests in a row that failed to connect.
    connect_failures: AtomicU32,
    /// Answers in a row with a `5xx` status.
    http_5xx: AtomicU32,
    /// Requests in flight, for `least_conn` ([`InFlight`]).
    in_flight: AtomicU32,
    /// Ejections with less than `eject_for_max` between them, and when the last one ends
    /// (a [`now_ms`]) and how long it was.
    ejections_in_a_row: AtomicU32,
    last_ejection_end: AtomicU64,
    last_ejection_ms: AtomicU64,
    /// Out of rotation until this [`now_ms`]; `0` when not ejected.
    ejected_until: AtomicU64,
    /// The last ejection's [`Ejection`], as its discriminant; `0` before any.
    ejected_reason: AtomicU8,
    /// Ejections so far, by [`Ejection::index`].
    ejections: [AtomicU64; 2],
    /// The next check is due at this [`now_ms`].
    next_check: AtomicU64,
    /// A check is running.
    checking: AtomicBool,
    checks_passed: AtomicU64,
    checks_failed: AtomicU64,
    /// The last check, and the last request that failed to connect: written on those rare
    /// events, read only by the status endpoint.
    last_check: Mutex<Option<Event>>,
    last_connect_error: Mutex<Option<Event>>,
}

impl Default for TargetHealth {
    fn default() -> Self {
        TargetHealth {
            passing: AtomicBool::new(true),
            streak: AtomicU32::new(0),
            connect_failures: AtomicU32::new(0),
            http_5xx: AtomicU32::new(0),
            in_flight: AtomicU32::new(0),
            ejections_in_a_row: AtomicU32::new(0),
            last_ejection_end: AtomicU64::new(0),
            last_ejection_ms: AtomicU64::new(0),
            ejected_until: AtomicU64::new(0),
            ejected_reason: AtomicU8::new(0),
            ejections: [AtomicU64::new(0), AtomicU64::new(0)],
            next_check: AtomicU64::new(0),
            checking: AtomicBool::new(false),
            checks_passed: AtomicU64::new(0),
            checks_failed: AtomicU64::new(0),
            last_check: Mutex::new(None),
            last_connect_error: Mutex::new(None),
        }
    }
}

impl TargetHealth {
    fn in_rotation(&self, now: u64) -> bool {
        self.passing.load(Ordering::Acquire) && self.ejected_until.load(Ordering::Acquire) <= now
    }

    /// Whether the target is in rotation now.
    pub fn is_in_rotation(&self) -> bool {
        self.in_rotation(now_ms())
    }

    /// Active checks passed and failed so far.
    pub fn checks(&self) -> (u64, u64) {
        (
            self.checks_passed.load(Ordering::Relaxed),
            self.checks_failed.load(Ordering::Relaxed),
        )
    }

    /// Ejections so far for `reason`.
    pub fn ejections(&self, reason: Ejection) -> u64 {
        self.ejections[reason.index()].load(Ordering::Relaxed)
    }

    /// Why the last ejection happened; `None` before any.
    pub fn ejected_reason(&self) -> Option<Ejection> {
        match self.ejected_reason.load(Ordering::Relaxed) {
            1 => Some(Ejection::ConnectError),
            2 => Some(Ejection::Http5xx),
            _ => None,
        }
    }

    // Each of these writes only when there is something to change, so a healthy target's
    // requests only read.

    /// A request connected.
    fn connected(&self) {
        if self.connect_failures.load(Ordering::Relaxed) != 0 {
            self.connect_failures.store(0, Ordering::Relaxed);
        }
    }

    /// A request got an answer below `500`.
    fn answered_ok(&self) {
        if self.http_5xx.load(Ordering::Relaxed) != 0 {
            self.http_5xx.store(0, Ordering::Relaxed);
        }
        // An ejected target is only tried when nothing is in rotation. If it answered, it is back.
        if self.ejected_until.load(Ordering::Relaxed) != 0 {
            self.ejected_until.store(0, Ordering::Release);
        }
    }

    /// Ejections in a row as of `now`: none once `max` has passed without another
    /// since the last one ended.
    fn ejections_in_a_row(&self, now: u64, max: Duration) -> u32 {
        let end = self.last_ejection_end.load(Ordering::Acquire);
        if end == 0 || now >= end.saturating_add(max.as_millis() as u64) {
            0
        } else {
            self.ejections_in_a_row.load(Ordering::Relaxed)
        }
    }

    /// Take the target out for `base` times its ejections in a row, up to `max`. Returns how many
    /// in a row this makes, and how long it is out.
    fn eject(&self, now: u64, base: Duration, max: Duration, reason: Ejection) -> (u32, Duration) {
        let n = if self.ejections_in_a_row(now, max) == 0 {
            self.ejections_in_a_row.store(1, Ordering::Relaxed);
            1
        } else {
            self.ejections_in_a_row.fetch_add(1, Ordering::Relaxed) + 1
        };
        let length = (base.as_millis() as u64)
            .saturating_mul(u64::from(n))
            .min(max.as_millis() as u64);
        self.ejected_reason.store(reason as u8, Ordering::Relaxed);
        self.ejections[reason.index()].fetch_add(1, Ordering::Relaxed);
        self.last_ejection_ms.store(length, Ordering::Relaxed);
        self.last_ejection_end
            .store(now + length, Ordering::Release);
        self.ejected_until.store(now + length, Ordering::Release);
        (n, Duration::from_millis(length))
    }

    /// Count a failed connection. When it ejects the target: how many in a row, and for how long.
    fn connect_failed(
        &self,
        eject_after: u32,
        base: Duration,
        max: Duration,
    ) -> Option<(u32, Duration)> {
        let n = self.connect_failures.fetch_add(1, Ordering::AcqRel) + 1;
        if n < eject_after {
            return None;
        }
        self.connect_failures.store(0, Ordering::Relaxed);
        Some(self.eject(now_ms(), base, max, Ejection::ConnectError))
    }

    /// Claim the next check if it is due: `Ok(())` to run it now, or `Err(when)` it is due.
    fn claim_check(&self, now: u64, interval: Duration) -> Result<(), Option<u64>> {
        let due = self.next_check.load(Ordering::Acquire);
        if now < due {
            return Err(Some(due));
        }
        if self.checking.swap(true, Ordering::AcqRel) {
            return Err(None);
        }
        self.next_check
            .store(now + interval.as_millis() as u64, Ordering::Release);
        Ok(())
    }

    /// Record a check's result; returns the new verdict when it changed.
    fn checked(&self, passed: bool, hc: &HealthCheck) -> Option<bool> {
        if passed {
            self.checks_passed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.checks_failed.fetch_add(1, Ordering::Relaxed);
        }
        if self.passing.load(Ordering::Acquire) == passed {
            self.streak.store(0, Ordering::Relaxed);
            return None;
        }
        let n = self.streak.fetch_add(1, Ordering::Relaxed) + 1;
        let needed = if passed {
            hc.healthy_after
        } else {
            hc.unhealthy_after
        };
        if n < needed {
            return None;
        }
        self.streak.store(0, Ordering::Relaxed);
        self.passing.store(passed, Ordering::Release);
        Some(passed)
    }
}

/// Run the active health checks of every pool in the current runtime, until `shutdown` flips. The
/// runtime is read afresh each round, so a reload's pools are checked from then on.
pub fn spawn_health_checks(
    state: &AppState,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let runtime = Arc::clone(&state.runtime);
    let client = state.client.clone();
    let connector = state.connector.clone();
    tokio::spawn(async move {
        let mut shutdown = Some(shutdown);
        loop {
            let rt = runtime.load_full();
            let now = now_ms();
            // Woken at least once a second, so a reload's new pools start promptly.
            let mut next = now + 1000;
            for pool in rt.pools() {
                let Some(hc) = &pool.health_check else {
                    continue;
                };
                for target in &pool.targets {
                    match target.health.claim_check(now, hc.interval) {
                        Ok(()) => {
                            // On another port, TLS is still the target's: the shared client
                            // would look it up by the port it dials and get the defaults.
                            let client = match hc.port {
                                Some(_) if target.base.starts_with("https://") => {
                                    hyper_util::client::legacy::Client::builder(
                                        hyper_util::rt::TokioExecutor::new(),
                                    )
                                    .build(connector.with_tls_of(&target.base))
                                }
                                _ => client.clone(),
                            };
                            tokio::spawn(check(
                                client,
                                pool.route.clone(),
                                target.clone(),
                                hc.clone(),
                            ));
                            next = next.min(now + hc.interval.as_millis() as u64);
                        }
                        Err(Some(due)) => next = next.min(due),
                        Err(None) => {}
                    }
                }
            }
            drop(rt);
            let sleep = tokio::time::sleep(Duration::from_millis(next.saturating_sub(now_ms())));
            tokio::select! {
                _ = sleep => {}
                stop = async {
                    match &mut shutdown {
                        Some(rx) => rx.wait_for(|v| *v).await.is_ok(),
                        None => std::future::pending().await,
                    }
                } => {
                    if stop {
                        return;
                    }
                    // The sender is gone: nobody can ask for a shutdown any more.
                    shutdown = None;
                }
            }
        }
    })
}

/// One check of one target, within `timeout`: for HTTP, `GET` its `path`, passing on a status in
/// `expect_status` and, with `expect_body`, a body that contains it; for TCP, a connection.
async fn check(
    client: crate::proxy::UpstreamClient,
    route: String,
    target: Target,
    hc: HealthCheck,
) {
    let base = hc.base_for(&target);
    // Named by label, as the logs name targets: the configured URL may carry credentials.
    let at = crate::proxy::upstream_for_log(&base);
    let what = match hc.kind {
        CheckKind::Http => format!("{at}{}", hc.path),
        CheckKind::Tcp => format!("tcp {at}"),
    };
    let checking = async {
        match hc.kind {
            CheckKind::Http => check_http(&client, &base, &hc).await,
            CheckKind::Tcp => check_tcp(&base).await,
        }
    };
    let result = match tokio::time::timeout(hc.timeout, checking).await {
        Ok(result) => result,
        Err(_) => Err(format!("no answer within {:?}", hc.timeout)),
    };
    let health = &target.health;
    *lock(&health.last_check) = Some(match &result {
        Ok(detail) => Event::now(true, detail),
        Err(reason) => Event::now(false, reason),
    });
    match (health.checked(result.is_ok(), &hc), &result) {
        (Some(false), Err(reason)) => warn!(
            %route,
            upstream = %target.label,
            check = %what,
            reason = %reason,
            failures = hc.unhealthy_after,
            "upstream target failed its health check: out of rotation"
        ),
        (Some(true), _) => info!(
            %route,
            upstream = %target.label,
            passes = hc.healthy_after,
            "upstream target passed its health check: back in rotation"
        ),
        _ => {}
    }
    health.checking.store(false, Ordering::Release);
}

/// Ask the check's path with its method and headers: the status must be in `expect_status`, and
/// the body, with `expect_body`, must contain that within its first [`CHECK_BODY_LIMIT`] bytes, or
/// with `expect_body_regex` match it within the body as read to its end or that limit.
async fn check_http(
    client: &crate::proxy::UpstreamClient,
    base: &str,
    hc: &HealthCheck,
) -> Result<String, String> {
    use http_body_util::BodyExt;
    let mut req = Request::builder()
        .method(hc.method.clone())
        .uri(format!("{base}{}", hc.path))
        .body(Body::empty())
        .map_err(|e| format!("not a valid URL: {e}"))?;
    *req.headers_mut() = hc.headers.clone();
    let resp = client
        .request(req)
        .await
        .map_err(|e| crate::upstream::error_chain(&e))?;
    let status = resp.status().as_u16();
    if !hc.passes(status) {
        return Err(format!("answered {status}, expected {}", hc.expect_status));
    }
    let Some(want) = &hc.body else {
        return Ok(format!("answered {status}"));
    };
    let mut body = resp.into_body();
    let mut seen: Vec<u8> = Vec::new();
    while seen.len() < CHECK_BODY_LIMIT {
        let Some(frame) = body.frame().await else {
            break;
        };
        let frame = frame.map_err(|e| format!("answered {status}, then the body failed: {e}"))?;
        if let Some(data) = frame.data_ref() {
            let before = seen.len();
            seen.extend_from_slice(data);
            seen.truncate(CHECK_BODY_LIMIT);
            // Text found is found whatever follows: only where the new bytes could complete it.
            // A regular expression waits for the whole body: `$`, or `ok$` against `ok, then
            // not`, could pass on a part of it.
            if let BodyMatch::Text(text) = want {
                let from = before.saturating_sub(text.len() - 1);
                if seen[from..].windows(text.len()).any(|w| w == text) {
                    return Ok(format!("answered {status} with {:?}", hc.expect_body));
                }
            }
        }
    }
    match want {
        BodyMatch::Regex(re) if re.is_match(&seen) => Ok(format!(
            "answered {status} matching {:?}",
            hc.expect_body_regex
        )),
        BodyMatch::Regex(_) => Err(format!(
            "answered {status}, but the body's first {} bytes do not match {:?}",
            seen.len(),
            hc.expect_body_regex
        )),
        BodyMatch::Text(_) => Err(format!(
            "answered {status}, but the body's first {} bytes do not contain {:?}",
            seen.len(),
            hc.expect_body
        )),
    }
}

/// Connect to the host and port of `base` (the target's, or its check port), and hang up.
async fn check_tcp(base: &str) -> Result<String, String> {
    let (host, port) = host_port(base)?;
    tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map(|_| "connected".to_string())
        .map_err(|e| format!("connecting: {e}"))
}

/// `base` on `port`: its scheme, credentials, host and path kept, its port replaced.
fn on_port(base: &str, port: u16) -> Result<String, String> {
    let uri: Uri = base.parse().map_err(|e| format!("not a valid URL: {e}"))?;
    let scheme = uri.scheme_str().ok_or("no scheme")?;
    let authority = uri.authority().ok_or("no host")?.as_str();
    let userinfo = authority
        .rsplit_once('@')
        .map(|(user, _)| format!("{user}@"))
        .unwrap_or_default();
    let host = uri.host().ok_or("no host")?;
    let path = uri.path().trim_end_matches('/');
    Ok(format!("{scheme}://{userinfo}{host}:{port}{path}"))
}

/// The host and port a base URL names, the port from its scheme when it gives none.
fn host_port(base: &str) -> Result<(String, u16), String> {
    let uri: axum::http::Uri = base.parse().map_err(|e| format!("not a valid URL: {e}"))?;
    let host = uri.host().ok_or("no host")?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    Ok((
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
        port,
    ))
}

/// The pool series of `pools`: whether each target is in rotation, and its checks.
pub(crate) fn render<'a>(out: &mut String, pools: impl Iterator<Item = &'a Pool> + Clone) {
    use crate::metrics::escape_label;
    let managed = pools.filter(|p| p.managed);
    if managed.clone().next().is_none() {
        return;
    }
    out.push_str(
        "# HELP edgeguard_upstream_in_rotation Whether a pool's target takes requests (1), or is \
         out (0): failing its health check, or ejected after failed connections or 5xx answers.\n\
         # TYPE edgeguard_upstream_in_rotation gauge\n",
    );
    for pool in managed.clone() {
        let route = escape_label(&pool.route);
        for t in &pool.targets {
            out.push_str(&format!(
                "edgeguard_upstream_in_rotation{{route=\"{route}\",upstream=\"{}\"}} {}\n",
                escape_label(&t.label),
                u8::from(t.health.is_in_rotation())
            ));
        }
    }
    let least_conn = managed.clone().filter(|p| p.balance == Balance::LeastConn);
    if least_conn.clone().next().is_some() {
        out.push_str(
            "# HELP edgeguard_upstream_in_flight Requests in flight to each target of a \
             least_conn pool, which sends the next to the least loaded.\n\
             # TYPE edgeguard_upstream_in_flight gauge\n",
        );
        for pool in least_conn {
            let route = escape_label(&pool.route);
            for t in &pool.targets {
                out.push_str(&format!(
                    "edgeguard_upstream_in_flight{{route=\"{route}\",upstream=\"{}\"}} {}\n",
                    escape_label(&t.label),
                    t.health.in_flight.load(Ordering::Acquire)
                ));
            }
        }
    }
    out.push_str(
        "# HELP edgeguard_upstream_ejections_total Times a pool's target was taken out of rotation \
         by requests, by reason: connect_error (eject_after) or http_5xx (eject_after_5xx).\n\
         # TYPE edgeguard_upstream_ejections_total counter\n",
    );
    for pool in managed.clone() {
        let route = escape_label(&pool.route);
        for t in &pool.targets {
            let upstream = escape_label(&t.label);
            for reason in Ejection::ALL {
                out.push_str(&format!(
                    "edgeguard_upstream_ejections_total{{route=\"{route}\",upstream=\"{upstream}\",reason=\"{}\"}} {}\n",
                    reason.label(),
                    t.health.ejections(reason)
                ));
            }
        }
    }
    let checked = managed.filter(|p| p.health_check.is_some());
    if checked.clone().next().is_none() {
        return;
    }
    out.push_str(
        "# HELP edgeguard_upstream_health_checks_total Active health checks of a pool's targets, \
         by result.\n\
         # TYPE edgeguard_upstream_health_checks_total counter\n",
    );
    for pool in checked {
        let route = escape_label(&pool.route);
        for t in &pool.targets {
            let upstream = escape_label(&t.label);
            let (passed, failed) = t.health.checks();
            out.push_str(&format!(
                "edgeguard_upstream_health_checks_total{{route=\"{route}\",upstream=\"{upstream}\",result=\"pass\"}} {passed}\n\
                 edgeguard_upstream_health_checks_total{{route=\"{route}\",upstream=\"{upstream}\",result=\"fail\"}} {failed}\n"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HealthCheckCfg;

    fn route(targets: &[&str]) -> UpstreamRoute {
        UpstreamRoute {
            path: "/api".into(),
            targets: targets.iter().map(|t| (*t).into()).collect(),
            ..Default::default()
        }
    }

    fn err(cfg: UpstreamRoute) -> String {
        format!("{:#}", Pool::from_route(&cfg, "api").unwrap_err())
    }

    #[test]
    fn a_pool_or_a_target_but_not_both_and_each_url_once() {
        let both = UpstreamRoute {
            target: "http://a:1".into(),
            ..route(&["http://b:1"])
        };
        assert!(err(both).contains("both target and targets"));
        assert!(err(route(&[])).contains("target must not be empty"));
        assert!(err(route(&["http://a:1", "http://a:1/"])).contains("twice"));
        assert!(err(route(&["http://a:1", "ftp://b"])).contains("http://"));
        let single = UpstreamRoute {
            target: "http://a:1".into(),
            health_check: HealthCheckCfg {
                path: "/healthz".into(),
                ..Default::default()
            },
            ..route(&[])
        };
        assert!(err(single).contains("health_check needs a pool"));

        let pool = Pool::from_route(&route(&["http://a:1/", "https://b"]), "api").unwrap();
        assert!(pool.is_pool());
        assert_eq!(pool.primary(), "http://a:1");
        assert_eq!(pool.targets[1].label, "https://b:443");
        assert!(pool.health_check.is_none(), "passive only without a path");
    }

    #[test]
    fn health_settings_must_parse_and_mean_something() {
        let with = |hc: HealthCheckCfg| UpstreamRoute {
            health_check: hc,
            ..route(&["http://a:1"])
        };
        let hc = |path: &str| HealthCheckCfg {
            path: path.into(),
            ..Default::default()
        };
        assert!(err(with(hc("healthz"))).contains("must start with '/'"));
        assert!(err(with(HealthCheckCfg {
            interval: "0".into(),
            ..hc("/h")
        }))
        .contains("health_check.interval must be more than 0"));
        assert!(err(with(HealthCheckCfg {
            timeout: "soon".into(),
            ..hc("/h")
        }))
        .contains("health_check.timeout"));
        assert!(err(with(HealthCheckCfg {
            healthy_after: 0,
            ..hc("/h")
        }))
        .contains("at least 1"));
        assert!(err(UpstreamRoute {
            eject_for: "0s".into(),
            ..route(&["http://a:1"])
        })
        .contains("eject_for"));
        // Ejection off: eject_for is not read.
        assert!(Pool::from_route(
            &UpstreamRoute {
                eject_after: 0,
                eject_for: "never".into(),
                ..route(&["http://a:1"])
            },
            "api"
        )
        .is_ok());
        let pool = Pool::from_route(&with(hc("/healthz")), "api").unwrap();
        let hc = pool.health_check.unwrap();
        assert_eq!(
            (hc.interval, hc.timeout),
            (Duration::from_secs(5), Duration::from_secs(2))
        );
    }

    #[test]
    fn requests_go_to_the_first_target_in_rotation_and_to_all_when_none_is() {
        let pool =
            Pool::from_route(&route(&["http://a:1", "http://b:1", "http://c:1"]), "api").unwrap();
        let bases =
            |p: &Pool| -> Vec<String> { p.order().iter().map(|t| t.base.to_string()).collect() };
        assert_eq!(bases(&pool), ["http://a:1", "http://b:1", "http://c:1"]);
        pool.connect_failed(&pool.targets[0], "refused");
        assert_eq!(bases(&pool), ["http://b:1", "http://c:1"]);
        assert!(pool.any_in_rotation());
        pool.connect_failed(&pool.targets[1], "refused");
        pool.connect_failed(&pool.targets[2], "refused");
        assert!(!pool.any_in_rotation());
        assert_eq!(
            bases(&pool),
            ["http://a:1", "http://b:1", "http://c:1"],
            "nothing in rotation: try them all"
        );
        // An ejected target that answers is back.
        pool.answered(&pool.targets[1], 200);
        assert_eq!(bases(&pool), ["http://b:1"]);
    }

    fn bases(p: &Pool) -> Vec<String> {
        p.order().iter().map(|t| t.base.to_string()).collect()
    }

    #[test]
    fn round_robin_takes_the_targets_in_rotation_in_turn() {
        let cfg = UpstreamRoute {
            balance: "round_robin".into(),
            ..route(&["http://a:1", "http://b:1", "http://c:1"])
        };
        let pool = Pool::from_route(&cfg, "api").unwrap();
        assert_eq!(pool.balance, Balance::RoundRobin);
        let firsts: Vec<String> = (0..6).map(|_| bases(&pool)[0].clone()).collect();
        assert_eq!(
            firsts,
            [
                "http://a:1",
                "http://b:1",
                "http://c:1",
                "http://a:1",
                "http://b:1",
                "http://c:1"
            ]
        );
        // Each request still has every target to fail over to, from its own start.
        assert_eq!(bases(&pool), ["http://a:1", "http://b:1", "http://c:1"]);
        assert_eq!(bases(&pool), ["http://b:1", "http://c:1", "http://a:1"]);

        // One out: the others share its turns.
        pool.connect_failed(&pool.targets[1], "refused");
        let firsts: std::collections::HashMap<String, usize> =
            (0..10).fold(Default::default(), |mut m, _| {
                *m.entry(bases(&pool)[0].clone()).or_default() += 1;
                m
            });
        assert_eq!(firsts.get("http://a:1"), Some(&5));
        assert_eq!(firsts.get("http://c:1"), Some(&5));
        assert_eq!(firsts.get("http://b:1"), None);
    }

    fn weighted(entries: &[(&str, Option<u32>)]) -> UpstreamRoute {
        UpstreamRoute {
            path: "/api".into(),
            balance: "round_robin".into(),
            targets: entries
                .iter()
                .map(|(url, weight)| crate::config::TargetCfg {
                    url: url.to_string(),
                    weight: *weight,
                })
                .collect(),
            ..Default::default()
        }
    }

    fn firsts(pool: &Pool, n: usize) -> Vec<String> {
        (0..n)
            .map(|_| bases(pool)[0].trim_start_matches("http://").to_string())
            .collect()
    }

    #[test]
    fn weights_interleave_each_targets_share_of_every_cycle() {
        let pool = Pool::from_route(
            &weighted(&[
                ("http://a:1", Some(3)),
                ("http://b:1", None),
                ("http://c:1", Some(2)),
            ]),
            "api",
        )
        .unwrap();
        assert_eq!(
            firsts(&pool, 12),
            ["a:1", "b:1", "c:1", "a:1", "c:1", "a:1", "a:1", "b:1", "c:1", "a:1", "c:1", "a:1"]
        );
        // A request still fails over to every other target, from the one whose turn it is.
        assert_eq!(bases(&pool), ["http://a:1", "http://b:1", "http://c:1"]);
        assert_eq!(bases(&pool), ["http://b:1", "http://c:1", "http://a:1"]);

        // c out: a and b keep their 3 : 1, over the turns they now share.
        pool.connect_failed(&pool.targets[2], "refused");
        let counts = firsts(&pool, 400).into_iter().fold(
            std::collections::HashMap::<String, usize>::new(),
            |mut m, t| {
                *m.entry(t).or_default() += 1;
                m
            },
        );
        assert_eq!(counts.get("a:1"), Some(&300));
        assert_eq!(counts.get("b:1"), Some(&100));
        assert_eq!(counts.get("c:1"), None);
    }

    #[test]
    fn equal_weights_are_plain_round_robin() {
        let plain = Pool::from_route(
            &weighted(&[
                ("http://a:1", None),
                ("http://b:1", None),
                ("http://c:1", None),
            ]),
            "api",
        )
        .unwrap();
        let heavy = Pool::from_route(
            &weighted(&[
                ("http://a:1", Some(7)),
                ("http://b:1", Some(7)),
                ("http://c:1", Some(7)),
            ]),
            "api",
        )
        .unwrap();
        assert_eq!(firsts(&plain, 9), firsts(&heavy, 9));
        assert_eq!(firsts(&plain, 3), ["a:1", "b:1", "c:1"]);
    }

    #[test]
    fn a_weight_needs_round_robin_and_must_be_at_least_one() {
        let mut cfg = weighted(&[("http://a:1", Some(2)), ("http://b:1", None)]);
        cfg.balance = "priority".into();
        assert!(err(cfg).contains("weights only apply to balance = \"round_robin\""));
        assert!(
            err(weighted(&[("http://a:1", Some(0)), ("http://b:1", None)])).contains("weight 0")
        );
        // In backup too: balanced the same way.
        let mut cfg = weighted(&[("http://a:1", None)]);
        cfg.backup = vec![crate::config::TargetCfg {
            url: "http://x:1".into(),
            weight: Some(0),
        }];
        assert!(err(cfg).contains("weight 0"));
    }

    #[test]
    fn targets_are_urls_or_tables_and_a_misspelled_key_is_an_error() {
        let parse = |toml_text: &str| toml::from_str::<crate::config::Config>(toml_text);
        let cfg = parse(
            r#"
            [[upstreams]]
            path = "/"
            balance = "round_robin"
            targets = ["http://a:1", { url = "http://b:1", weight = 3 }]
            backup = [{ url = "http://x:1" }]
            "#,
        )
        .unwrap();
        let u = &cfg.upstreams[0];
        assert_eq!(u.targets[0], "http://a:1".into());
        assert_eq!(u.targets[1].weight, Some(3));
        assert_eq!(u.backup[0].url, "http://x:1");
        let pool = Pool::from_route(u, "app").unwrap();
        assert_eq!(pool.targets[1].weight, 3);
        assert_eq!(pool.targets[0].weight, 1);

        let e = parse(
            r#"
            [[upstreams]]
            path = "/"
            targets = [{ url = "http://b:1", wieght = 3 }]
            "#,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("unknown field `wieght`"), "{e}");
        assert!(parse("[[upstreams]]\npath = \"/\"\ntargets = [3]\n").is_err());
    }

    #[test]
    fn backup_targets_come_after_the_others_and_alone_only_when_none_is_in_rotation() {
        let cfg = UpstreamRoute {
            backup: vec!["http://x:1".into(), "http://y:1".into()],
            ..route(&["http://a:1", "http://b:1"])
        };
        let pool = Pool::from_route(&cfg, "api").unwrap();
        assert!(pool.targets[2].backup && !pool.targets[1].backup);
        // A request refused by both a and b still reaches a backup.
        assert_eq!(
            bases(&pool),
            ["http://a:1", "http://b:1", "http://x:1", "http://y:1"]
        );
        pool.connect_failed(&pool.targets[0], "refused");
        pool.connect_failed(&pool.targets[1], "refused");
        assert_eq!(bases(&pool), ["http://x:1", "http://y:1"]);
        pool.connect_failed(&pool.targets[2], "refused");
        pool.connect_failed(&pool.targets[3], "refused");
        assert_eq!(
            bases(&pool),
            ["http://a:1", "http://b:1", "http://x:1", "http://y:1"],
            "nothing in rotation: every target, main ones first"
        );

        // Round-robin turns within each tier.
        let rr = Pool::from_route(
            &UpstreamRoute {
                balance: "round_robin".into(),
                ..cfg
            },
            "api",
        )
        .unwrap();
        assert_eq!(
            bases(&rr),
            ["http://a:1", "http://b:1", "http://x:1", "http://y:1"]
        );
        assert_eq!(
            bases(&rr),
            ["http://b:1", "http://a:1", "http://y:1", "http://x:1"]
        );
    }

    #[test]
    fn pool_settings_need_a_pool_and_balance_is_one_of_four() {
        let single = |f: fn(&mut UpstreamRoute)| {
            let mut cfg = UpstreamRoute {
                target: "http://a:1".into(),
                ..route(&[])
            };
            f(&mut cfg);
            err(cfg)
        };
        assert!(single(|c| c.balance = "round_robin".into()).contains("balance needs a pool"));
        assert!(single(|c| c.backup = vec!["http://b:1".into()]).contains("backup needs a pool"));
        assert!(err(UpstreamRoute {
            balance: "random".into(),
            ..route(&["http://a:1"])
        })
        .contains("expected \"priority\", \"round_robin\", \"least_conn\" or \"hash\""));
        assert!(err(UpstreamRoute {
            backup: vec!["http://a:1/".into()],
            ..route(&["http://a:1"])
        })
        .contains("twice"));
        assert!(err(UpstreamRoute {
            backup: vec!["gopher://b".into()],
            ..route(&["http://a:1"])
        })
        .contains("upstreams[].backup"));
    }

    #[test]
    fn ejection_takes_eject_after_failures_in_a_row_and_ends_after_eject_for() {
        let cfg = UpstreamRoute {
            eject_after: 2,
            eject_for: "150ms".into(),
            ..route(&["http://a:1", "http://b:1"])
        };
        let pool = Pool::from_route(&cfg, "api").unwrap();
        let a = &pool.targets[0];
        pool.connect_failed(a, "refused");
        pool.answered(a, 404);
        pool.connect_failed(a, "refused");
        assert!(
            a.health.is_in_rotation(),
            "an answer in between resets the count"
        );
        pool.connect_failed(a, "refused");
        assert!(!a.health.is_in_rotation());
        std::thread::sleep(Duration::from_millis(200));
        assert!(a.health.is_in_rotation(), "back after eject_for");

        let off = Pool::from_route(
            &UpstreamRoute {
                eject_after: 0,
                ..route(&["http://a:1", "http://b:1"])
            },
            "api",
        )
        .unwrap();
        off.connect_failed(&off.targets[0], "refused");
        assert!(off.targets[0].health.is_in_rotation(), "eject_after = 0");

        // A single target is never ejected: it is all there is.
        let single = Pool::single("http://a:1");
        single.connect_failed(&single.targets[0], "refused");
        assert!(single.any_in_rotation());
    }

    fn five_xx_pool(targets: &[&str], backup: &[&str], after: u32) -> Pool {
        let cfg = UpstreamRoute {
            eject_after_5xx: after,
            backup: backup.iter().map(|b| (*b).into()).collect(),
            ..route(targets)
        };
        Pool::from_route(&cfg, "api").unwrap()
    }

    #[test]
    fn five_xx_answers_in_a_row_eject_and_any_other_answer_resets_the_count() {
        let pool = five_xx_pool(&["http://a:1", "http://b:1"], &[], 3);
        let a = &pool.targets[0];
        pool.answered(a, 500);
        pool.answered(a, 503);
        pool.answered(a, 404);
        pool.answered(a, 502);
        pool.answered(a, 500);
        assert!(
            a.health.is_in_rotation(),
            "a 404 in between: two in a row, not three"
        );
        pool.answered(a, 504);
        assert!(!a.health.is_in_rotation());
        assert_eq!(a.health.ejected_reason(), Some(Ejection::Http5xx));
        assert_eq!(a.health.ejections(Ejection::Http5xx), 1);
        assert_eq!(a.health.ejections(Ejection::ConnectError), 0);
        assert_eq!(bases(&pool), ["http://b:1"]);

        // Off by default.
        let off = five_xx_pool(&["http://a:1", "http://b:1"], &[], 0);
        for _ in 0..20 {
            off.answered(&off.targets[0], 500);
        }
        assert!(off.targets[0].health.is_in_rotation());
    }

    #[test]
    fn five_xx_never_takes_out_the_last_target_in_rotation() {
        let pool = five_xx_pool(&["http://a:1", "http://b:1"], &[], 2);
        let (a, b) = (&pool.targets[0], &pool.targets[1]);
        pool.answered(a, 500);
        pool.answered(a, 500);
        assert!(!a.health.is_in_rotation());
        for _ in 0..5 {
            pool.answered(b, 500);
        }
        assert!(
            b.health.is_in_rotation(),
            "the last one stays: rotation cannot fix this"
        );
        assert_eq!(pool.state(), "normal");

        // A backup in rotation is another target: the main ones can all go.
        let pool = five_xx_pool(&["http://a:1"], &["http://x:1"], 1);
        pool.answered(&pool.targets[0], 500);
        assert_eq!(pool.state(), "backup");
        pool.answered(&pool.targets[1], 500);
        assert!(pool.targets[1].health.is_in_rotation());
    }

    #[test]
    fn an_ejected_target_is_back_only_on_an_answer_below_500() {
        let pool = five_xx_pool(&["http://a:1", "http://b:1"], &[], 1);
        let (a, b) = (&pool.targets[0], &pool.targets[1]);
        pool.connect_failed(a, "refused");
        pool.connect_failed(b, "refused");
        assert_eq!(pool.state(), "all_out");
        // Nothing in rotation, so requests reach them anyway. A 5xx is no sign it is back.
        pool.answered(a, 500);
        assert!(!a.health.is_in_rotation());
        pool.answered(a, 200);
        assert!(a.health.is_in_rotation());
        assert_eq!(a.health.ejected_reason(), Some(Ejection::ConnectError));
    }

    #[test]
    fn five_xx_from_a_target_already_out_does_not_eject_it_again() {
        // A request in flight when its target left rotation can still bring back a 5xx.
        let pool = five_xx_pool(&["http://a:1", "http://b:1"], &[], 1);
        let a = &pool.targets[0];
        pool.connect_failed(a, "refused");
        pool.answered(a, 500);
        assert_eq!(a.health.ejections(Ejection::Http5xx), 0);
        assert_eq!(a.health.ejected_reason(), Some(Ejection::ConnectError));
    }

    #[test]
    fn after_a_5xx_ejection_the_count_starts_over() {
        let cfg = UpstreamRoute {
            eject_after_5xx: 2,
            eject_for: "100ms".into(),
            ..route(&["http://a:1", "http://b:1"])
        };
        let pool = Pool::from_route(&cfg, "api").unwrap();
        let a = &pool.targets[0];
        pool.answered(a, 500);
        pool.answered(a, 500);
        assert!(!a.health.is_in_rotation());
        std::thread::sleep(Duration::from_millis(150));
        assert!(a.health.is_in_rotation());
        pool.answered(a, 500);
        assert!(
            a.health.is_in_rotation(),
            "one 5xx since it came back, not two"
        );
        pool.answered(a, 500);
        assert!(!a.health.is_in_rotation());
        assert_eq!(a.health.ejections(Ejection::Http5xx), 2);
    }

    #[test]
    fn five_xx_ejection_needs_a_pool_and_an_eject_for() {
        assert!(err(UpstreamRoute {
            target: "http://a:1".into(),
            eject_after_5xx: 3,
            ..route(&[])
        })
        .contains("eject_after_5xx needs a pool"));
        assert!(err(UpstreamRoute {
            eject_after: 0,
            eject_after_5xx: 3,
            eject_for: "0s".into(),
            ..route(&["http://a:1"])
        })
        .contains("eject_for"));
    }

    fn least_conn(entries: &[(&str, Option<u32>)]) -> Pool {
        let mut cfg = weighted(entries);
        cfg.balance = "least_conn".into();
        Pool::from_route(&cfg, "api").unwrap()
    }

    #[test]
    fn least_conn_sends_each_request_to_the_target_with_the_fewest_in_flight() {
        let pool = least_conn(&[
            ("http://a:1", None),
            ("http://b:1", None),
            ("http://c:1", None),
        ]);
        // Idle: ties are taken in turn, so requests still spread.
        assert_eq!(firsts(&pool, 3), ["a:1", "b:1", "c:1"]);

        let busy: Vec<_> = [0, 0, 2]
            .iter()
            .filter_map(|&i| pool.start(&pool.targets[i]))
            .collect();
        assert_eq!(pool.targets[0].health.in_flight.load(Ordering::Relaxed), 2);
        assert_eq!(bases(&pool)[0], "http://b:1", "a has 2, c has 1, b none");
        let b_busy = pool.start(&pool.targets[1]);
        // b and c tie at one each: the turn decides between them; a stays last choice.
        let picks: Vec<String> = firsts(&pool, 4);
        assert!(picks.iter().all(|p| p != "a:1"), "{picks:?}");
        assert!(picks.contains(&"b:1".to_string()) && picks.contains(&"c:1".to_string()));

        // Finished requests are no longer counted.
        drop(busy);
        drop(b_busy);
        for t in &pool.targets {
            assert_eq!(t.health.in_flight.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn least_conn_weighs_in_flight_by_weight() {
        // (in flight + 1) / weight: idle, the weight-3 target goes first.
        let pool = least_conn(&[("http://a:1", Some(3)), ("http://b:1", None)]);
        assert_eq!(bases(&pool)[0], "http://a:1");
        let _one = pool.start(&pool.targets[0]);
        assert_eq!(bases(&pool)[0], "http://a:1", "2/3 is still under 1/1");
        let _two = pool.start(&pool.targets[0]);
        // 3/3 against 1/1: a tie, taken in turn.
        let picks = firsts(&pool, 2);
        assert!(picks.contains(&"b:1".to_string()), "{picks:?}");
        let _three = pool.start(&pool.targets[0]);
        assert_eq!(bases(&pool)[0], "http://b:1", "4/3 is over 1/1");
    }

    #[test]
    fn only_least_conn_pools_count_requests_in_flight() {
        let rr = Pool::from_route(&weighted(&[("http://a:1", None)]), "api").unwrap();
        assert!(rr.start(&rr.targets[0]).is_none());
        let single = Pool::single("http://a:1");
        assert!(single.start(&single.targets[0]).is_none());
    }

    #[test]
    fn repeat_ejections_last_longer_up_to_eject_for_max_and_start_over_after_it() {
        let h = TargetHealth::default();
        let (base, max) = (Duration::from_secs(30), Duration::from_secs(80));
        let t0 = 1_000;
        assert_eq!(
            h.eject(t0, base, max, Ejection::ConnectError),
            (1, Duration::from_secs(30))
        );
        // Ejected again 10s after coming back: twice as long, then capped.
        let t1 = t0 + 40_000;
        assert_eq!(
            h.eject(t1, base, max, Ejection::Http5xx),
            (2, Duration::from_secs(60))
        );
        let t2 = t1 + 70_000;
        assert_eq!(h.eject(t2, base, max, Ejection::Http5xx), (3, max));
        assert_eq!(h.ejections_in_a_row(t2 + 1, max), 3);
        // eject_for_max since that one ended without another: the count starts over.
        let back = t2 + 80_000;
        assert_eq!(h.ejections_in_a_row(back + 79_999, max), 3);
        assert_eq!(h.ejections_in_a_row(back + 80_000, max), 0);
        assert_eq!(
            h.eject(back + 80_000, base, max, Ejection::ConnectError),
            (1, base)
        );
    }

    #[test]
    fn eject_for_max_defaults_to_five_minutes_and_is_never_under_eject_for() {
        let max_of = |cfg: UpstreamRoute| Pool::from_route(&cfg, "api").unwrap().eject_for_max;
        assert_eq!(max_of(route(&["http://a:1"])), Duration::from_secs(300));
        assert_eq!(
            max_of(UpstreamRoute {
                eject_for: "10m".into(),
                ..route(&["http://a:1"])
            }),
            Duration::from_secs(600),
            "a longer eject_for is the floor"
        );
        assert_eq!(
            max_of(UpstreamRoute {
                eject_for_max: "30s".into(),
                ..route(&["http://a:1"])
            }),
            Duration::from_secs(30),
            "equal to eject_for: no growth"
        );
        assert!(err(UpstreamRoute {
            eject_for_max: "10s".into(),
            ..route(&["http://a:1"])
        })
        .contains("shorter than eject_for"));
    }

    #[test]
    fn expect_status_takes_codes_ranges_and_classes() {
        assert_eq!(parse_statuses("200").unwrap(), [(200, 200)]);
        assert_eq!(parse_statuses("2xx").unwrap(), [(200, 299)]);
        assert_eq!(
            parse_statuses("200-299, 304").unwrap(),
            [(200, 299), (304, 304)]
        );
        for bad in ["", "ok", "600", "6xx", "300-200", "200,", "2x"] {
            assert!(parse_statuses(bad).is_err(), "{bad:?}");
        }
        let with = |expect: &str| {
            let cfg = UpstreamRoute {
                health_check: HealthCheckCfg {
                    path: "/h".into(),
                    expect_status: expect.into(),
                    ..Default::default()
                },
                ..route(&["http://a:1"])
            };
            Pool::from_route(&cfg, "api")
        };
        let hc = with("200,204").unwrap().health_check.unwrap();
        assert!(hc.passes(200) && hc.passes(204));
        assert!(!hc.passes(301) && !hc.passes(202));
        let default = with("200-399").unwrap().health_check.unwrap();
        assert!(default.passes(302) && !default.passes(404));
        let e = format!("{:#}", with("20x").unwrap_err());
        assert!(e.contains("health_check.expect_status"), "{e}");
    }

    #[test]
    fn checks_move_a_target_out_and_back_after_their_thresholds() {
        let hc = HealthCheck {
            path: "/h".into(),
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            healthy_after: 2,
            unhealthy_after: 3,
            expect_status: "200-399".into(),
            expect: vec![(200, 399)],
            kind: CheckKind::Http,
            expect_body: String::new(),
            expect_body_regex: String::new(),
            body: None,
            method: Method::GET,
            headers: HeaderMap::new(),
            header_names: Vec::new(),
            port: None,
        };
        let h = TargetHealth::default();
        assert_eq!(h.checked(false, &hc), None);
        assert_eq!(h.checked(false, &hc), None);
        assert_eq!(h.checked(true, &hc), None, "a pass resets the failures");
        assert_eq!(h.checked(false, &hc), None);
        assert_eq!(h.checked(false, &hc), None);
        assert_eq!(h.checked(false, &hc), Some(false));
        assert!(!h.is_in_rotation());
        assert_eq!(h.checked(true, &hc), None);
        assert_eq!(h.checked(true, &hc), Some(true));
        assert!(h.is_in_rotation());
        assert_eq!(h.checks(), (3, 5));
    }

    #[test]
    fn a_check_is_claimed_once_per_interval() {
        let h = TargetHealth::default();
        let now = now_ms();
        assert_eq!(h.claim_check(now, Duration::from_secs(5)), Ok(()));
        assert_eq!(
            h.claim_check(now, Duration::from_secs(5)),
            Err(Some(now + 5000))
        );
        // Due again, but the last one is still running.
        assert_eq!(h.claim_check(now + 5000, Duration::from_secs(5)), Err(None));
        h.checking.store(false, Ordering::Release);
        assert_eq!(h.claim_check(now + 5000, Duration::from_secs(5)), Ok(()));
    }

    #[test]
    fn a_reload_keeps_the_health_of_the_targets_it_keeps() {
        let old = Pool::from_route(&route(&["http://a:1", "http://b:1"]), "api").unwrap();
        old.connect_failed(&old.targets[0], "refused");
        let mut new = Pool::from_route(&route(&["http://c:1", "http://a:1"]), "api").unwrap();
        new.carry_health_from(&old);
        assert!(
            new.targets[0].health.is_in_rotation(),
            "new: starts in rotation"
        );
        assert!(
            !new.targets[1].health.is_in_rotation(),
            "kept: still ejected"
        );
        assert!(Arc::ptr_eq(&new.targets[1].health, &old.targets[0].health));
    }

    #[test]
    fn a_reload_that_drops_the_health_check_drops_its_verdict() {
        let checked = |path: &str| UpstreamRoute {
            health_check: HealthCheckCfg {
                path: path.into(),
                unhealthy_after: 1,
                ..Default::default()
            },
            ..route(&["http://a:1", "http://b:1"])
        };
        let old = Pool::from_route(&checked("/h"), "api").unwrap();
        let hc = old.health_check.clone().unwrap();
        assert_eq!(old.targets[0].health.checked(false, &hc), Some(false));
        // One pass of the two that would bring it back.
        assert_eq!(old.targets[0].health.checked(true, &hc), None);
        assert_eq!(old.targets[0].health.streak.load(Ordering::Relaxed), 1);
        // Still checked: the verdict stands until the check says otherwise.
        let mut still = Pool::from_route(&checked("/healthz"), "api").unwrap();
        still.carry_health_from(&old);
        assert!(!still.targets[0].health.is_in_rotation());
        // No longer checked: nothing could bring it back, so it is back now.
        let mut unchecked = Pool::from_route(&checked(""), "api").unwrap();
        unchecked.carry_health_from(&old);
        assert!(unchecked.targets[0].health.is_in_rotation());
        assert_eq!(
            unchecked.targets[0].health.streak.load(Ordering::Relaxed),
            0
        );
    }

    fn hashed(on: &str, targets: &[(&str, u32)]) -> Pool {
        let cfg = UpstreamRoute {
            balance: "hash".into(),
            hash_on: on.into(),
            targets: targets
                .iter()
                .map(|(url, w)| crate::config::TargetCfg {
                    url: url.to_string(),
                    weight: Some(*w),
                })
                .collect(),
            ..route(&[])
        };
        Pool::from_route(&cfg, "api").unwrap()
    }

    fn keyed(key: &str) -> Affinity {
        Affinity {
            key: Some(hash64(key.as_bytes())),
            stuck: None,
        }
    }

    fn ranked(pool: &Pool, a: &Affinity) -> Vec<String> {
        pool.order_for(a)
            .iter()
            .map(|t| t.base.trim_start_matches("http://").to_string())
            .collect()
    }

    #[test]
    fn hashing_is_pinned_so_every_edge_of_any_version_agrees() {
        // From an independent implementation. If these change, every fleet's keys and sticky
        // cookies move to other targets on upgrade.
        assert_eq!(hash64(b""), 0xefd0_1f60_ba99_2926);
        assert_eq!(hash64(b"user-1"), 0x41a2_fca5_c684_01c5);
        let pool = hashed(
            "header:x-user",
            &[("http://a:1", 1), ("http://b:1", 1), ("http://c:1", 1)],
        );
        assert_eq!(pool.targets[0].id, 0x90f6_0739_6ac2_3bec);
        assert_eq!(ranked(&pool, &keyed("user-1")), ["a:1", "c:1", "b:1"]);
        assert_eq!(ranked(&pool, &keyed("user-2")), ["c:1", "a:1", "b:1"]);
        assert_eq!(ranked(&pool, &keyed("user-3")), ["b:1", "a:1", "c:1"]);
    }

    #[test]
    fn a_key_goes_to_one_target_and_keys_spread_by_weight() {
        let pool = hashed(
            "",
            &[("http://a:1", 1), ("http://b:1", 1), ("http://c:1", 2)],
        );
        assert_eq!(pool.hash_on, Some(HashOn::ClientIp));
        let mut won = std::collections::HashMap::new();
        for i in 0..20_000 {
            let key = keyed(&format!("k{i}"));
            let first = ranked(&pool, &key);
            assert_eq!(first, ranked(&pool, &key), "the same key, the same order");
            *won.entry(first[0].clone()).or_insert(0u32) += 1;
        }
        let share = |t: &str| f64::from(won[t]) / 20_000.0;
        assert!((share("a:1") - 0.25).abs() < 0.02, "{won:?}");
        assert!((share("b:1") - 0.25).abs() < 0.02, "{won:?}");
        assert!((share("c:1") - 0.5).abs() < 0.02, "{won:?}");
        assert_eq!(
            pool.turn.load(Ordering::Relaxed),
            0,
            "a keyed pick takes no turn"
        );
    }

    #[test]
    fn a_target_leaving_rotation_moves_only_its_keys_to_their_next_choice() {
        let pool = hashed(
            "",
            &[("http://a:1", 1), ("http://b:1", 1), ("http://c:1", 1)],
        );
        let keys: Vec<Affinity> = (0..3000).map(|i| keyed(&format!("k{i}"))).collect();
        let before: Vec<Vec<String>> = keys.iter().map(|k| ranked(&pool, k)).collect();
        let max = Duration::from_secs(60);
        pool.targets[2]
            .health
            .eject(now_ms(), max, max, Ejection::ConnectError);
        let mut moved = 0;
        for (key, was) in keys.iter().zip(&before) {
            let now = ranked(&pool, key);
            assert_eq!(now.len(), 2);
            if was[0] == "c:1" {
                // Where a request that could not connect to c would have gone next.
                assert_eq!(now[0], was[1]);
                moved += 1;
            } else {
                assert_eq!(now[0], was[0], "a key c did not have moved");
            }
        }
        assert!((800..1200).contains(&moved), "c had about a third: {moved}");
    }

    #[test]
    fn a_request_without_its_key_is_balanced_in_turn() {
        let pool = hashed("header:x-user", &[("http://a:1", 1), ("http://b:1", 1)]);
        let firsts: Vec<String> = (0..4)
            .map(|_| ranked(&pool, &Affinity::default())[0].clone())
            .collect();
        assert_eq!(firsts, ["a:1", "b:1", "a:1", "b:1"]);
        // A key on a pool that does not hash changes nothing.
        let rr = Pool::from_route(
            &weighted(&[("http://a:1", None), ("http://b:1", None)]),
            "api",
        )
        .unwrap();
        let firsts: Vec<String> = (0..2)
            .map(|_| ranked(&rr, &keyed("x"))[0].clone())
            .collect();
        assert_eq!(firsts, ["a:1", "b:1"]);
    }

    #[test]
    fn affinity_reads_the_key_hash_on_names_and_nothing_else() {
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-user", HeaderValue::from_static("alice"));
        h.append(header::COOKIE, HeaderValue::from_static("a=1; sid=bob"));
        h.append(header::COOKIE, HeaderValue::from_static("sid=carol"));
        let key = |on: &str, headers: &HeaderMap, uri: &str, ip: IpAddr| {
            hashed(on, &[("http://a:1", 1)])
                .affinity(headers, &uri.parse().unwrap(), ip)
                .key
        };
        let hash = |s: &str| Some(hash64(s.as_bytes()));
        assert_eq!(key("header:X-User", &h, "/", ip), hash("alice"));
        assert_eq!(key("header:x-other", &h, "/", ip), None);
        assert_eq!(key("cookie:sid", &h, "/", ip), hash("bob"), "the first one");
        assert_eq!(key("cookie:none", &h, "/", ip), None);
        assert_eq!(key("path", &h, "/api/x", ip), hash("/api/x"));
        assert_eq!(
            key("path", &h, "/api/x?u=1", ip),
            hash("/api/x"),
            "without the query"
        );
        // A query parameter: its value as sent, the first if it repeats, nothing if empty.
        let q = |uri: &str| key("query:u", &h, uri, ip);
        assert_eq!(q("/a?u=alice"), hash("alice"));
        assert_eq!(q("/a?x=1&u=alice&u=bob"), hash("alice"));
        assert_eq!(q("/a?u=a%20b"), hash("a%20b"), "not decoded");
        assert_eq!(q("/a?uu=alice&xu=1"), None, "the whole name");
        assert_eq!(q("/a?u=&u=bob"), None, "the first is empty");
        assert_eq!(q("/a?u"), None);
        assert_eq!(q("/a"), None);
        assert_eq!(key("client_ip", &h, "/", ip), Some(hash64(&[10, 0, 0, 7])));
        let mapped: IpAddr = "::ffff:10.0.0.7".parse().unwrap();
        assert_eq!(
            key("client_ip", &h, "/", mapped),
            Some(hash64(&[10, 0, 0, 7]))
        );
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_ne!(key("client_ip", &h, "/", v6), key("client_ip", &h, "/", ip));
        let mut empty = HeaderMap::new();
        empty.insert("x-user", HeaderValue::from_static(""));
        empty.insert(header::COOKIE, HeaderValue::from_static("sid="));
        assert_eq!(key("header:x-user", &empty, "/", ip), None);
        assert_eq!(key("cookie:sid", &empty, "/", ip), None);
        // A pool that neither hashes nor sticks reads nothing.
        let plain = Pool::from_route(&route(&["http://a:1"]), "api").unwrap();
        let a = plain.affinity(&h, &"/?u=1".parse().unwrap(), ip);
        assert_eq!((a.key, a.stuck), (None, None));
    }

    fn sticky(cookie: &str) -> Pool {
        let cfg = UpstreamRoute {
            balance: "round_robin".into(),
            sticky_cookie: cookie.into(),
            backup: vec!["http://c:1".into()],
            ..route(&["http://a:1", "http://b:1"])
        };
        Pool::from_route(&cfg, "api").unwrap()
    }

    fn carrying(pool: &Pool, cookie: &str) -> Affinity {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        pool.affinity(&h, &"/api".parse().unwrap(), "127.0.0.1".parse().unwrap())
    }

    #[test]
    fn a_sticky_cookie_puts_its_target_first_while_it_is_in_rotation() {
        let pool = sticky("eg");
        let id = |i: usize| format!("{:016x}", pool.targets[i].id);
        let on_b = carrying(&pool, &format!("other=1; eg={}", id(1)));
        assert_eq!(on_b.stuck, Some(pool.targets[1].id));
        for _ in 0..4 {
            assert_eq!(ranked(&pool, &on_b), ["b:1", "a:1", "c:1"]);
        }
        // The first one naming a target of this pool, as another route's may come first.
        let two = carrying(&pool, &format!("eg=00000000000000ff; eg={}", id(1)));
        assert_eq!(two.stuck, Some(pool.targets[1].id));
        // Not a backup ahead of a target that is in rotation.
        let on_c = carrying(&pool, &format!("eg={}", id(2)));
        assert_eq!(ranked(&pool, &on_c)[0], "a:1");
        // Naming no target of this pool, or not hex: as if there were none.
        for bad in [
            "eg=0123456789abcdef",
            "eg=zzzzzzzzzzzzzzzz",
            "eg=",
            "other=x",
        ] {
            assert_eq!(carrying(&pool, bad).stuck, None, "{bad}");
        }
        // Out of rotation: balanced as usual.
        let max = Duration::from_secs(60);
        pool.targets[1]
            .health
            .eject(now_ms(), max, max, Ejection::ConnectError);
        assert_eq!(ranked(&pool, &on_b), ["a:1", "c:1"]);
        // With only backup left, a backup it names goes first.
        pool.targets[0]
            .health
            .eject(now_ms(), max, max, Ejection::ConnectError);
        assert_eq!(ranked(&pool, &on_c), ["c:1"]);
    }

    #[test]
    fn the_sticky_cookie_is_set_only_when_it_names_another_target() {
        let pool = sticky("eg");
        let (a, b) = (&pool.targets[0], &pool.targets[1]);
        let none = Affinity::default();
        assert_eq!(
            pool.sticky_cookie(&none, b).unwrap(),
            format!("eg={:016x}; Path=/api; HttpOnly; SameSite=Lax", b.id).as_str()
        );
        let on_b = carrying(&pool, &format!("eg={:016x}", b.id));
        assert!(pool.sticky_cookie(&on_b, b).is_none());
        assert!(pool.sticky_cookie(&on_b, a).is_some(), "moved to a");
        let plain = Pool::from_route(&route(&["http://a:1"]), "api").unwrap();
        assert!(plain.sticky_cookie(&none, &plain.targets[0]).is_none());
    }

    fn sticky_with(f: impl FnOnce(&mut UpstreamRoute)) -> Result<Pool, String> {
        let mut cfg = UpstreamRoute {
            balance: "round_robin".into(),
            sticky_cookie: "eg".into(),
            ..route(&["http://a:1", "http://b:1"])
        };
        f(&mut cfg);
        Pool::from_route(&cfg, "api").map_err(|e| format!("{e:#}"))
    }

    #[test]
    fn a_sticky_cookie_can_last_a_while_and_be_kept_from_the_upstream() {
        let pool = sticky_with(|c| c.sticky_cookie_max_age = "8h".into()).unwrap();
        let b = &pool.targets[1];
        assert_eq!(
            pool.sticky_cookie(&Affinity::default(), b).unwrap(),
            format!(
                "eg={:016x}; Path=/api; Max-Age=28800; HttpOnly; SameSite=Lax",
                b.id
            )
            .as_str()
        );
        for (bad, why) in [
            ("0s", "at least 1s"),
            ("500ms", "at least 1s"),
            ("soon", "sticky_cookie_max_age = \"soon\""),
        ] {
            let e = sticky_with(|c| c.sticky_cookie_max_age = bad.into()).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        for e in [
            sticky_with(|c| {
                c.sticky_cookie.clear();
                c.sticky_cookie_max_age = "1h".into();
            }),
            sticky_with(|c| {
                c.sticky_cookie.clear();
                c.sticky_cookie_strip = true;
            }),
        ] {
            assert!(e.unwrap_err().contains("needs sticky_cookie"));
        }
        let single = |f: fn(&mut UpstreamRoute)| {
            let mut cfg = UpstreamRoute {
                target: "http://a:1".into(),
                ..route(&[])
            };
            f(&mut cfg);
            format!("{:#}", Pool::from_route(&cfg, "api").unwrap_err())
        };
        assert!(
            single(|c| c.sticky_cookie_strip = true).contains("sticky_cookie_strip needs a pool")
        );
        assert!(single(|c| c.sticky_cookie_max_age = "1h".into())
            .contains("sticky_cookie_max_age needs a pool"));
    }

    #[test]
    fn stripping_takes_out_the_sticky_cookie_and_keeps_the_rest() {
        let strip = |pool: &Pool, cookies: &[&[u8]]| {
            let mut h = HeaderMap::new();
            h.insert("x-other", HeaderValue::from_static("1"));
            for c in cookies {
                h.append(header::COOKIE, HeaderValue::from_bytes(c).unwrap());
            }
            pool.strip_sticky_cookie(&mut h);
            assert_eq!(h["x-other"], "1");
            h.get_all(header::COOKIE)
                .iter()
                .map(|v| v.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        let pool = sticky_with(|c| c.sticky_cookie_strip = true).unwrap();
        assert_eq!(
            strip(&pool, &[b"a=1; eg=00ff; b=2"]),
            [b"a=1; b=2".to_vec()]
        );
        assert_eq!(
            strip(&pool, &[b"eg=00ff"]),
            Vec::<Vec<u8>>::new(),
            "none left"
        );
        // Every one of that name, from every Cookie header, which become one.
        assert_eq!(
            strip(&pool, &[b"eg=1; a=1", b"eg=2", b" b=2 ;eg=3"]),
            [b"a=1; b=2".to_vec()]
        );
        // Only that name: not one it begins, nor a value that contains it.
        assert_eq!(
            strip(&pool, &[b"egg=1; x=eg=2; eg=3"]),
            [b"egg=1; x=eg=2".to_vec()]
        );
        // Bytes that are not UTF-8 pass through untouched.
        assert_eq!(
            strip(&pool, &[b"a=\xe9t\xe9; eg=1"]),
            [b"a=\xe9t\xe9".to_vec()]
        );
        // Without the cookie, the headers are left exactly as they came.
        assert_eq!(
            strip(&pool, &[b"a=1", b"b=2"]),
            [b"a=1".to_vec(), b"b=2".to_vec()]
        );
        // Off, nothing is touched.
        let keep = sticky_with(|_| {}).unwrap();
        assert_eq!(strip(&keep, &[b"a=1; eg=00ff"]), [b"a=1; eg=00ff".to_vec()]);
    }

    #[test]
    fn hash_and_sticky_settings_must_parse_and_need_a_pool() {
        let single = |f: fn(&mut UpstreamRoute)| {
            let mut cfg = UpstreamRoute {
                target: "http://a:1".into(),
                ..route(&[])
            };
            f(&mut cfg);
            err(cfg)
        };
        assert!(single(|c| c.hash_on = "path".into()).contains("hash_on needs a pool"));
        assert!(single(|c| c.sticky_cookie = "eg".into()).contains("sticky_cookie needs a pool"));
        fn with(f: impl FnOnce(&mut UpstreamRoute)) -> Result<Pool, String> {
            let mut cfg = route(&["http://a:1", "http://b:1"]);
            cfg.balance = "hash".into();
            f(&mut cfg);
            Pool::from_route(&cfg, "api").map_err(|e| format!("{e:#}"))
        }
        assert!(with(|c| c.balance = "round_robin".into())
            .unwrap()
            .hash_on
            .is_none());
        let needs = with(|c| {
            c.balance = "round_robin".into();
            c.hash_on = "path".into();
        });
        assert!(needs
            .unwrap_err()
            .contains("hash_on = \"path\" needs balance = \"hash\""));
        assert_eq!(
            with(|c| c.hash_on = "path".into()).unwrap().hash_on,
            Some(HashOn::Path)
        );
        assert_eq!(
            with(|c| c.hash_on = "cookie:sid".into()).unwrap().hash_on,
            Some(HashOn::Cookie("sid".into()))
        );
        let header = with(|c| c.hash_on = "header:X-User".into()).unwrap();
        assert_eq!(header.hash_on.as_ref().unwrap().label(), "header:x-user");
        for bad in [
            "ip",
            "header:",
            "header:bad name",
            "cookie:",
            "cookie:a;b",
            "query:",
            "query:a=b",
            "query:a&b",
            "query:a%20b",
            "query:a b",
        ] {
            let e = with(move |c| c.hash_on = bad.into());
            assert!(e.is_err(), "{bad}");
        }
        let query = with(|c| c.hash_on = "query:user_id".into()).unwrap();
        assert_eq!(query.hash_on, Some(HashOn::Query("user_id".into())));
        assert_eq!(query.hash_on.as_ref().unwrap().label(), "query:user_id");
        assert!(with(|c| c.hash_on = "random".into())
            .unwrap_err()
            .contains("\"cookie:<name>\" or \"query:<name>\""));
        // Weights rank keys too.
        let mut cfg = weighted(&[("http://a:1", Some(3)), ("http://b:1", None)]);
        cfg.balance = "hash".into();
        assert_eq!(Pool::from_route(&cfg, "api").unwrap().targets[0].weight, 3);
        assert!(with(|c| c.sticky_cookie = "e g".into())
            .unwrap_err()
            .contains("sticky_cookie = \"e g\" is not a cookie name"));
        assert!(with(|c| c.sticky_cookie = "a=b".into()).is_err());
        let spaced = with(|c| {
            c.sticky_cookie = "eg".into();
            c.path = "/a b".into();
        });
        assert!(spaced.unwrap_err().contains("cookie's Path"));
        let semicolon = with(|c| {
            c.sticky_cookie = "eg".into();
            c.path = "/a;b".into();
        });
        assert!(semicolon.unwrap_err().contains("cookie's Path"));
        assert!(with(|c| c.sticky_cookie = "__Host-eg".into()).is_ok());
    }

    #[test]
    fn the_status_names_the_hash_key_the_cookie_and_each_targets_cookie_value() {
        let pool = hashed("header:x-user", &[("http://a:1", 1)]);
        let j = pool.status_json(Some("/api"), |_| serde_json::json!({}));
        assert_eq!(j["hash_on"], "header:x-user");
        assert_eq!(j["sticky_cookie"], serde_json::Value::Null);
        assert!(j["targets"][0].get("sticky_cookie_value").is_none());
        let pool = sticky("eg");
        let j = pool.status_json(Some("/api"), |_| serde_json::json!({}));
        assert!(j.get("hash_on").is_none());
        assert_eq!(j["sticky_cookie"], "eg");
        assert_eq!(
            j["targets"][1]["sticky_cookie_value"],
            format!("{:016x}", pool.targets[1].id)
        );
    }

    #[test]
    fn a_check_takes_a_method_headers_and_a_regular_expression() {
        let with = |hc: HealthCheckCfg| UpstreamRoute {
            health_check: HealthCheckCfg {
                path: "/h".into(),
                ..hc
            },
            ..route(&["http://a:1"])
        };
        let check = |hc: HealthCheckCfg| {
            Pool::from_route(&with(hc), "api")
                .map(|p| p.health_check.unwrap())
                .map_err(|e| format!("{e:#}"))
        };
        let head = check(HealthCheckCfg {
            method: " head ".into(),
            headers: vec![
                ("Host".into(), "app.internal".into()),
                ("X-Probe".into(), "1".into()),
                ("x-probe".into(), "2".into()),
            ],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(head.method, Method::HEAD);
        assert_eq!(head.label(), "HEAD /h");
        assert_eq!(head.headers["host"], "app.internal");
        let probes: Vec<&HeaderValue> = head.headers.get_all("x-probe").iter().collect();
        assert_eq!(probes, ["1", "2"], "both, in order");
        assert!(head.headers[header::USER_AGENT]
            .to_str()
            .unwrap()
            .starts_with("edgeguard-health-check/"));
        assert_eq!(head.header_names, ["host", "x-probe"]);
        // One that names a User-Agent replaces the edge's.
        let ua = check(HealthCheckCfg {
            headers: vec![("User-Agent".into(), "probe/1".into())],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            ua.headers
                .get_all(header::USER_AGENT)
                .iter()
                .collect::<Vec<_>>(),
            ["probe/1"]
        );
        let custom = check(HealthCheckCfg {
            method: "OPTIONS".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(custom.label(), "OPTIONS /h");

        for (hc, why) in [
            (
                HealthCheckCfg {
                    method: "CONNECT".into(),
                    ..Default::default()
                },
                "asks for a tunnel",
            ),
            (
                HealthCheckCfg {
                    method: "GE T".into(),
                    ..Default::default()
                },
                "is not a method",
            ),
            (
                HealthCheckCfg {
                    method: "HEAD".into(),
                    expect_body: "ok".into(),
                    ..Default::default()
                },
                "HEAD\" gets no body",
            ),
            (
                HealthCheckCfg {
                    method: "HEAD".into(),
                    expect_body_regex: "ok".into(),
                    ..Default::default()
                },
                "HEAD\" gets no body",
            ),
            (
                HealthCheckCfg {
                    headers: vec![("Content-Length".into(), "0".into())],
                    ..Default::default()
                },
                "describes a body or a connection",
            ),
            (
                HealthCheckCfg {
                    headers: vec![("Bad Name".into(), "x".into())],
                    ..Default::default()
                },
                "is not a header name",
            ),
            (
                HealthCheckCfg {
                    headers: vec![("X-Ok".into(), "line\nbreak".into())],
                    ..Default::default()
                },
                "is not a header value",
            ),
            (
                HealthCheckCfg {
                    expect_body: "ok".into(),
                    expect_body_regex: "ok".into(),
                    ..Default::default()
                },
                "not both",
            ),
            (
                HealthCheckCfg {
                    expect_body_regex: "(unclosed".into(),
                    ..Default::default()
                },
                "expect_body_regex = \"(unclosed\"",
            ),
        ] {
            let e = check(hc).unwrap_err();
            assert!(e.contains(why), "{why}: {e}");
        }
        let re = check(HealthCheckCfg {
            expect_body_regex: r#""status":\s*"(ok|degraded)""#.into(),
            ..Default::default()
        })
        .unwrap();
        let Some(BodyMatch::Regex(compiled)) = &re.body else {
            panic!("{:?}", re.body);
        };
        assert!(compiled.is_match(br#"{"status": "degraded"}"#));
        assert!(!compiled.is_match(br#"{"status": "down"}"#));
        let pool = Pool::from_route(
            &with(HealthCheckCfg {
                headers: vec![("Authorization".into(), "Bearer s3cret".into())],
                expect_body_regex: "ok".into(),
                ..Default::default()
            }),
            "api",
        )
        .unwrap();
        let j = pool.status_json(None, |_| serde_json::json!({}))["health_check"].clone();
        assert_eq!(j["method"], "GET");
        assert_eq!(j["headers"], serde_json::json!(["authorization"]));
        assert_eq!(j["expect_body_regex"], "ok");
        assert!(!j.to_string().contains("s3cret"), "{j}");
    }

    #[test]
    fn a_check_can_use_another_port_of_each_target() {
        assert_eq!(
            on_port("http://a.internal:8080", 8081).unwrap(),
            "http://a.internal:8081"
        );
        assert_eq!(
            on_port("https://a.internal", 9443).unwrap(),
            "https://a.internal:9443"
        );
        assert_eq!(
            on_port("http://a:8080/v1", 8081).unwrap(),
            "http://a:8081/v1",
            "path kept"
        );
        assert_eq!(
            on_port("http://[::1]:8080", 8081).unwrap(),
            "http://[::1]:8081"
        );
        assert_eq!(
            on_port("http://u:pw@a:8080", 8081).unwrap(),
            "http://u:pw@a:8081",
            "credentials kept"
        );
        let with = |hc: HealthCheckCfg| UpstreamRoute {
            health_check: hc,
            ..route(&["http://u:pw@a:8080/v1", "https://b"])
        };
        let pool = Pool::from_route(
            &with(HealthCheckCfg {
                path: "/healthz".into(),
                port: 8081,
                ..Default::default()
            }),
            "api",
        )
        .unwrap();
        let hc = pool.health_check.as_ref().unwrap();
        assert_eq!(hc.label(), "GET :8081/healthz");
        assert_eq!(hc.base_for(&pool.targets[0]), "http://u:pw@a:8081/v1");
        assert_eq!(hc.base_for(&pool.targets[1]), "https://b:8081");
        let j = pool.status_json(None, |_| serde_json::json!({}));
        assert_eq!(j["health_check"]["port"], 8081);
        // Its own port by default.
        let own = Pool::from_route(
            &with(HealthCheckCfg {
                path: "/healthz".into(),
                ..Default::default()
            }),
            "api",
        )
        .unwrap();
        let hc = own.health_check.as_ref().unwrap();
        assert_eq!(hc.base_for(&own.targets[0]), "http://u:pw@a:8080/v1");
        assert_eq!(hc.label(), "GET /healthz");
        assert!(own.status_json(None, |_| serde_json::json!({}))["health_check"]["port"].is_null());
        // A TCP check takes one too.
        let tcp = Pool::from_route(
            &with(HealthCheckCfg {
                kind: "tcp".into(),
                port: 6379,
                ..Default::default()
            }),
            "api",
        )
        .unwrap();
        assert_eq!(tcp.health_check.as_ref().unwrap().label(), "tcp :6379");
        // Without a check to send, it does nothing.
        let e = err(with(HealthCheckCfg {
            port: 8081,
            ..Default::default()
        }));
        assert!(
            e.contains("health_check.port needs health_check.path"),
            "{e}"
        );
    }

    #[test]
    fn a_tcp_check_takes_no_http_settings_and_a_body_match_needs_a_path() {
        let with = |hc: HealthCheckCfg| UpstreamRoute {
            health_check: hc,
            ..route(&["http://a:1"])
        };
        let tcp = HealthCheckCfg {
            kind: "tcp".into(),
            ..Default::default()
        };
        let pool = Pool::from_route(&with(tcp.clone()), "api").unwrap();
        let hc = pool.health_check.as_ref().expect("on without a path");
        assert_eq!((hc.kind, hc.label().as_str()), (CheckKind::Tcp, "tcp"));
        let j = pool.status_json(None, |_| serde_json::json!({}));
        assert_eq!(j["health_check"]["type"], "tcp");
        for (setting, hc) in [
            (
                "path",
                HealthCheckCfg {
                    path: "/h".into(),
                    ..tcp.clone()
                },
            ),
            (
                "expect_status",
                HealthCheckCfg {
                    expect_status: "2xx".into(),
                    ..tcp.clone()
                },
            ),
            (
                "expect_body",
                HealthCheckCfg {
                    expect_body: "ok".into(),
                    ..tcp.clone()
                },
            ),
            (
                "expect_body_regex",
                HealthCheckCfg {
                    expect_body_regex: "ok".into(),
                    ..tcp.clone()
                },
            ),
            (
                "method",
                HealthCheckCfg {
                    method: "HEAD".into(),
                    ..tcp.clone()
                },
            ),
            (
                "headers",
                HealthCheckCfg {
                    headers: vec![("Host".into(), "a".into())],
                    ..tcp.clone()
                },
            ),
        ] {
            let e = err(with(hc));
            assert!(
                e.contains(&format!(
                    "health_check.{setting} does nothing with type = \"tcp\""
                )),
                "{e}"
            );
        }
        // Without a path there is no HTTP check to send them with.
        for (setting, hc) in [
            (
                "expect_body_regex",
                HealthCheckCfg {
                    expect_body_regex: "ok".into(),
                    ..Default::default()
                },
            ),
            (
                "method",
                HealthCheckCfg {
                    method: "HEAD".into(),
                    ..Default::default()
                },
            ),
            (
                "headers",
                HealthCheckCfg {
                    headers: vec![("Host".into(), "a".into())],
                    ..Default::default()
                },
            ),
        ] {
            let e = err(with(hc));
            assert!(
                e.contains(&format!("health_check.{setting} needs health_check.path")),
                "{e}"
            );
        }
        let e = err(with(HealthCheckCfg {
            kind: "udp".into(),
            ..Default::default()
        }));
        assert!(
            e.contains("health_check.type = \"udp\": expected \"http\" or \"tcp\""),
            "{e}"
        );
        let e = err(with(HealthCheckCfg {
            expect_body: "ok".into(),
            ..Default::default()
        }));
        assert!(
            e.contains("health_check.expect_body needs health_check.path"),
            "{e}"
        );
        let body = Pool::from_route(
            &with(HealthCheckCfg {
                path: "/h".into(),
                expect_body: "ok".into(),
                ..Default::default()
            }),
            "api",
        )
        .unwrap();
        let hc = body.health_check.as_ref().unwrap();
        assert_eq!((hc.kind, hc.label().as_str()), (CheckKind::Http, "GET /h"));
        let j = body.status_json(None, |_| serde_json::json!({}));
        assert_eq!(j["health_check"]["type"], "http");
        assert_eq!(j["health_check"]["expect_body"], "ok");
        let hp = |base: &str| host_port(base).unwrap();
        assert_eq!(hp("http://a.internal"), ("a.internal".into(), 80));
        assert_eq!(hp("https://a.internal"), ("a.internal".into(), 443));
        assert_eq!(hp("https://10.0.0.1:8443"), ("10.0.0.1".into(), 8443));
        assert_eq!(hp("http://[::1]:8080"), ("::1".into(), 8080));
        // A TCP check on one target is a pool setting too.
        let single = UpstreamRoute {
            target: "http://a:1".into(),
            health_check: tcp,
            ..route(&[])
        };
        assert!(err(single).contains("health_check needs a pool"));
    }
}
