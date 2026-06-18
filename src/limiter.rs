//! Distributed (shared-store) rate limiting (Phase 4 / v2).
//!
//! The default limiter (`ratelimit.store = "local"`) is the in-process `governor` limiter wired
//! up in [`crate::lib`]; it is fast and dependency-free but counts per replica, so three
//! instances behind a load balancer allow 3× the configured rate. This module adds a
//! **shared-store** limiter so N replicas enforce one global limit.
//!
//! The design separates the *algorithm* from the *store*:
//!
//! * [`gcra_admit`] is the pure GCRA (Generic Cell Rate Algorithm — the same family `governor`
//!   uses) decision: given the stored theoretical-arrival-time (TAT) and now, return the new TAT
//!   to persist, or `None` to reject. It is exhaustively unit-tested with no clock or I/O.
//! * A [`Store`] performs that decision atomically against shared state. [`Store::Memory`] is an
//!   in-process map (a reference backend, used by the tests and valid for a single replica);
//!   [`Store::Redis`] runs the *same* GCRA as a Lua script inside Redis, so the check-and-set is
//!   atomic across replicas.
//!
//! **Honesty note (mirrors ACME):** the Redis backend is implemented and compiled, but a live
//! Redis can't be reached from the in-process test suite, so the Redis transport is *not*
//! exercised by `cargo test` — only the GCRA core and the in-memory store are. See
//! `docs/ROADMAP.md` Phase 4. On a store error the limiter fails **closed** (`503`) unless
//! `ratelimit.fail_open` is set; this is the failure path the removed `fail_mode` knob was
//! always meant to govern.
//!
//! Shared-store limiting assumes replica clocks are roughly in sync (NTP); the TAT is an
//! absolute wall-clock time in microseconds.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing::warn;

use crate::config::{parse_rate, RateLimitCfg};

/// Which backend holds limiter state. Parsed from `ratelimit.store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
    /// In-process `governor` limiter (built in `lib::build_runtime`, not here). Per-replica.
    Local,
    /// In-process shared-store map. Single-replica / testing backend for the distributed path.
    Memory,
    /// Redis-backed shared store: one global limit across replicas.
    Redis,
}

impl StoreMode {
    pub fn parse(s: &str) -> Result<StoreMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" | "governor" | "" => Ok(StoreMode::Local),
            "memory" | "in-memory" => Ok(StoreMode::Memory),
            "redis" => Ok(StoreMode::Redis),
            other => {
                anyhow::bail!("invalid ratelimit.store {other:?} (expected local|memory|redis)")
            }
        }
    }

    /// True for the shared-store backends handled by this module (`memory`/`redis`); `local`
    /// stays on the `governor` limiter.
    pub fn is_distributed(self) -> bool {
        matches!(self, StoreMode::Memory | StoreMode::Redis)
    }
}

/// GCRA parameters for one limit, in microseconds. `emission_interval` is the steady-state time
/// per request (period / count); `tolerance` is how far the TAT may run ahead of now before a
/// request is rejected (`emission_interval * burst`), i.e. the burst allowance.
#[derive(Debug, Clone, Copy)]
pub struct Gcra {
    emission_interval: u64,
    tolerance: u64,
}

impl Gcra {
    /// Derive GCRA timings from a `rate`/`burst` policy, rejecting the same degenerate input as
    /// the local limiter (zero rate/burst, or a rate so high the interval underflows to 0µs).
    pub fn from_rate(rate: &str, burst: u32) -> Result<Gcra> {
        let (count, period) = parse_rate(rate)?;
        anyhow::ensure!(count > 0, "rate count must be > 0 (got {rate:?})");
        anyhow::ensure!(burst > 0, "burst must be > 0 (rate {rate:?})");
        let period_us = period.as_micros() as u64;
        let emission_interval = period_us / count as u64;
        anyhow::ensure!(
            emission_interval > 0,
            "rate too high for a usable sub-microsecond interval: {rate:?}"
        );
        let tolerance = emission_interval.saturating_mul(burst as u64);
        Ok(Gcra {
            emission_interval,
            tolerance,
        })
    }
}

/// Pure GCRA decision. `stored_tat` is the persisted theoretical arrival time (µs since the
/// epoch) or `None` for a fresh key; `now` is the current time (µs). Returns `Some(new_tat)` to
/// persist when the request is admitted, or `None` when it must be rejected (the stored TAT is
/// deliberately *not* advanced on rejection, so a flood of blocked requests doesn't extend the
/// penalty window). Shared by every [`Store`] so all backends agree bit-for-bit.
fn gcra_admit(stored_tat: Option<u64>, now: u64, g: &Gcra) -> Option<u64> {
    // A TAT in the past means the bucket has drained; clamp it forward to now.
    let tat = stored_tat.unwrap_or(now).max(now);
    let new_tat = tat + g.emission_interval;
    let allow_at = new_tat.saturating_sub(g.tolerance);
    if now < allow_at {
        None
    } else {
        Some(new_tat)
    }
}

/// A shared-state store that can perform a GCRA admission atomically for a key. The Redis
/// backend is boxed since it is much larger than the in-memory map variant.
enum Store {
    Memory(MemoryStore),
    Redis(Box<RedisStore>),
}

impl Store {
    /// Returns `Ok(true)` to admit, `Ok(false)` to reject, `Err` on a store failure.
    async fn admit(&self, key: &str, g: &Gcra, now: u64) -> Result<bool> {
        match self {
            Store::Memory(s) => Ok(s.admit(key, g, now)),
            Store::Redis(s) => s.admit(key, g, now).await,
        }
    }
}

/// In-process shared store: a map of key → TAT (µs). For a single replica this matches the
/// `local` limiter's semantics; across replicas it is *not* shared (use Redis for that). It is
/// the reference backend the test suite drives to prove the distributed code path end-to-end.
#[derive(Default)]
struct MemoryStore {
    tats: Mutex<HashMap<String, u64>>,
}

impl MemoryStore {
    fn admit(&self, key: &str, g: &Gcra, now: u64) -> bool {
        let mut map = self.tats.lock().expect("limiter store mutex poisoned");
        match gcra_admit(map.get(key).copied(), now, g) {
            Some(new_tat) => {
                map.insert(key.to_string(), new_tat);
                true
            }
            None => false,
        }
    }
}

/// GCRA as a Redis Lua script: GET the TAT, run the same arithmetic as [`gcra_admit`], and SET
/// the new TAT with a TTL only when the request is admitted — all atomically server-side, so
/// concurrent replicas can't race the check against the update. Returns `1` to admit, `0` to
/// reject.
const GCRA_LUA: &str = r#"
local tat = redis.call('GET', KEYS[1])
local now = tonumber(ARGV[1])
local interval = tonumber(ARGV[2])
local tolerance = tonumber(ARGV[3])
if tat == false then
  tat = now
else
  tat = tonumber(tat)
  if tat < now then tat = now end
end
local new_tat = tat + interval
local allow_at = new_tat - tolerance
if now < allow_at then
  return 0
end
local ttl_ms = math.ceil((new_tat - now) / 1000)
if ttl_ms < 1 then ttl_ms = 1 end
redis.call('SET', KEYS[1], new_tat, 'PX', ttl_ms)
return 1
"#;

/// Redis-backed shared store. The connection is established lazily on first use (so a replica
/// doesn't crash-loop if Redis is briefly unreachable at boot) and auto-reconnects thereafter
/// via [`redis::aio::ConnectionManager`].
struct RedisStore {
    client: redis::Client,
    conn: tokio::sync::OnceCell<redis::aio::ConnectionManager>,
    script: redis::Script,
}

impl RedisStore {
    fn new(url: &str) -> Result<RedisStore> {
        anyhow::ensure!(
            !url.trim().is_empty(),
            "ratelimit.redis_url is required when ratelimit.store = \"redis\""
        );
        let client = redis::Client::open(url)
            .with_context(|| format!("opening redis client for {url:?} (ratelimit.redis_url)"))?;
        Ok(RedisStore {
            client,
            conn: tokio::sync::OnceCell::new(),
            script: redis::Script::new(GCRA_LUA),
        })
    }

    async fn admit(&self, key: &str, g: &Gcra, now: u64) -> Result<bool> {
        let manager = self
            .conn
            .get_or_try_init(|| redis::aio::ConnectionManager::new(self.client.clone()))
            .await
            .context("connecting to redis rate-limit store")?;
        let mut conn = manager.clone();
        let admitted: i64 = self
            .script
            .key(key)
            .arg(now)
            .arg(g.emission_interval)
            .arg(g.tolerance)
            .invoke_async(&mut conn)
            .await
            .context("evaluating redis GCRA script")?;
        Ok(admitted == 1)
    }
}

/// The outcome of consulting a limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Within the limit — proceed.
    Allowed,
    /// Over the limit — reject with `429`; the scope (`ip`/`route`/`key`) names which limit.
    Limited(&'static str),
    /// The store failed and `fail_open` is off — reject with `503`.
    Error,
}

/// A per-route GCRA override (matched by longest path prefix), mirroring the local limiter.
struct RouteGcra {
    prefix: String,
    gcra: Gcra,
}

/// Shared-store rate limiter: the distributed counterpart of the three `governor` limiters. Holds
/// the GCRA params for the global per-IP limit, the per-route overrides, and the per-key limit,
/// plus the backing [`Store`] and the fail-open policy.
pub struct DistributedLimiter {
    store: Store,
    key_prefix: String,
    fail_open: bool,
    global: Gcra,
    routes: Vec<RouteGcra>,
    per_key: Option<Gcra>,
}

impl DistributedLimiter {
    /// Build from config for a distributed [`StoreMode`] (`memory`/`redis`). Compiles the GCRA
    /// params for every limit up front, so a bad rate/burst fails at startup/reload — exactly
    /// like the local limiter.
    pub fn build(rl: &RateLimitCfg, mode: StoreMode) -> Result<DistributedLimiter> {
        let store = match mode {
            StoreMode::Memory => Store::Memory(MemoryStore::default()),
            StoreMode::Redis => Store::Redis(Box::new(RedisStore::new(&rl.redis_url)?)),
            StoreMode::Local => {
                anyhow::bail!("DistributedLimiter::build called for the local store")
            }
        };

        let global = Gcra::from_rate(&rl.rate, rl.burst)?;
        let mut routes = Vec::new();
        for route in &rl.routes {
            anyhow::ensure!(
                !route.path.is_empty(),
                "ratelimit.routes[].path must not be empty"
            );
            routes.push(RouteGcra {
                prefix: route.path.clone(),
                gcra: Gcra::from_rate(&route.rate, route.burst)?,
            });
        }
        let per_key = if rl.per_key.enabled {
            Some(Gcra::from_rate(&rl.per_key.rate, rl.per_key.burst)?)
        } else {
            None
        };

        Ok(DistributedLimiter {
            store,
            key_prefix: rl.redis_prefix.clone(),
            fail_open: rl.fail_open,
            global,
            routes,
            per_key,
        })
    }

    /// Pre-auth check: the per-route override matching `path` (longest prefix), else the global
    /// per-IP limit. Keyed per client IP, like the local limiter.
    pub async fn check_ip_route(&self, ip: IpAddr, path: &str) -> Admit {
        let now = now_micros();
        if let Some(route) = self
            .routes
            .iter()
            .filter(|r| path.starts_with(&r.prefix))
            .max_by_key(|r| r.prefix.len())
        {
            let key = format!("{}:route:{}:{}", self.key_prefix, route.prefix, ip);
            self.admit(&key, &route.gcra, now, "route").await
        } else {
            let key = format!("{}:ip:{}", self.key_prefix, ip);
            self.admit(&key, &self.global, now, "ip").await
        }
    }

    /// Post-auth check: the per-principal limit (keyed by API-key id / JWT subject). Returns
    /// [`Admit::Allowed`] when per-key limiting is disabled.
    pub async fn check_key(&self, principal: &str) -> Admit {
        match &self.per_key {
            Some(gcra) => {
                let now = now_micros();
                let key = format!("{}:key:{}", self.key_prefix, principal);
                self.admit(&key, gcra, now, "key").await
            }
            None => Admit::Allowed,
        }
    }

    async fn admit(&self, key: &str, g: &Gcra, now: u64, scope: &'static str) -> Admit {
        match self.store.admit(key, g, now).await {
            Ok(true) => Admit::Allowed,
            Ok(false) => Admit::Limited(scope),
            Err(e) => {
                if self.fail_open {
                    warn!(error = %format!("{e:#}"), scope, "rate-limit store error; failing open (allowing request)");
                    Admit::Allowed
                } else {
                    warn!(error = %format!("{e:#}"), scope, "rate-limit store error; failing closed (503)");
                    Admit::Error
                }
            }
        }
    }
}

/// Current wall-clock time in microseconds since the Unix epoch (the GCRA TAT's basis).
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        // Saturate rather than wrap on the (year ~584942) u128→u64 boundary.
        .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PerKeyRateLimit, RouteRateLimit};

    fn gcra(rate: &str, burst: u32) -> Gcra {
        Gcra::from_rate(rate, burst).unwrap()
    }

    #[test]
    fn store_mode_parses_and_classifies() {
        assert_eq!(StoreMode::parse("local").unwrap(), StoreMode::Local);
        assert_eq!(StoreMode::parse("").unwrap(), StoreMode::Local);
        assert_eq!(StoreMode::parse("REDIS").unwrap(), StoreMode::Redis);
        assert_eq!(StoreMode::parse(" memory ").unwrap(), StoreMode::Memory);
        assert!(StoreMode::parse("dynamo").is_err());
        assert!(!StoreMode::parse("local").unwrap().is_distributed());
        assert!(StoreMode::parse("redis").unwrap().is_distributed());
        assert!(StoreMode::parse("memory").unwrap().is_distributed());
    }

    #[test]
    fn gcra_from_rate_rejects_degenerate_input() {
        assert!(Gcra::from_rate("0/sec", 5).is_err()); // zero rate
        assert!(Gcra::from_rate("10/sec", 0).is_err()); // zero burst
        assert!(Gcra::from_rate("nonsense", 5).is_err());
    }

    #[test]
    fn gcra_admit_allows_burst_then_rejects_at_same_instant() {
        // burst=3 at 1/sec: three requests at the same instant are admitted, the fourth is not.
        let g = gcra("1/sec", 3);
        let now = 1_000_000_000;
        let mut tat = None;
        for _ in 0..3 {
            let next = gcra_admit(tat, now, &g);
            assert!(next.is_some(), "within-burst request should be admitted");
            tat = next;
        }
        assert!(
            gcra_admit(tat, now, &g).is_none(),
            "the request past the burst must be rejected"
        );
    }

    #[test]
    fn gcra_admit_recovers_after_emission_interval() {
        // burst=1 at 1/sec: one per second. A second request 1s later is admitted again.
        let g = gcra("1/sec", 1);
        let t0 = 5_000_000_000;
        let tat = gcra_admit(None, t0, &g).expect("first admitted");
        assert!(
            gcra_admit(Some(tat), t0, &g).is_none(),
            "immediate second rejected"
        );
        // One emission interval (1s = 1_000_000µs) later the bucket has a cell again.
        assert!(
            gcra_admit(Some(tat), t0 + 1_000_000, &g).is_some(),
            "request after the interval admitted"
        );
    }

    #[test]
    fn gcra_admit_does_not_advance_tat_on_rejection() {
        let g = gcra("1/min", 1);
        let now = 2_000_000_000;
        let tat = gcra_admit(None, now, &g).unwrap();
        // Two rejected attempts return None and leave the caller's stored TAT unchanged, so the
        // penalty window is fixed by the first admit — not extended by the flood.
        assert!(gcra_admit(Some(tat), now, &g).is_none());
        assert!(gcra_admit(Some(tat), now, &g).is_none());
    }

    #[tokio::test]
    async fn memory_store_enforces_global_limit() {
        let rl = RateLimitCfg {
            enabled: true,
            rate: "1/min".into(),
            burst: 1,
            store: "memory".into(),
            ..Default::default()
        };
        let limiter = DistributedLimiter::build(&rl, StoreMode::Memory).unwrap();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        // burst of 1: first allowed, second (same IP) limited under the "ip" scope.
        assert_eq!(limiter.check_ip_route(ip, "/").await, Admit::Allowed);
        assert_eq!(limiter.check_ip_route(ip, "/").await, Admit::Limited("ip"));
        // A different IP has its own bucket.
        let ip2: IpAddr = "203.0.113.8".parse().unwrap();
        assert_eq!(limiter.check_ip_route(ip2, "/").await, Admit::Allowed);
    }

    #[tokio::test]
    async fn memory_store_applies_per_route_override() {
        let rl = RateLimitCfg {
            enabled: true,
            rate: "1000/min".into(), // generous global
            burst: 1000,
            routes: vec![RouteRateLimit {
                path: "/api/".into(),
                rate: "1/min".into(),
                burst: 1,
            }],
            store: "memory".into(),
            ..Default::default()
        };
        let limiter = DistributedLimiter::build(&rl, StoreMode::Memory).unwrap();
        let ip: IpAddr = "198.51.100.4".parse().unwrap();

        // /api/ uses the strict override (scope "route"); a non-/api/ path uses the global.
        assert_eq!(limiter.check_ip_route(ip, "/api/x").await, Admit::Allowed);
        assert_eq!(
            limiter.check_ip_route(ip, "/api/x").await,
            Admit::Limited("route")
        );
        assert_eq!(limiter.check_ip_route(ip, "/public").await, Admit::Allowed);
    }

    #[tokio::test]
    async fn memory_store_per_key_limit() {
        let rl = RateLimitCfg {
            enabled: true,
            rate: "1000/min".into(),
            burst: 1000,
            per_key: PerKeyRateLimit {
                enabled: true,
                rate: "1/min".into(),
                burst: 1,
            },
            store: "memory".into(),
            ..Default::default()
        };
        let limiter = DistributedLimiter::build(&rl, StoreMode::Memory).unwrap();

        assert_eq!(limiter.check_key("apikey:abc").await, Admit::Allowed);
        assert_eq!(limiter.check_key("apikey:abc").await, Admit::Limited("key"));
        // A different principal is independent.
        assert_eq!(limiter.check_key("apikey:def").await, Admit::Allowed);
    }

    #[tokio::test]
    async fn per_key_disabled_always_allows() {
        let rl = RateLimitCfg {
            enabled: true,
            store: "memory".into(),
            ..Default::default()
        };
        let limiter = DistributedLimiter::build(&rl, StoreMode::Memory).unwrap();
        assert_eq!(limiter.check_key("whoever").await, Admit::Allowed);
    }

    #[test]
    fn redis_store_requires_a_url() {
        let rl = RateLimitCfg {
            enabled: true,
            store: "redis".into(),
            redis_url: "".into(),
            ..Default::default()
        };
        assert!(DistributedLimiter::build(&rl, StoreMode::Redis).is_err());
        // A malformed URL is rejected at build too (fails fast, not per-request).
        let bad = RateLimitCfg {
            enabled: true,
            store: "redis".into(),
            redis_url: "not-a-redis-url".into(),
            ..Default::default()
        };
        assert!(DistributedLimiter::build(&bad, StoreMode::Redis).is_err());
    }
}
