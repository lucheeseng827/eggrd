//! LLM hard budgets (gateway L1).
//!
//! L0 ([`crate::llm`]) *meters* token spend; L1 *enforces* a hard cap on it. A budget is a ceiling
//! on tokens (or cost) over a fixed window, enforced **fail-closed** and **atomically across
//! replicas** so a fleet behind a load balancer can't collectively overshoot — the failure mode
//! that makes naive per-replica caps leak.
//!
//! The enforcement model is **reserve → reconcile** (the same shape a payment hold uses):
//!
//!  1. **reserve** an *estimate* (prompt size + the request's `max_tokens`) before forwarding. If it
//!     would exceed the budget, the request is denied `429` and never reaches the upstream — so the
//!     cap is a true ceiling, not a post-hoc overshoot.
//!  2. **reconcile** to the upstream's *actual* `usage` once known: release the over-reserved
//!     remainder, or charge the extra if the estimate was low. A request that never produced usage
//!     (error, client hangup) reconciles to zero — a full release.
//!
//! Structure mirrors [`crate::limiter`]: a pure decision ([`would_reserve`]) split from the store
//! ([`Store::Memory`] for a single replica / tests, [`Store::Redis`] running the same arithmetic as
//! an atomic Lua script). The window is encoded in the key (`…:{window_index}`) so it resets at the
//! boundary with no sweeper, and the key TTLs out after the window passes.
//!
//! **Honesty note (mirrors the limiter / ACME):** the Redis backend is implemented and compiled but
//! the live transport isn't exercised by `cargo test` (no Redis in CI) — only the pure decision and
//! the in-memory store are. The `#[ignore]`d `redis_*_live` tests prove it against a real server.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing::warn;

use crate::config::{BudgetCfg, LlmCfg};

/// The unit a budget caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetUnit {
    /// Total tokens (prompt + completion).
    Tokens,
    /// Cost in micro-dollars (1e-6 USD), via the model price book.
    UsdMicros,
}

impl BudgetUnit {
    fn parse(s: &str) -> Result<BudgetUnit> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tokens" | "token" | "" => Ok(BudgetUnit::Tokens),
            "usd" | "usd_micros" | "cost" => Ok(BudgetUnit::UsdMicros),
            other => anyhow::bail!("invalid llm budget unit {other:?} (expected tokens|usd)"),
        }
    }
}

/// Which dimension a budget is keyed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetScope {
    /// One shared budget across all traffic.
    Global,
    /// One budget per authenticated principal (API-key id / JWT subject).
    PerKey,
    /// One budget per requested model.
    PerModel,
    /// One budget per team/tag (from the team header/claim) — the chargeback dimension a
    /// multi-tenant deployment bills on.
    PerTeam,
}

impl BudgetScope {
    fn parse(s: &str) -> Result<BudgetScope> {
        match s.trim().to_ascii_lowercase().as_str() {
            "global" | "" => Ok(BudgetScope::Global),
            "key" | "per_key" | "per-key" => Ok(BudgetScope::PerKey),
            "model" | "per_model" | "per-model" => Ok(BudgetScope::PerModel),
            "team" | "per_team" | "per-team" | "tag" => Ok(BudgetScope::PerTeam),
            other => {
                anyhow::bail!("invalid llm budget scope {other:?} (expected global|key|model|team)")
            }
        }
    }

    /// The stable metric/log label for this scope. Kept in sync with `BUDGET_SCOPES` in
    /// [`crate::metrics`].
    pub fn label(&self) -> &'static str {
        match self {
            BudgetScope::Global => "global",
            BudgetScope::PerKey => "key",
            BudgetScope::PerModel => "model",
            BudgetScope::PerTeam => "team",
        }
    }
}

/// One compiled budget: a `limit` (in `unit`) over `window_secs`, keyed by `scope`.
#[derive(Debug, Clone)]
struct Budget {
    name: String,
    scope: BudgetScope,
    unit: BudgetUnit,
    limit: u64,
    window_secs: u64,
}

impl Budget {
    /// Compile a [`BudgetCfg`]. A USD limit (float dollars) becomes integer micro-dollars; a token
    /// limit is taken as-is. Rejects a zero/negative limit or window so a typo fails at startup.
    fn build(cfg: &BudgetCfg) -> Result<Budget> {
        anyhow::ensure!(
            !cfg.name.trim().is_empty(),
            "llm budget name must not be empty"
        );
        let unit = BudgetUnit::parse(&cfg.unit)?;
        let scope = BudgetScope::parse(&cfg.scope)?;
        let window_secs = crate::config::parse_duration(&cfg.window)
            .with_context(|| format!("llm budget {:?} window", cfg.name))?
            .as_secs();
        anyhow::ensure!(
            window_secs > 0,
            "llm budget {:?} window must be > 0",
            cfg.name
        );
        anyhow::ensure!(
            cfg.limit.is_finite() && cfg.limit > 0.0,
            "llm budget {:?} limit must be > 0",
            cfg.name
        );
        let limit = match unit {
            BudgetUnit::Tokens => cfg.limit.round() as u64,
            BudgetUnit::UsdMicros => (cfg.limit * 1_000_000.0).round() as u64,
        };
        anyhow::ensure!(
            limit > 0,
            "llm budget {:?} limit rounds to zero; use a larger value",
            cfg.name
        );
        Ok(Budget {
            name: cfg.name.clone(),
            scope,
            unit,
            limit,
            window_secs,
        })
    }

    /// The store key for this budget given the request's dimensions and the current time. The
    /// window index (`now / window_secs`) is part of the key, so the budget resets at the window
    /// boundary with no sweeper — the previous window's key simply ages out via TTL.
    fn key(&self, prefix: &str, dims: &Dims, now_secs: u64) -> String {
        let dim = match self.scope {
            BudgetScope::Global => "_",
            BudgetScope::PerKey => dims.principal.unwrap_or("_anon"),
            BudgetScope::PerModel => dims.model,
            BudgetScope::PerTeam => dims.team.unwrap_or("_none"),
        };
        let window = now_secs / self.window_secs;
        format!("{prefix}:budget:{}:{dim}:{window}", self.name)
    }

    /// The amount this budget would charge for a `(tokens, cost_micros)` estimate, in its own unit.
    fn amount(&self, tokens: u64, cost_micros: u64) -> u64 {
        match self.unit {
            BudgetUnit::Tokens => tokens,
            BudgetUnit::UsdMicros => cost_micros,
        }
    }

    /// TTL (ms) to set on the key: two windows, so an in-progress window stays live while a passed
    /// one is reclaimed well before its index could recur.
    fn ttl_ms(&self) -> u64 {
        self.window_secs.saturating_mul(2_000).max(1)
    }
}

/// The request dimensions a budget keys on (which subset it uses depends on the budget's scope).
#[derive(Debug, Clone, Copy, Default)]
pub struct Dims<'a> {
    /// Authenticated principal (API-key id / JWT subject) — the `key` scope.
    pub principal: Option<&'a str>,
    /// Requested model — the `model` scope.
    pub model: &'a str,
    /// Team/tag — the `team` scope (chargeback dimension).
    pub team: Option<&'a str>,
}

/// The pure admission decision: may `amount` be reserved against `used` without exceeding `limit`?
/// Shared by every [`Store`] so all backends agree bit-for-bit.
fn would_reserve(used: u64, amount: u64, limit: u64) -> bool {
    used.saturating_add(amount) <= limit
}

/// The result of a reserve attempt against one key: whether it was admitted and the balance *after*
/// (unchanged from the current used total when denied). The post-reserve total drives the near-limit
/// consumed-ratio gauge.
#[derive(Debug, Clone, Copy)]
struct ReserveOutcome {
    admitted: bool,
    used_after: u64,
}

/// A shared-state store that performs reserve / reconcile atomically per key.
enum Store {
    Memory(MemoryStore),
    Redis(Box<RedisStore>),
}

impl Store {
    /// Reserve `amount` against `key` (capped at `limit`), returning admission + the post-reserve
    /// balance. `Err` on store failure.
    async fn reserve(
        &self,
        key: &str,
        amount: u64,
        limit: u64,
        ttl_ms: u64,
    ) -> Result<ReserveOutcome> {
        match self {
            Store::Memory(s) => Ok(s.reserve(key, amount, limit, ttl_ms)),
            Store::Redis(s) => s.reserve(key, amount, limit, ttl_ms).await,
        }
    }

    /// Apply `delta` (actual − reserved; may be negative) to `key`, flooring at 0, **idempotently**
    /// via `marker` (a repeated settle is a no-op). Returns `true` on success. On the Redis path this
    /// retries a transient error (safe because the settle is idempotent); a final failure is logged
    /// and returns `false` so the caller can count the drift (`edgeguard_llm_budget_reconcile_failures_total`).
    async fn reconcile(&self, key: &str, delta: i64, ttl_ms: u64, marker: &str) -> bool {
        match self {
            Store::Memory(s) => {
                s.reconcile(key, delta, ttl_ms, marker);
                true
            }
            Store::Redis(s) => match s.reconcile(key, delta, ttl_ms, marker).await {
                Ok(()) => true,
                Err(e) => {
                    warn!(error = %format!("{e:#}"), "llm budget reconcile failed after retries — counter has drifted (alert on edgeguard_llm_budget_reconcile_failures_total)");
                    false
                }
            },
        }
    }
}

/// In-process shared store: `key → (used, expiry)`. Single-replica / reference backend the tests
/// drive. Tracks per-entry expiry so keys are evicted lazily on every write, preventing unbounded
/// growth when many distinct budget keys (different principals or window indexes) are created over
/// time. The expiry mirrors the TTL the Redis store sets on the key.
#[derive(Default)]
struct MemoryStore {
    used: Mutex<HashMap<String, (u64, Instant)>>,
    /// Settle markers (`marker → expiry`) for **idempotent** reconcile: a repeated settle for the
    /// same marker is a no-op, mirroring the Redis `SET NX` marker so both backends dedupe a retry.
    settled: Mutex<HashMap<String, Instant>>,
}

impl MemoryStore {
    fn reserve(&self, key: &str, amount: u64, limit: u64, ttl_ms: u64) -> ReserveOutcome {
        let now = Instant::now();
        let expires = now + Duration::from_millis(ttl_ms);
        let mut map = self.used.lock().expect("budget store mutex poisoned");
        map.retain(|_, (_, exp)| *exp > now);
        let used = map.get(key).map(|(v, _)| *v).unwrap_or(0);
        if would_reserve(used, amount, limit) {
            let used_after = used.saturating_add(amount);
            map.insert(key.to_string(), (used_after, expires));
            ReserveOutcome {
                admitted: true,
                used_after,
            }
        } else {
            ReserveOutcome {
                admitted: false,
                used_after: used,
            }
        }
    }

    fn reconcile(&self, key: &str, delta: i64, ttl_ms: u64, marker: &str) {
        let now = Instant::now();
        // Idempotency: an unexpired marker means this exact settle already applied → no-op, so a
        // retry (or a double call) can't double-apply the signed delta.
        {
            let mut seen = self.settled.lock().expect("budget settled mutex poisoned");
            seen.retain(|_, exp| *exp > now);
            if seen.contains_key(marker) {
                return;
            }
            seen.insert(
                marker.to_string(),
                now + Duration::from_millis(MARKER_TTL_MS),
            );
        }
        let expires = now + Duration::from_millis(ttl_ms);
        let mut map = self.used.lock().expect("budget store mutex poisoned");
        map.retain(|_, (_, exp)| *exp > now);
        let used = map.get(key).map(|(v, _)| *v).unwrap_or(0) as i64;
        let next = (used + delta).max(0) as u64;
        map.insert(key.to_string(), (next, expires));
    }
}

/// Reserve as a Redis Lua script: GET the used total, run the same check as [`would_reserve`], and
/// INCRBY + refresh the TTL only when admitted — all atomic server-side, so concurrent replicas
/// can't race the check against the update. Returns `1` to admit, `0` to deny.
const RESERVE_LUA: &str = r#"
local used = tonumber(redis.call('GET', KEYS[1]) or '0')
local amount = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
if used + amount > limit then
  return {0, used}
end
local newv = redis.call('INCRBY', KEYS[1], amount)
redis.call('PEXPIRE', KEYS[1], ttl)
return {1, newv}
"#;

/// Reconcile as a Lua script — **idempotent**: a per-settle marker (`KEYS[2]`, set `NX`) makes a
/// given settle apply *at most once*, so a retry after a lost response can't double-apply the signed
/// delta (the correctness trap that makes a naive delta retry unsafe). On the first call it applies
/// the delta (flooring at 0) and refreshes the counter TTL; a repeat call is a no-op returning the
/// current value. The marker's own TTL only needs to outlive the retry window, not the whole budget
/// window, so marker keys are short-lived and don't accumulate.
/// KEYS[1]=counter, KEYS[2]=settle-marker · ARGV[1]=delta, ARGV[2]=counter_ttl_ms, ARGV[3]=marker_ttl_ms
const RECONCILE_LUA: &str = r#"
if redis.call('SET', KEYS[2], '1', 'NX', 'PX', tonumber(ARGV[3])) == false then
  return tonumber(redis.call('GET', KEYS[1]) or '0')
end
local new = redis.call('INCRBY', KEYS[1], tonumber(ARGV[1]))
if new < 0 then
  redis.call('SET', KEYS[1], 0)
  new = 0
end
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
return new
"#;

/// How long a settle marker lives — long enough to cover the reconcile retry window (retries happen
/// within ~100ms), short enough that markers don't accumulate. NOT the budget window.
const MARKER_TTL_MS: u64 = 300_000;
/// Reconcile retry policy against the shared store. Safe to retry *because* the settle is idempotent
/// (the marker dedupes), so a transient Redis blip no longer silently leaks a reserve (upward drift).
const RECONCILE_ATTEMPTS: u32 = 3;
const RECONCILE_BACKOFF: Duration = Duration::from_millis(25);

/// Retry an async fallible op up to `attempts` (>=1) times with a fixed backoff. Returns on the first
/// success, else the last error after exhausting attempts.
async fn retry_async<F, Fut, T>(attempts: u32, backoff: Duration, mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let attempts = attempts.max(1);
    let mut last: Option<anyhow::Error> = None;
    for i in 0..attempts {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                last = Some(e);
                if i + 1 < attempts {
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
    Err(last.expect("retry_async ran at least one attempt"))
}

/// Redis-backed shared store. Connection established lazily and auto-reconnecting, mirroring the
/// rate limiter's [`crate::limiter`] store.
struct RedisStore {
    client: redis::Client,
    conn: tokio::sync::OnceCell<redis::aio::ConnectionManager>,
    reserve: redis::Script,
    reconcile: redis::Script,
}

impl RedisStore {
    fn new(url: &str) -> Result<RedisStore> {
        anyhow::ensure!(
            !url.trim().is_empty(),
            "llm.redis_url is required when llm.store = \"redis\""
        );
        let client = redis::Client::open(url)
            .with_context(|| format!("opening redis client for {url:?} (llm.redis_url)"))?;
        Ok(RedisStore {
            client,
            conn: tokio::sync::OnceCell::new(),
            reserve: redis::Script::new(RESERVE_LUA),
            reconcile: redis::Script::new(RECONCILE_LUA),
        })
    }

    async fn manager(&self) -> Result<redis::aio::ConnectionManager> {
        self.conn
            .get_or_try_init(|| redis::aio::ConnectionManager::new(self.client.clone()))
            .await
            .context("connecting to redis llm-budget store")
            .cloned()
    }

    async fn reserve(
        &self,
        key: &str,
        amount: u64,
        limit: u64,
        ttl_ms: u64,
    ) -> Result<ReserveOutcome> {
        let mut conn = self.manager().await?;
        let (admitted, used_after): (i64, i64) = self
            .reserve
            .key(key)
            .arg(amount)
            .arg(limit)
            .arg(ttl_ms)
            .invoke_async(&mut conn)
            .await
            .context("evaluating redis budget reserve script")?;
        Ok(ReserveOutcome {
            admitted: admitted == 1,
            used_after: used_after.max(0) as u64,
        })
    }

    async fn reconcile(&self, key: &str, delta: i64, ttl_ms: u64, marker: &str) -> Result<()> {
        // Retry is safe: the idempotent Lua (marker set NX) applies the delta at most once, so a
        // retried settle after a lost response can't double-count.
        retry_async(RECONCILE_ATTEMPTS, RECONCILE_BACKOFF, || async {
            let mut conn = self.manager().await?;
            let _: i64 = self
                .reconcile
                .key(key)
                .key(marker)
                .arg(delta)
                .arg(ttl_ms)
                .arg(MARKER_TTL_MS)
                .invoke_async(&mut conn)
                .await
                .context("evaluating redis budget reconcile script")?;
            Ok(())
        })
        .await
    }
}

/// An estimate (or actual) spend, carrying both units so a budget can charge whichever it caps.
#[derive(Debug, Clone, Copy, Default)]
pub struct Spend {
    pub tokens: u64,
    pub cost_micros: u64,
}

/// One budget's post-reserve consumption, surfaced so the caller can feed the near-limit gauge.
#[derive(Debug, Clone)]
pub struct Observation {
    /// The budget's name (the gauge's `budget` label).
    pub name: String,
    /// `used / limit` after this reserve, in `[0.0, 1.0]` (a request is never admitted past 1.0).
    pub consumed_ratio: f64,
}

/// A budget denial: which budget rejected the request, its scope (the block-counter label) and unit
/// (so a cost cap can answer `402` while a token cap answers `429`).
#[derive(Debug, Clone)]
pub struct Denial {
    pub name: String,
    pub scope: BudgetScope,
    pub unit: BudgetUnit,
    /// Budgets reserved before this denial that failed to roll back against the store — drift,
    /// like a failed [`BudgetEngine::reconcile`]/[`BudgetEngine::release`] settle. The caller
    /// should feed this into the same `edgeguard_llm_budget_reconcile_failures_total` counter.
    pub rollback_failures: usize,
}

/// A held reservation: the per-budget amounts charged at reserve time, to be reconciled (or
/// released) once the actual usage is known. Opaque to the caller beyond passing it back, except for
/// the [`Observation`]s it exposes for metrics.
#[derive(Debug, Default)]
pub struct Reservation {
    /// Unique id for this reservation; part of each budget's settle marker so a retried settle
    /// dedupes to a single application (idempotent reconcile).
    id: String,
    /// `(store key, reserved amount, budget index)` per budget that admitted.
    held: Vec<(String, u64, usize)>,
    /// Post-reserve consumption per admitted budget, for the near-limit gauge.
    observations: Vec<Observation>,
    /// Rollback settle failures from an earlier, aborted reserve attempt in the *same* call —
    /// only ever non-zero on the fail-open path (a store error rolled back what was already
    /// held, then admitted anyway). See [`Denial::rollback_failures`] for the denied-path twin.
    rollback_failures: usize,
}

impl Reservation {
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The per-budget consumed ratios observed at reserve time (for `edgeguard_llm_budget_consumed_ratio`).
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    /// Rollback settle failures to feed into `edgeguard_llm_budget_reconcile_failures_total`,
    /// like the return value of [`BudgetEngine::reconcile`]/[`BudgetEngine::release`].
    pub fn rollback_failures(&self) -> usize {
        self.rollback_failures
    }
}

/// The outcome of a reserve attempt.
#[derive(Debug)]
pub enum Reserved {
    /// Admitted under every budget; hold the [`Reservation`] to reconcile later.
    Ok(Reservation),
    /// Denied by a budget — the request must be rejected (`429`, or `402` for a cost cap). Any budgets
    /// reserved before the denial have already been rolled back.
    Denied(Denial),
    /// A store error and `fail_open` is off — reject `503` (fail-closed). With `fail_open` set this
    /// is never returned (the engine admits instead). Carries any rollback settle failures from
    /// budgets already held before the error, for `edgeguard_llm_budget_reconcile_failures_total`.
    Error { rollback_failures: usize },
}

/// Enforces the configured LLM budgets over a [`Store`]. Built once per config (re)load and carried
/// on the proxy [`Runtime`](crate::proxy::Runtime).
pub struct BudgetEngine {
    budgets: Vec<Budget>,
    store: Store,
    prefix: String,
    fail_open: bool,
}

impl BudgetEngine {
    /// Build from `[llm]` config when budgets are present. Returns `Ok(None)` when no budgets are
    /// configured (the engine is then absent and the proxy skips enforcement entirely).
    pub fn build(cfg: &LlmCfg) -> Result<Option<BudgetEngine>> {
        if cfg.budgets.is_empty() {
            return Ok(None);
        }
        let store = match crate::limiter::StoreMode::parse(&cfg.store)? {
            // `local` is meaningless for a shared budget (it would be per-replica); treat the
            // single-process default as the in-memory shared store.
            crate::limiter::StoreMode::Local | crate::limiter::StoreMode::Memory => {
                Store::Memory(MemoryStore::default())
            }
            crate::limiter::StoreMode::Redis => {
                Store::Redis(Box::new(RedisStore::new(&cfg.redis_url)?))
            }
        };
        let budgets = cfg
            .budgets
            .iter()
            .map(Budget::build)
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(BudgetEngine {
            budgets,
            store,
            prefix: if cfg.redis_prefix.trim().is_empty() {
                "edgeguard".to_string()
            } else {
                cfg.redis_prefix.clone()
            },
            fail_open: cfg.fail_open,
        }))
    }

    /// Reserve `estimate` against every budget that applies to `dims`. Reserves in order; on the first
    /// denial, releases everything already reserved and returns [`Reserved::Denied`], so a partial
    /// reservation never leaks. Budgets that don't match the scope are skipped. The returned
    /// [`Reservation`] carries each admitted budget's post-reserve consumed ratio for the near-limit gauge.
    pub async fn reserve(&self, dims: Dims<'_>, estimate: Spend) -> Reserved {
        let now = now_secs();
        let mut held = Vec::new();
        let mut observations = Vec::new();
        for (idx, budget) in self.budgets.iter().enumerate() {
            let amount = budget.amount(estimate.tokens, estimate.cost_micros);
            // A zero-amount charge (e.g. a cost budget on an unpriced model) can't exceed anything;
            // skip it so it neither denies nor needs reconciling.
            if amount == 0 {
                continue;
            }
            let key = budget.key(&self.prefix, &dims, now);
            match self
                .store
                .reserve(&key, amount, budget.limit, budget.ttl_ms())
                .await
            {
                Ok(outcome) if outcome.admitted => {
                    held.push((key, amount, idx));
                    observations.push(Observation {
                        name: budget.name.clone(),
                        consumed_ratio: ratio(outcome.used_after, budget.limit),
                    });
                }
                Ok(_) => {
                    let rollback_failures = self.rollback(&held).await;
                    return Reserved::Denied(Denial {
                        name: budget.name.clone(),
                        scope: budget.scope,
                        unit: budget.unit,
                        rollback_failures,
                    });
                }
                Err(e) => {
                    let rollback_failures = self.rollback(&held).await;
                    if self.fail_open {
                        warn!(error = %format!("{e:#}"), budget = %budget.name, "llm budget store error; failing open (allowing request)");
                        return Reserved::Ok(Reservation {
                            rollback_failures,
                            ..Reservation::default()
                        });
                    }
                    warn!(error = %format!("{e:#}"), budget = %budget.name, "llm budget store error; failing closed (503)");
                    return Reserved::Error { rollback_failures };
                }
            }
        }
        Reserved::Ok(Reservation {
            id: uuid::Uuid::new_v4().to_string(),
            held,
            observations,
            rollback_failures: 0,
        })
    }

    /// Reconcile a held reservation to the `actual` spend: for each budget, apply `actual − reserved`
    /// in that budget's unit (releasing the over-estimate, or charging a low one). Idempotent per
    /// reservation (the settle marker dedupes a retry). Returns the number of budgets whose settle
    /// **failed** against the store — non-zero means the distributed counter has drifted, which the
    /// caller records to `edgeguard_llm_budget_reconcile_failures_total`.
    pub async fn reconcile(&self, reservation: &Reservation, actual: Spend) -> usize {
        let mut failures = 0usize;
        for (key, reserved, idx) in &reservation.held {
            let budget = &self.budgets[*idx];
            let actual_amount = budget.amount(actual.tokens, actual.cost_micros);
            let delta = actual_amount as i64 - *reserved as i64;
            if delta != 0 {
                // Marker = counter key + reservation id, so THIS reservation's settle applies once.
                let marker = format!("{key}:s:{}", reservation.id);
                if !self
                    .store
                    .reconcile(key, delta, budget.ttl_ms(), &marker)
                    .await
                {
                    failures += 1;
                }
            }
        }
        failures
    }

    /// Release a reservation in full (actual spend was zero — upstream error / no usage produced).
    /// Returns the count of failed settles (drift), like [`Self::reconcile`].
    pub async fn release(&self, reservation: &Reservation) -> usize {
        self.reconcile(reservation, Spend::default()).await
    }

    /// Roll back the amounts reserved so far (used when a later budget denies / errors). Each rollback
    /// gets a unique marker (it runs once), so a retry of that rollback still dedupes. Returns the
    /// count of failed settles (drift), like [`Self::reconcile`]/[`Self::release`] — a failed
    /// rollback settle leaks that budget's hold exactly like a failed reconcile does.
    async fn rollback(&self, held: &[(String, u64, usize)]) -> usize {
        let mut failures = 0usize;
        for (key, amount, idx) in held {
            let budget = &self.budgets[*idx];
            let marker = format!("{key}:rb:{}", uuid::Uuid::new_v4());
            if !self
                .store
                .reconcile(key, -(*amount as i64), budget.ttl_ms(), &marker)
                .await
            {
                failures += 1;
            }
        }
        failures
    }
}

/// `used / limit` as a ratio in `[0.0, ∞)` (0.0 when the limit is 0, which `Budget::build` already
/// rejects, so this is just belt-and-suspenders against a divide-by-zero).
fn ratio(used: u64, limit: u64) -> f64 {
    if limit == 0 {
        return 0.0;
    }
    used as f64 / limit as f64
}

/// Current wall-clock time in whole seconds since the Unix epoch (the budget window's basis).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BudgetCfg;

    fn token_budget(limit: f64, window: &str) -> BudgetCfg {
        BudgetCfg {
            name: "test".into(),
            scope: "key".into(),
            unit: "tokens".into(),
            limit,
            window: window.into(),
        }
    }

    fn engine(budgets: Vec<BudgetCfg>) -> BudgetEngine {
        BudgetEngine::build(&LlmCfg {
            enabled: true,
            budgets,
            store: "memory".into(),
            ..Default::default()
        })
        .unwrap()
        .expect("budgets configured")
    }

    /// Test shorthand for the request dimensions (no team).
    fn dims<'a>(principal: Option<&'a str>, model: &'a str) -> Dims<'a> {
        Dims {
            principal,
            model,
            team: None,
        }
    }

    #[test]
    fn would_reserve_caps_at_limit() {
        assert!(would_reserve(0, 100, 100));
        assert!(would_reserve(90, 10, 100));
        assert!(!would_reserve(90, 11, 100));
        // Saturating add: a huge amount never wraps to admit.
        assert!(!would_reserve(u64::MAX, 1, 100));
    }

    #[test]
    fn unit_and_scope_parse() {
        assert_eq!(BudgetUnit::parse("tokens").unwrap(), BudgetUnit::Tokens);
        assert_eq!(BudgetUnit::parse("USD").unwrap(), BudgetUnit::UsdMicros);
        assert!(BudgetUnit::parse("bananas").is_err());
        assert_eq!(BudgetScope::parse("global").unwrap(), BudgetScope::Global);
        assert_eq!(BudgetScope::parse("per-key").unwrap(), BudgetScope::PerKey);
        assert!(BudgetScope::parse("galaxy").is_err());
    }

    #[test]
    fn build_is_none_without_budgets() {
        let none = BudgetEngine::build(&LlmCfg::default()).unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn limit_rounding_to_zero_is_rejected() {
        // 0.3 tokens > 0.0 but rounds to 0 — a nonsensical budget; catch it at startup.
        assert!(Budget::build(&BudgetCfg {
            name: "tiny".into(),
            scope: "global".into(),
            unit: "tokens".into(),
            limit: 0.3,
            window: "1h".into(),
        })
        .is_err());
    }

    #[test]
    fn usd_budget_compiles_to_micros() {
        let b = Budget::build(&BudgetCfg {
            name: "spend".into(),
            scope: "global".into(),
            unit: "usd".into(),
            limit: 2.50,
            window: "24h".into(),
        })
        .unwrap();
        assert_eq!(b.limit, 2_500_000); // $2.50 -> micro-dollars
        assert_eq!(b.unit, BudgetUnit::UsdMicros);
    }

    #[tokio::test]
    async fn retry_async_succeeds_after_transient_failures() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let r: Result<u32> = retry_async(3, Duration::from_millis(0), || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    anyhow::bail!("transient blip")
                } else {
                    Ok(n)
                }
            }
        })
        .await;
        assert_eq!(r.unwrap(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_async_gives_up_after_exhausting_attempts() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let r: Result<()> = retry_async(2, Duration::from_millis(0), || {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { anyhow::bail!("always fails") }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn memory_reconcile_is_idempotent_per_marker() {
        // The core of the distributed-reconcile hardening: a settle applies at most once per marker,
        // so a retry (or a double call) can't double-apply the delta and drift the counter.
        let store = MemoryStore::default();
        assert!(store.reserve("k", 100, 1000, 60_000).admitted); // used = 100
        store.reconcile("k", -40, 60_000, "settle-1"); // used = 60
        store.reconcile("k", -40, 60_000, "settle-1"); // same marker → no-op (NOT 20)
        assert_eq!(store.reserve("k", 0, 1000, 60_000).used_after, 60);
        // A different settle (different marker) applies.
        store.reconcile("k", -10, 60_000, "settle-2");
        assert_eq!(store.reserve("k", 0, 1000, 60_000).used_after, 50);
    }

    #[tokio::test]
    async fn reserve_admits_until_limit_then_denies() {
        let eng = engine(vec![token_budget(100.0, "1h")]);
        let est = Spend {
            tokens: 60,
            cost_micros: 0,
        };
        // 60 + 60 = 120 > 100, so the second reserve is denied.
        assert!(matches!(
            eng.reserve(dims(Some("alice"), "gpt-4o"), est).await,
            Reserved::Ok(_)
        ));
        assert!(matches!(
            eng.reserve(dims(Some("alice"), "gpt-4o"), est).await,
            Reserved::Denied(d) if d.name == "test"
        ));
        // A different principal has its own budget.
        assert!(matches!(
            eng.reserve(dims(Some("bob"), "gpt-4o"), est).await,
            Reserved::Ok(_)
        ));
    }

    #[tokio::test]
    async fn reconcile_releases_overestimate() {
        let eng = engine(vec![token_budget(100.0, "1h")]);
        // Reserve 80 (estimate), then reconcile to an actual of 30 → 50 released.
        let reserved = match eng
            .reserve(
                dims(Some("c"), "m"),
                Spend {
                    tokens: 80,
                    cost_micros: 0,
                },
            )
            .await
        {
            Reserved::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        eng.reconcile(
            &reserved,
            Spend {
                tokens: 30,
                cost_micros: 0,
            },
        )
        .await;
        // Used is now 30; a new 70 fits (30 + 70 = 100), but 71 would not.
        assert!(matches!(
            eng.reserve(
                dims(Some("c"), "m"),
                Spend {
                    tokens: 70,
                    cost_micros: 0
                }
            )
            .await,
            Reserved::Ok(_)
        ));
    }

    #[tokio::test]
    async fn release_returns_full_reservation() {
        let eng = engine(vec![token_budget(100.0, "1h")]);
        let reserved = match eng
            .reserve(
                dims(Some("d"), "m"),
                Spend {
                    tokens: 100,
                    cost_micros: 0,
                },
            )
            .await
        {
            Reserved::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        // Full budget reserved → next is denied…
        assert!(matches!(
            eng.reserve(
                dims(Some("d"), "m"),
                Spend {
                    tokens: 1,
                    cost_micros: 0
                }
            )
            .await,
            Reserved::Denied(_)
        ));
        // …but after releasing the whole hold (upstream errored), the budget is free again.
        eng.release(&reserved).await;
        assert!(matches!(
            eng.reserve(
                dims(Some("d"), "m"),
                Spend {
                    tokens: 100,
                    cost_micros: 0
                }
            )
            .await,
            Reserved::Ok(_)
        ));
    }

    #[tokio::test]
    async fn multi_budget_denial_rolls_back_prior_reserve() {
        // Two budgets: a generous token budget and a tight cost budget. A request that fits the
        // first but not the second must leave the first budget unconsumed.
        let eng = engine(vec![
            BudgetCfg {
                name: "tok".into(),
                scope: "global".into(),
                unit: "tokens".into(),
                limit: 1000.0,
                window: "1h".into(),
            },
            BudgetCfg {
                name: "cost".into(),
                scope: "global".into(),
                unit: "usd".into(),
                limit: 0.000010, // 10 micro-dollars
                window: "1h".into(),
            },
        ]);
        // tokens=100 fits "tok"; cost=20 micro exceeds "cost" (10) → denied by "cost", "tok" rolled back.
        assert!(matches!(
            eng.reserve(dims(None, "m"), Spend { tokens: 100, cost_micros: 20 }).await,
            Reserved::Denied(d) if d.name == "cost" && d.unit == BudgetUnit::UsdMicros
        ));
        // "tok" must be untouched: a 1000-token request still fits.
        assert!(matches!(
            eng.reserve(
                dims(None, "m"),
                Spend {
                    tokens: 1000,
                    cost_micros: 0
                }
            )
            .await,
            Reserved::Ok(_)
        ));
    }

    #[tokio::test]
    async fn per_team_scope_is_keyed_by_team() {
        let eng = engine(vec![BudgetCfg {
            name: "team-cap".into(),
            scope: "team".into(),
            unit: "tokens".into(),
            limit: 100.0,
            window: "1h".into(),
        }]);
        let est = Spend {
            tokens: 60,
            cost_micros: 0,
        };
        let team_a = Dims {
            principal: Some("alice"),
            model: "gpt-4o",
            team: Some("team-a"),
        };
        // team-a fills to 60, then 120 > 100 denies — even though the principal differs, the team
        // key is shared.
        assert!(matches!(eng.reserve(team_a, est).await, Reserved::Ok(_)));
        let team_a_bob = Dims {
            principal: Some("bob"),
            model: "gpt-4o",
            team: Some("team-a"),
        };
        assert!(matches!(
            eng.reserve(team_a_bob, est).await,
            Reserved::Denied(d) if d.scope == BudgetScope::PerTeam
        ));
        // A different team has its own budget.
        let team_b = Dims {
            principal: Some("alice"),
            model: "gpt-4o",
            team: Some("team-b"),
        };
        assert!(matches!(eng.reserve(team_b, est).await, Reserved::Ok(_)));
    }

    #[tokio::test]
    async fn reserve_reports_consumed_ratio() {
        let eng = engine(vec![token_budget(100.0, "1h")]);
        let r = match eng
            .reserve(
                dims(Some("alice"), "m"),
                Spend {
                    tokens: 75,
                    cost_micros: 0,
                },
            )
            .await
        {
            Reserved::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        let obs = r.observations();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].name, "test");
        assert!(
            (obs[0].consumed_ratio - 0.75).abs() < 1e-9,
            "{}",
            obs[0].consumed_ratio
        );
    }

    // ---- Live-Redis proof (mirrors the limiter's #[ignore]d tests) ----------------------------
    //
    //   docker run --rm -p 6379:6379 redis:7-alpine
    //   cargo test -p eggrd --lib budget::tests::redis_ -- --ignored

    fn redis_url() -> String {
        std::env::var("EDGEGUARD_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
    }

    #[tokio::test]
    #[ignore = "requires a live Redis (EDGEGUARD_TEST_REDIS_URL, default redis://127.0.0.1:6379)"]
    async fn redis_budget_reserve_and_reconcile_live() {
        let eng = BudgetEngine::build(&LlmCfg {
            enabled: true,
            store: "redis".into(),
            redis_url: redis_url(),
            redis_prefix: format!("egtest:budget:{}:{}", std::process::id(), now_secs()),
            budgets: vec![token_budget(100.0, "1h")],
            ..Default::default()
        })
        .unwrap()
        .expect("budgets configured");

        let est = Spend {
            tokens: 60,
            cost_micros: 0,
        };
        // First reserve proves reachability; a store error (Redis down) fails closed → skip.
        let reserved = match eng.reserve(dims(Some("alice"), "m"), est).await {
            Reserved::Ok(r) => r,
            Reserved::Error { .. } => {
                eprintln!("skipping redis_budget_reserve_and_reconcile_live: Redis unreachable");
                return;
            }
            other => panic!("unexpected first reserve: {other:?}"),
        };
        // 60 + 60 > 100 → second denied.
        assert!(matches!(
            eng.reserve(dims(Some("alice"), "m"), est).await,
            Reserved::Denied(_)
        ));
        // Reconcile the first down to 10 actual → frees room for another 60.
        eng.reconcile(
            &reserved,
            Spend {
                tokens: 10,
                cost_micros: 0,
            },
        )
        .await;
        assert!(matches!(
            eng.reserve(dims(Some("alice"), "m"), est).await,
            Reserved::Ok(_)
        ));
    }
}
