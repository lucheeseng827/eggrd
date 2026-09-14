//! Access-log shipping — the edge's half of the centralized log plane.
//!
//! # What was missing
//!
//! The edge emits one structured access-log line per request, to **stdout**, and that was the whole
//! story. There was no sink, no transport and no destination: an operator running a fleet had to
//! collect logs per box, out of band, with whatever their platform happened to provide. For a
//! product whose pitch is centralized control of an edge fleet, that is the gap.
//!
//! # Why it ships to a collector rather than to the control plane
//!
//! Two shapes were possible. The control plane could grow a log-ingest endpoint and own the data;
//! or the edge could ship to a collector the operator already runs. This is the second, and the
//! reason is volume: access logs are three to five orders of magnitude more records than the usage
//! deltas the control plane meters. Putting them through the same Postgres that holds invoices
//! would make that store's dominant workload the one thing nobody bills for.
//!
//! Shipping to any NDJSON collector — Vector, Loki, Splunk HEC, Datadog, an S3 writer — means the
//! operator keeps the data on their own retention and their own bill, which is also what a
//! self-hosted enterprise customer wants. It reuses the wire shape the control plane's
//! `[audit.ship]` already established: one POST of newline-delimited JSON, not an SDK per vendor.
//!
//! # This is NOT the audit trail, and the difference is deliberate
//!
//! `[audit.ship]` in the control plane is **at-least-once with a cursor**: the audit trail is
//! evidence, and a lost record is a hole in it. Access logs are telemetry. Guaranteeing delivery
//! here would mean an unbounded on-box buffer, and the failure mode of an unbounded buffer on a
//! proxy is that a collector outage takes down the proxy — trading a real outage for a telemetry
//! gap. So this is **best-effort and bounded**, and it counts precisely what it drops.
//!
//! # It must never slow down a request
//!
//! The request path does one `try_send` on a bounded channel and returns. It never awaits, never
//! blocks, never allocates a batch and never touches the network. Everything else happens on a
//! background task. If the channel is full — the collector is slow or gone — the record is dropped
//! and counted, which is the same fail-static discipline the control-plane client uses: degrade the
//! telemetry, never the traffic.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::LogShipCfg;

/// One access-log record on the wire.
///
/// The fields are exactly what `finish()` already logs to stdout — deliberately, so the shipped
/// stream and the local one cannot disagree about what happened. `target` arrives already
/// sanitised by [`crate::accesslog::sanitize_target`]: a proxy that advertises DLP must not be the
/// component that writes credentials into a SIEM.
#[derive(Debug, Clone, Serialize)]
pub struct AccessRecord {
    /// RFC3339 UTC, so a collector can order records across boxes without trusting arrival order.
    pub ts: String,
    pub request_id: String,
    pub method: String,
    /// Path plus sanitised query.
    pub target: String,
    pub client_ip: String,
    pub status: u16,
    pub outcome: String,
    pub latency_ms: u64,
    /// The edge that served it, so a fleet-wide stream stays attributable.
    pub edge_id: String,
}

/// Counters for the shipper itself.
///
/// A log pipeline that silently drops is worse than no pipeline: the gap is invisible in the
/// destination, and the absence of records reads as an absence of traffic. These are exported so
/// the drop is a number someone can alert on.
#[derive(Debug, Default)]
pub struct ShipStats {
    pub sent: AtomicU64,
    /// Records the request path could not hand off because the queue was full.
    pub dropped_queue_full: AtomicU64,
    /// Records in batches the collector refused after the retry.
    pub dropped_send_failed: AtomicU64,
    pub batches_sent: AtomicU64,
    pub batches_failed: AtomicU64,
}

impl ShipStats {
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.sent.load(Ordering::Relaxed),
            self.dropped_queue_full.load(Ordering::Relaxed),
            self.dropped_send_failed.load(Ordering::Relaxed),
            self.batches_sent.load(Ordering::Relaxed),
            self.batches_failed.load(Ordering::Relaxed),
        )
    }
}

/// The handle the request path holds. Cloneable, cheap, and non-blocking to use.
#[derive(Clone)]
pub struct LogShipper {
    tx: mpsc::Sender<AccessRecord>,
    stats: Arc<ShipStats>,
    edge_id: String,
}

impl LogShipper {
    /// This edge's identity, stamped onto every record.
    pub fn edge_id(&self) -> &str {
        &self.edge_id
    }

    pub fn stats(&self) -> &Arc<ShipStats> {
        &self.stats
    }

    /// Hand a record to the shipper. Never blocks and never fails the caller.
    ///
    /// `try_send`, not `send().await`: this is called from the response path of every request. An
    /// await here would couple request latency to collector latency, which is the precise failure
    /// this module exists to avoid — an access-log pipeline is not worth a millisecond of p99, let
    /// alone the unbounded stall a wedged collector would cause.
    ///
    /// A full queue drops the NEWEST record rather than evicting the oldest. Both lose data; this
    /// one is O(1) with no locking, and during a collector outage the older records are the ones
    /// already batched and about to go out. Dropping is counted, never silent.
    pub fn record(&self, rec: AccessRecord) {
        if self.tx.try_send(rec).is_err() {
            self.stats
                .dropped_queue_full
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Build the shipper and spawn its background task. `None` when shipping is disabled.
pub fn spawn(
    cfg: &LogShipCfg,
    edge_id: String,
    shutdown: watch::Receiver<bool>,
) -> Option<LogShipper> {
    if !cfg.enabled || cfg.url.is_empty() {
        return None;
    }
    let stats = Arc::new(ShipStats::default());
    let (tx, rx) = mpsc::channel(cfg.queue_size.max(1));
    let shipper = LogShipper {
        tx,
        stats: Arc::clone(&stats),
        edge_id,
    };
    let task = ShipTask {
        url: cfg.url.clone(),
        headers: cfg.headers.clone(),
        batch: cfg.batch.max(1),
        interval: Duration::from_secs(cfg.interval_secs.max(1)),
        stats,
        // A short timeout on purpose: this task is the only consumer of the queue, so a request
        // that hangs for the client's default (no timeout at all) stops draining and every record
        // behind it is dropped for queue-full. Failing fast and retrying loses less.
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .ok()?,
    };
    info!(url = %cfg.url, batch = task.batch, ?task.interval, "access-log shipping enabled");
    tokio::spawn(task.run(rx, shutdown));
    Some(shipper)
}

struct ShipTask {
    http: reqwest::Client,
    url: String,
    headers: Vec<(String, String)>,
    batch: usize,
    interval: Duration,
    stats: Arc<ShipStats>,
}

impl ShipTask {
    async fn run(self, mut rx: mpsc::Receiver<AccessRecord>, mut shutdown: watch::Receiver<bool>) {
        let mut buf: Vec<AccessRecord> = Vec::with_capacity(self.batch);
        let mut tick = tokio::time::interval(self.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `interval`'s FIRST tick completes immediately. Left in place it fires on the task's first
        // pass through the select, which — if a record arrived before the task was scheduled —
        // flushes a one-record batch at startup instead of after the configured interval. Harmless,
        // but it makes `interval_secs` mean something other than what it says, and it turns the
        // first batch of every process into a batch of one. Consume it here so the first real tick
        // lands one full interval in.
        tick.tick().await;

        loop {
            tokio::select! {
                // Biased so the queue is drained before the timer fires. Without it, a busy edge
                // can starve the drain under a hot timer and hold records longer than the interval
                // it promises.
                biased;

                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                got = rx.recv() => {
                    match got {
                        Some(rec) => {
                            buf.push(rec);
                            if buf.len() >= self.batch {
                                self.flush(&mut buf).await;
                            }
                        }
                        // The senders are gone: the proxy is shutting down.
                        None => break,
                    }
                }
                _ = tick.tick() => {
                    if !buf.is_empty() {
                        self.flush(&mut buf).await;
                    }
                }
            }
        }

        // Drain what is already queued on the way out. A graceful shutdown that discarded the last
        // partial batch would lose exactly the records around a restart — the ones most likely to
        // explain why it happened.
        while let Ok(rec) = rx.try_recv() {
            buf.push(rec);
            if buf.len() >= self.batch {
                self.flush(&mut buf).await;
            }
        }
        if !buf.is_empty() {
            self.flush(&mut buf).await;
        }
    }

    /// POST one batch as NDJSON. Empties `buf` either way — see the module docs on why this is
    /// best-effort rather than at-least-once.
    async fn flush(&self, buf: &mut Vec<AccessRecord>) {
        let n = buf.len() as u64;
        let mut body = String::with_capacity(n as usize * 256);
        for rec in buf.iter() {
            // A record that will not serialize is skipped rather than poisoning the batch: one bad
            // line must not cost the other 499.
            if let Ok(line) = serde_json::to_string(rec) {
                body.push_str(&line);
                body.push('\n');
            }
        }
        buf.clear();

        // One retry, then drop. More would build a backlog behind a collector that is down, which
        // on a bounded queue just converts collector downtime into request-path drops.
        for attempt in 0..2 {
            let mut req = self
                .http
                .post(&self.url)
                .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
                .body(body.clone());
            for (k, v) in &self.headers {
                req = req.header(k.as_str(), v.as_str());
            }
            match req.send().await {
                Ok(r) if r.status().is_success() => {
                    self.stats.sent.fetch_add(n, Ordering::Relaxed);
                    self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Ok(r) => {
                    if attempt == 1 {
                        warn!(status = %r.status(), records = n, "log collector rejected a batch");
                    }
                }
                Err(e) => {
                    if attempt == 1 {
                        warn!(error = %e, records = n, "shipping a log batch failed");
                    }
                }
            }
        }
        self.stats
            .dropped_send_failed
            .fetch_add(n, Ordering::Relaxed);
        self.stats.batches_failed.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn rec(id: &str) -> AccessRecord {
        AccessRecord {
            ts: "2026-09-06T12:00:00Z".into(),
            request_id: id.into(),
            method: "GET".into(),
            target: "/x".into(),
            client_ip: "1.2.3.4".into(),
            status: 200,
            outcome: "proxied".into(),
            latency_ms: 3,
            edge_id: "edge-1".into(),
        }
    }

    fn cfg(url: &str) -> LogShipCfg {
        LogShipCfg {
            enabled: true,
            url: url.into(),
            headers: Vec::new(),
            batch: 2,
            interval_secs: 1,
            queue_size: 8,
        }
    }

    /// The bodies a test collector received, in arrival order.
    type Collected = Arc<std::sync::Mutex<Vec<String>>>;

    /// State the test collector handler runs over.
    #[derive(Clone)]
    struct CollectorState {
        hits: Arc<AtomicUsize>,
        bodies: Collected,
        status: u16,
    }

    /// A collector that records the NDJSON bodies it receives.
    async fn spawn_collector(status: u16) -> (String, Arc<AtomicUsize>, Collected) {
        use axum::extract::State;
        use axum::routing::post;

        let hits = Arc::new(AtomicUsize::new(0));
        let bodies: Collected = Arc::new(std::sync::Mutex::new(Vec::new()));
        let st = CollectorState {
            hits: Arc::clone(&hits),
            bodies: Arc::clone(&bodies),
            status,
        };

        async fn sink(
            State(CollectorState {
                hits,
                bodies,
                status,
            }): State<CollectorState>,
            body: String,
        ) -> axum::http::StatusCode {
            hits.fetch_add(1, Ordering::SeqCst);
            bodies.lock().unwrap().push(body);
            axum::http::StatusCode::from_u16(status).unwrap()
        }

        let app = axum::Router::new()
            .route("/ingest", post(sink))
            .with_state(st);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}/ingest"), hits, bodies)
    }

    #[tokio::test]
    async fn disabled_or_urlless_config_builds_nothing() {
        let (_tx, rx) = watch::channel(false);
        let mut c = cfg("http://example");
        c.enabled = false;
        assert!(spawn(&c, "e".into(), rx.clone()).is_none());

        let mut c = cfg("");
        c.enabled = true;
        assert!(
            spawn(&c, "e".into(), rx).is_none(),
            "enabled with no URL must not spawn a task that can never deliver"
        );
    }

    #[tokio::test]
    async fn a_full_batch_is_posted_as_ndjson() {
        let (url, hits, bodies) = spawn_collector(200).await;
        let (_tx, rx) = watch::channel(false);
        let s = spawn(&cfg(&url), "edge-1".into(), rx).unwrap();

        s.record(rec("a"));
        s.record(rec("b")); // batch = 2, so this triggers a flush
        for _ in 0..50 {
            if hits.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "one batch, not one POST per record"
        );

        let body = bodies.lock().unwrap()[0].clone();
        let lines: Vec<&str> = body.trim_end().split('\n').collect();
        assert_eq!(lines.len(), 2, "NDJSON: one record per line");
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["request_id"], "a");
        assert_eq!(first["edge_id"], "edge-1");
        assert_eq!(first["status"], 200);
        assert_eq!(s.stats().sent.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn a_partial_batch_flushes_on_the_interval() {
        // Otherwise a low-traffic edge holds its last records indefinitely, and the collector shows
        // a gap that looks exactly like an outage.
        let (url, hits, _) = spawn_collector(200).await;
        let (_tx, rx) = watch::channel(false);
        let s = spawn(&cfg(&url), "edge-1".into(), rx).unwrap();

        s.record(rec("only-one")); // below the batch size of 2
        for _ in 0..100 {
            if hits.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the timer must flush a partial batch"
        );
    }

    #[tokio::test]
    async fn a_full_queue_drops_and_counts_rather_than_blocking() {
        // The property the request path depends on. A collector that never answers must cost
        // dropped telemetry, never request latency.
        let (url, _, _) = spawn_collector(200).await;
        let (_tx, rx) = watch::channel(false);
        let mut c = cfg(&url);
        c.queue_size = 1;
        // Large enough that the task never flushes on size, so the queue genuinely fills.
        c.batch = 10_000;
        c.interval_secs = 3_600;
        let s = spawn(&c, "edge-1".into(), rx).unwrap();

        // Far more than the queue can hold. Every one of these must return immediately.
        let started = std::time::Instant::now();
        for i in 0..500 {
            s.record(rec(&format!("r{i}")));
        }
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "recording must never block the request path"
        );
        assert!(
            s.stats().dropped_queue_full.load(Ordering::Relaxed) > 0,
            "a full queue must count its drops — a silent gap reads as an absence of traffic"
        );
    }

    #[tokio::test]
    async fn a_rejecting_collector_is_retried_once_then_the_batch_is_dropped() {
        let (url, hits, _) = spawn_collector(503).await;
        let (_tx, rx) = watch::channel(false);
        let s = spawn(&cfg(&url), "edge-1".into(), rx).unwrap();

        s.record(rec("a"));
        s.record(rec("b"));
        for _ in 0..100 {
            if s.stats().batches_failed.load(Ordering::Relaxed) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "one try plus exactly one retry"
        );
        assert_eq!(s.stats().dropped_send_failed.load(Ordering::Relaxed), 2);
        assert_eq!(s.stats().sent.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn queued_records_are_flushed_on_shutdown() {
        // The records around a restart are the ones most likely to explain it.
        let (url, hits, _) = spawn_collector(200).await;
        let (tx, rx) = watch::channel(false);
        let mut c = cfg(&url);
        c.batch = 100; // never flushes on size
        c.interval_secs = 3_600; // never flushes on the timer
        let s = spawn(&c, "edge-1".into(), rx).unwrap();

        s.record(rec("a"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "nothing should have flushed yet"
        );

        tx.send(true).unwrap();
        for _ in 0..100 {
            if hits.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "shutdown must drain the buffer"
        );
    }

    #[tokio::test]
    async fn configured_headers_are_sent() {
        // How a collector's API key travels: Splunk HEC wants `Authorization: Splunk <token>`,
        // Datadog wants `DD-API-KEY`. One header map rather than an integration per vendor.
        use std::sync::Mutex;
        let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let seen2 = Arc::clone(&seen);

        let app = axum::Router::new().route(
            "/ingest",
            axum::routing::post(move |headers: axum::http::HeaderMap, _b: String| {
                let seen = Arc::clone(&seen2);
                async move {
                    *seen.lock().unwrap() = headers
                        .get("x-api-key")
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);
                    axum::http::StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let (_tx, rx) = watch::channel(false);
        let mut c = cfg(&format!("http://{addr}/ingest"));
        c.headers = vec![("x-api-key".into(), "secret-token".into())];
        let s = spawn(&c, "edge-1".into(), rx).unwrap();
        s.record(rec("a"));
        s.record(rec("b"));

        for _ in 0..100 {
            if seen.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(seen.lock().unwrap().as_deref(), Some("secret-token"));
    }
}
