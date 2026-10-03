//! OTLP metrics export (`[metrics.otlp]`): the same numbers `/__edgeguard/metrics` serves, pushed to
//! an OpenTelemetry collector on an interval.
//!
//! It converts the Prometheus text exposition rather than instrumenting twice. That exposition is
//! the one place every series is already rendered — requests, latency, LLM, DLP, certificates —
//! so a metric added there is exported here with no second change, and the two can never disagree.
//! Same approach as [`crate::telemetry`]'s spans: OTLP-JSON over HTTP, no SDK, no protobuf.
//!
//! Mapping:
//! * `counter` → cumulative, monotonic **Sum** (start time = process start);
//! * `gauge` (and anything untyped) → **Gauge**;
//! * `histogram` → cumulative **Histogram**: the cumulative `_bucket{le}` series become per-bucket
//!   counts with explicit bounds, plus `_sum` and `_count`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::metrics::Metrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Counter,
    Gauge,
    Histogram,
}

/// One sample line: metric name, labels, value.
#[derive(Debug, Clone, PartialEq)]
struct Sample {
    name: String,
    labels: Vec<(String, String)>,
    value: f64,
}

/// Parse `name{a="x",b="y"} value` (labels optional). `None` for anything that is not a sample.
fn parse_sample(line: &str) -> Option<Sample> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (name, rest) = line.split_at(line.find(['{', ' '])?);
    let mut labels = Vec::new();
    let rest = if let Some(body) = rest.strip_prefix('{') {
        // Walk the label set by hand: values may contain `,`, `}` and escaped quotes.
        let mut chars = body.char_indices().peekable();
        let mut end = None;
        loop {
            while chars.peek().is_some_and(|(_, c)| *c == ',' || *c == ' ') {
                chars.next();
            }
            match chars.peek() {
                Some((i, '}')) => {
                    end = Some(*i);
                    break;
                }
                None => break,
                _ => {}
            }
            let mut key = String::new();
            for (_, c) in chars.by_ref() {
                if c == '=' {
                    break;
                }
                key.push(c);
            }
            if chars.next().map(|(_, c)| c) != Some('"') {
                return None;
            }
            let mut value = String::new();
            let mut closed = false;
            while let Some((_, c)) = chars.next() {
                match c {
                    '\\' => match chars.next().map(|(_, c)| c) {
                        Some('n') => value.push('\n'),
                        Some(other) => value.push(other),
                        None => return None,
                    },
                    '"' => {
                        closed = true;
                        break;
                    }
                    other => value.push(other),
                }
            }
            if !closed {
                return None;
            }
            labels.push((key.trim().to_string(), value));
        }
        let end = end?;
        &body[end + 1..]
    } else {
        rest
    };
    let value = rest.split_whitespace().next()?;
    let value = match value {
        "+Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        "NaN" => f64::NAN,
        v => v.parse().ok()?,
    };
    Some(Sample {
        name: name.to_string(),
        labels,
        value,
    })
}

/// The family a sample belongs to: its own name, or for a histogram's `_bucket`/`_sum`/`_count`
/// series, the histogram's name.
fn family_of<'a>(name: &'a str, types: &BTreeMap<String, Kind>) -> &'a str {
    for suffix in ["_bucket", "_sum", "_count"] {
        if let Some(base) = name.strip_suffix(suffix) {
            if types.get(base) == Some(&Kind::Histogram) {
                return base;
            }
        }
    }
    name
}

fn attributes(labels: &[(String, String)]) -> Value {
    Value::Array(
        labels
            .iter()
            .map(|(k, v)| json!({ "key": k, "value": { "stringValue": v } }))
            .collect(),
    )
}

/// Convert a Prometheus text exposition into an OTLP-JSON `ExportMetricsServiceRequest`.
pub fn to_otlp_json(
    text: &str,
    service_name: &str,
    start_unix_nano: u64,
    now_unix_nano: u64,
) -> Value {
    let mut types: BTreeMap<String, Kind> = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split_whitespace();
            if let (Some(name), Some(kind)) = (parts.next(), parts.next()) {
                let kind = match kind {
                    "counter" => Kind::Counter,
                    "histogram" => Kind::Histogram,
                    _ => Kind::Gauge,
                };
                types.insert(name.to_string(), kind);
            }
        }
    }
    // Samples grouped by family, in the order families first appear.
    let mut order: Vec<String> = Vec::new();
    let mut by_family: BTreeMap<String, Vec<Sample>> = BTreeMap::new();
    for s in text.lines().filter_map(parse_sample) {
        let fam = family_of(&s.name, &types).to_string();
        if !by_family.contains_key(&fam) {
            order.push(fam.clone());
        }
        by_family.entry(fam).or_default().push(s);
    }

    let start = start_unix_nano.to_string();
    let now = now_unix_nano.to_string();
    let mut metrics = Vec::new();
    for fam in order {
        let samples = &by_family[&fam];
        let kind = types.get(&fam).copied().unwrap_or(Kind::Gauge);
        match kind {
            Kind::Counter => {
                let points: Vec<Value> = samples
                    .iter()
                    .map(|s| {
                        json!({
                            "attributes": attributes(&s.labels),
                            "startTimeUnixNano": start,
                            "timeUnixNano": now,
                            "asDouble": s.value,
                        })
                    })
                    .collect();
                metrics.push(json!({
                    "name": fam,
                    "sum": { "aggregationTemporality": 2, "isMonotonic": true, "dataPoints": points },
                }));
            }
            Kind::Gauge => {
                let points: Vec<Value> = samples
                    .iter()
                    .map(|s| {
                        json!({
                            "attributes": attributes(&s.labels),
                            "timeUnixNano": now,
                            "asDouble": s.value,
                        })
                    })
                    .collect();
                metrics.push(json!({ "name": fam, "gauge": { "dataPoints": points } }));
            }
            Kind::Histogram => {
                // Group by the label set without `le`.
                #[derive(Default)]
                struct Acc {
                    buckets: Vec<(f64, f64)>,
                    sum: f64,
                    count: f64,
                }
                let mut groups: Vec<(Vec<(String, String)>, Acc)> = Vec::new();
                for s in samples {
                    let mut labels = s.labels.clone();
                    let le = labels
                        .iter()
                        .position(|(k, _)| k == "le")
                        .map(|i| labels.remove(i).1);
                    let idx = match groups.iter().position(|(l, _)| *l == labels) {
                        Some(i) => i,
                        None => {
                            groups.push((labels, Acc::default()));
                            groups.len() - 1
                        }
                    };
                    let acc = &mut groups[idx].1;
                    if s.name.ends_with("_bucket") {
                        let bound = match le.as_deref() {
                            Some("+Inf") | None => f64::INFINITY,
                            Some(b) => b.parse().unwrap_or(f64::INFINITY),
                        };
                        acc.buckets.push((bound, s.value));
                    } else if s.name.ends_with("_sum") {
                        acc.sum = s.value;
                    } else if s.name.ends_with("_count") {
                        acc.count = s.value;
                    }
                }
                let points: Vec<Value> = groups
                    .into_iter()
                    .map(|(labels, mut acc)| {
                        acc.buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
                        // Prometheus buckets are cumulative; OTLP's are per bucket.
                        let mut prev = 0.0;
                        let counts: Vec<String> = acc
                            .buckets
                            .iter()
                            .map(|(_, c)| {
                                let n = (c - prev).max(0.0);
                                prev = *c;
                                format!("{}", n as u64)
                            })
                            .collect();
                        let bounds: Vec<f64> = acc
                            .buckets
                            .iter()
                            .map(|(b, _)| *b)
                            .filter(|b| b.is_finite())
                            .collect();
                        json!({
                            "attributes": attributes(&labels),
                            "startTimeUnixNano": start,
                            "timeUnixNano": now,
                            "count": format!("{}", acc.count as u64),
                            "sum": acc.sum,
                            "bucketCounts": counts,
                            "explicitBounds": bounds,
                        })
                    })
                    .collect();
                metrics.push(json!({
                    "name": fam,
                    "histogram": { "aggregationTemporality": 2, "dataPoints": points },
                }));
            }
        }
    }

    json!({
        "resourceMetrics": [{
            "resource": { "attributes": [
                { "key": "service.name", "value": { "stringValue": service_name } }
            ]},
            "scopeMetrics": [{
                "scope": { "name": "edgeguard", "version": env!("CARGO_PKG_VERSION") },
                "metrics": metrics,
            }],
        }],
    })
}

fn unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Push the registry to `cfg.endpoint` every `cfg.interval_secs` until `shutdown` flips, then once
/// more so the last interval is not lost. Returns `None` (nothing spawned) when export is off or has
/// no endpoint. A failed push is logged and the next interval tries again; counters are cumulative,
/// so a missed push loses resolution, not counts.
pub fn spawn_exporter(
    cfg: &crate::config::OtlpMetricsCfg,
    metrics: Arc<Metrics>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !cfg.enabled || cfg.endpoint.trim().is_empty() {
        return None;
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms.max(100)))
        .build()
        .ok()?;
    let endpoint = cfg.endpoint.clone();
    let service = cfg.service_name.clone();
    let interval = Duration::from_secs(cfg.interval_secs.max(1));
    let start = unix_nanos();
    tracing::info!(endpoint = %endpoint, ?interval, "OTLP metrics export enabled");
    Some(tokio::spawn(async move {
        let push = |http: reqwest::Client| {
            let body = to_otlp_json(&metrics.render(), &service, start, unix_nanos());
            let endpoint = endpoint.clone();
            async move {
                match http
                    .post(&endpoint)
                    .json(&body)
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                {
                    Ok(_) => tracing::debug!("OTLP metrics pushed"),
                    Err(e) => {
                        tracing::warn!(error = %e, "OTLP metrics push failed; retrying next interval")
                    }
                }
            }
        };
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => push(http.clone()).await,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        push(http.clone()).await;
                        return;
                    }
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "\
# HELP edgeguard_requests_total Requests.
# TYPE edgeguard_requests_total counter
edgeguard_requests_total{outcome=\"ok\"} 7
edgeguard_requests_total{outcome=\"rate_limited\"} 2
# TYPE edgeguard_tls_cert_not_after_seconds gauge
edgeguard_tls_cert_not_after_seconds{source=\"file\",cert=\"a \\\"quoted\\\", b}\"} 1800000000
# TYPE edgeguard_request_duration_seconds histogram
edgeguard_request_duration_seconds_bucket{le=\"0.005\"} 1
edgeguard_request_duration_seconds_bucket{le=\"0.1\"} 3
edgeguard_request_duration_seconds_bucket{le=\"+Inf\"} 4
edgeguard_request_duration_seconds_sum 0.42
edgeguard_request_duration_seconds_count 4
edgeguard_untyped 5
";

    fn metric<'a>(doc: &'a Value, name: &str) -> &'a Value {
        doc["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    #[test]
    fn labels_with_escapes_commas_and_braces_parse() {
        let s = parse_sample(r#"x{cert="a \"q\", b}",n="2"} 3.5"#).unwrap();
        assert_eq!(s.name, "x");
        assert_eq!(
            s.labels,
            vec![
                ("cert".into(), "a \"q\", b}".into()),
                ("n".into(), "2".into())
            ]
        );
        assert_eq!(s.value, 3.5);
        assert_eq!(parse_sample("plain 4").unwrap().labels, vec![]);
        assert!(parse_sample("# HELP x y").is_none());
        assert!(parse_sample(r#"broken{a="x} 1"#).is_none());
    }

    #[test]
    fn counters_gauges_and_histograms_map_to_their_otlp_types() {
        let doc = to_otlp_json(TEXT, "edge-1", 100, 200);
        assert_eq!(
            doc["resourceMetrics"][0]["resource"]["attributes"][0]["value"]["stringValue"],
            "edge-1"
        );

        let req = &metric(&doc, "edgeguard_requests_total")["sum"];
        assert_eq!(req["isMonotonic"], true);
        assert_eq!(req["aggregationTemporality"], 2);
        let points = req["dataPoints"].as_array().unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0]["attributes"][0]["value"]["stringValue"], "ok");
        assert_eq!(points[0]["asDouble"], 7.0);
        assert_eq!(points[0]["startTimeUnixNano"], "100");
        assert_eq!(points[0]["timeUnixNano"], "200");

        let cert = &metric(&doc, "edgeguard_tls_cert_not_after_seconds")["gauge"]["dataPoints"][0];
        assert_eq!(cert["asDouble"], 1_800_000_000.0);
        assert_eq!(
            cert["attributes"][1]["value"]["stringValue"],
            "a \"quoted\", b}"
        );

        let h = &metric(&doc, "edgeguard_request_duration_seconds")["histogram"]["dataPoints"][0];
        assert_eq!(h["count"], "4");
        assert_eq!(h["sum"], 0.42);
        // Cumulative 1,3,4 → per bucket 1,2,1; +Inf is the implicit last bucket.
        assert_eq!(h["bucketCounts"], json!(["1", "2", "1"]));
        assert_eq!(h["explicitBounds"], json!([0.005, 0.1]));
        assert!(
            h["attributes"].as_array().unwrap().is_empty(),
            "le is not an attribute"
        );

        assert!(metric(&doc, "edgeguard_untyped").get("gauge").is_some());
    }

    /// The real registry converts without dropping a family: every `# TYPE` in the Prometheus
    /// output appears as an OTLP metric.
    #[test]
    fn every_family_the_registry_renders_is_exported() {
        let m = Metrics::new();
        m.record_request("ok");
        let text = m.render();
        let doc = to_otlp_json(&text, "edgeguard", 1, 2);
        let exported: std::collections::HashSet<String> = doc["resourceMetrics"][0]["scopeMetrics"]
            [0]["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["name"].as_str().unwrap().to_string())
            .collect();
        let typed: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("# TYPE "))
            .filter_map(|l| l.split_whitespace().next())
            .collect();
        assert!(!typed.is_empty());
        for name in typed {
            let has_samples = text
                .lines()
                .any(|l| !l.starts_with('#') && l.starts_with(name));
            if has_samples {
                assert!(exported.contains(name), "{name} not exported");
            }
        }
    }

    /// The exporter pushes on its interval and once more on shutdown, to the configured endpoint.
    #[tokio::test]
    async fn the_exporter_pushes_on_interval_and_on_shutdown() {
        use axum::{routing::post, Router};
        let received: Arc<std::sync::Mutex<Vec<Value>>> = Arc::default();
        let sink = Arc::clone(&received);
        let app = Router::new().route(
            "/v1/metrics",
            post(move |body: axum::Json<Value>| {
                let sink = Arc::clone(&sink);
                async move {
                    sink.lock().unwrap().push(body.0);
                    "ok"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let metrics = Arc::new(Metrics::new());
        metrics.record_request("ok");
        let cfg = crate::config::OtlpMetricsCfg {
            enabled: true,
            endpoint: format!("http://{addr}/v1/metrics"),
            interval_secs: 1,
            ..Default::default()
        };
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = spawn_exporter(&cfg, Arc::clone(&metrics), rx).expect("enabled");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while received.lock().unwrap().is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "no push within 5 s");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let before = received.lock().unwrap().len();
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        let all = received.lock().unwrap().clone();
        assert!(all.len() > before, "a final push on shutdown");
        let names: Vec<&str> = all[0]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"edgeguard_requests_total"), "{names:?}");

        // Off, or no endpoint: nothing is spawned.
        let (_tx, rx) = tokio::sync::watch::channel(false);
        assert!(spawn_exporter(&crate::config::OtlpMetricsCfg::default(), metrics, rx).is_none());
    }
}
