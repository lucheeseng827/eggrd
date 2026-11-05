# EdgeGuard (eggrd) monitoring stack

A small, self-contained **Prometheus + Grafana** deployment that scrapes an EdgeGuard instance's
`/__edgeguard/metrics` exposition and renders the `edgeguard_*` series on a ready-made dashboard.
Its purpose is twofold:

1. **Validation** — prove, end to end, that EdgeGuard's metrics actually work: bring the stack
   up and watch real request, latency, rate-limit, and WAF series populate a dashboard.
2. **OSS reference template** — the dashboard
   ([`grafana/dashboards/edgeguard-overview.json`](grafana/dashboards/edgeguard-overview.json))
   is a portable, importable template anyone running EdgeGuard can drop into their own Grafana.

This is intentionally **separate from [`../loadtest/`](../loadtest/)**: the load-test harness
drives the proxy to its performance ceiling, while this stack is about observability and
correctness validation, not load.

```text
   [ traffic gen ] ──HTTP──▶ edgeguard:8080 (proxy) ──▶ upstream:80 (nginx stub, static 200)
                             edgeguard:9090 (admin/metrics) ◀──scrape── prometheus ──▶ grafana
```

## Prerequisites

- **Podman** + **podman-compose** (or `podman compose`). Docker Compose works too — the file is
  plain Compose; just swap `podman` for `docker`.
- Outbound access to pull `mancube/eggrd`, `prom/prometheus`, `grafana/grafana`, `nginx`, and
  `curlimages/curl`.

## Quick start (turnkey demo)

From the crate root:

```bash
podman compose -f monitoring/compose.yaml up -d
```

This brings up **everything** — EdgeGuard (the published `mancube/eggrd` image), a stub upstream,
a traffic generator that drives clean + attack-shaped + over-limit requests, Prometheus, and
Grafana with the dashboard pre-provisioned. Within ~15s the dashboard is populated.

| Service | URL | Notes |
|---|---|---|
| **Grafana** | http://localhost:3000 | anonymous, no login → dashboards **EdgeGuard / eggrd — Overview** and **— API usage** (folder *EdgeGuard*) |
| **Prometheus** | http://localhost:9091 | check **Status → Targets**: `edgeguard` should be **UP** |
| **EdgeGuard proxy** | http://localhost:8080 | the public proxy port (try `curl localhost:8080/`) |

Tear down (and drop the Prometheus/Grafana volumes):

```bash
podman compose -f monitoring/compose.yaml down -v
```

### What you should see

The traffic generator exercises every series, so the dashboard's panels all move:

- **Targets up** = 1 (Prometheus is reaching EdgeGuard — metrics work).
- **Request rate by outcome** — a dominant `ok` line plus `rate_limited` from the bursts.
- **Rate-limit hits by scope** — `ip` climbs (the demo limit is `20/sec`, burst `10`).
- **WAF hits by rule** — `sqli`, `xss`, `path_traversal` register (WAF runs in `report` mode, so
  these are counted without blocking the demo traffic).
- **Request latency percentiles** — p50/p90/p99 from the histogram.

The **API usage** dashboard reads the per-route, per-consumer and per-upstream series, the edge's
own overhead, and the connection cap, which the pinned 0.7.0 image exports. The `api` route
answers, and the `legacy` route points at a closed port, so one upstream shows `connect_error`
beside a healthy one. For the 0.7 listener series (TLS handshakes, requests in flight,
`X-Forwarded-For` resolution) with traffic, see `deploy/reference/monitoring`.

## Monitor your own EdgeGuard

To point this stack at an EdgeGuard **you** run (instead of the bundled demo):

1. Run EdgeGuard with the metrics listener reachable from the Prometheus container — the
   recommended [public/private split](../README.md#publicprivate-split):

   ```toml
   [server]
   admin_port = 9090
   admin_addr = "0.0.0.0"   # bind on a reachable interface (keep it on a trusted network)
   ```

2. In [`prometheus/prometheus.yml`](prometheus/prometheus.yml), comment out the `edgeguard:9090`
   target and uncomment the `edgeguard-host` job (it scrapes `host.containers.internal:9090`, the
   Podman host gateway already wired up in `compose.yaml`).

3. Start **only** the monitoring services (skip the bundled proxy/upstream/traffic):

   ```bash
   podman compose -f monitoring/compose.yaml up -d prometheus grafana
   ```

If your EdgeGuard keeps the ops endpoints on the public port (`admin_port = 0`, the default),
point the target at that port and `/__edgeguard/metrics` instead.

## Using the dashboard in your own Grafana (OSS template)

The dashboard is datasource-agnostic — it exposes a **`Data source`** template variable (any
Prometheus datasource), so it imports cleanly anywhere:

- **Grafana UI:** *Dashboards → New → Import →* upload
  [`grafana/dashboards/edgeguard-overview.json`](grafana/dashboards/edgeguard-overview.json),
  then pick your Prometheus datasource.
- **Provisioning:** drop the JSON into your dashboards provider path (this stack does exactly
  that — see [`grafana/provisioning/`](grafana/provisioning/)).

It assumes the standard EdgeGuard metric names (`edgeguard_requests_total`,
`edgeguard_request_duration_seconds`, `edgeguard_ratelimit_hits_total`,
`edgeguard_waf_hits_total`, `edgeguard_csp_reports_total`) — no relabeling required. The
**API usage** dashboard
([`grafana/dashboards/edgeguard-api-usage.json`](grafana/dashboards/edgeguard-api-usage.json))
imports the same way.

### Metrics referenced

| Metric | Type | Labels | Panels |
|---|---|---|---|
| `edgeguard_requests_total` | counter | `outcome` | request rate, success ratio, outcome breakdowns, totals |
| `edgeguard_request_duration_seconds` | histogram | `le` | p50/p90/p99 + avg latency |
| `edgeguard_ratelimit_hits_total` | counter | `scope` (`ip`/`route`/`key`) | rate-limit hits |
| `edgeguard_waf_hits_total` | counter | `rule` (`sqli`/`xss`/`path_traversal`/`custom`) | WAF hits |
| `edgeguard_csp_reports_total` | counter | — | CSP reports |
| `up` | gauge | `job` | Targets up (scrape health) |

API usage dashboard:

| Metric | Type | Labels | Panels |
|---|---|---|---|
| `edgeguard_route_requests_total` | counter | `route`, `method`, `status_class` | requests and 5xx ratio by route |
| `edgeguard_route_request_duration_seconds` | histogram | `route`, `le` | p99 latency by route |
| `edgeguard_upstream_requests_total` | counter | `upstream`, `result` | upstream error ratio, failures by result |
| `edgeguard_upstream_duration_seconds` | histogram | `upstream`, `le` | upstream p99 time to headers |
| `edgeguard_edge_overhead_seconds` | histogram | `le` | edge overhead p50/p99/mean |
| `edgeguard_connections_open` / `edgeguard_connections_max` | gauge | `listener` | connections vs cap |
| `edgeguard_tls_handshake_failures_total` | counter | `listener`, `reason` | client certificates refused, handshake failures |
| `edgeguard_consumer_requests_total` / `edgeguard_consumer_bytes_total` | counter | `consumer`, `status_class` / `direction` | top consumers by requests, bytes, errors |
| `edgeguard_upstream_in_rotation` | gauge | `route`, `upstream` | pool targets in rotation |
| `edgeguard_upstream_health_checks_total` | counter | `route`, `upstream`, `result` | failed health checks |
| `edgeguard_upstream_ejections_total` | counter | `route`, `upstream`, `reason` | ejections |
| `edgeguard_client_cert_header_total` | counter | `result` | forwarded client certificates |
| `edgeguard_proxy_protocol_total` | counter | `listener`, `result` | PROXY protocol headers |

## Alerts

[`prometheus/alerts.yml`](prometheus/alerts.yml) carries three groups:
- **`edgeguard`**: request-level availability, latency, abuse signals and limiter health.
- **`edgeguard-api`**: per upstream, route and listener, the group the API usage dashboard
  pairs with.
- **`edgeguard-acme-budget`**: certificate issuance and expiry. The expiry alerts read the whole
  `edgeguard_tls_cert_not_after_seconds` family, so they cover the client certificates the edge
  presents and the CAs it trusts for client certificates (`cert="client:…"`, `cert="client-ca:…"`).
  `EdgeGuardCrlStale` fires for a client-auth CRL past its `nextUpdate`.

The `edgeguard-api` alerts:

| Alert | Fires when |
|---|---|
| `EdgeGuardUpstreamErrorRatio` | more than 5% of one upstream's requests fail or are answered 5xx for 5m, at more than 0.1 req/s |
| `EdgeGuardUpstreamNotAnswering` | requests are sent to an upstream and none is answered for 5m, at any traffic level |
| `EdgeGuardRouteLatencyRegression` | a route's p99 is over 250ms and more than double the same hour yesterday, for 15m |
| `EdgeGuardConnectionsNearCap` | a listener's open connections are above 80% of `server.max_connections` for 5m |
| `EdgeGuardClientCertRejectSpike` | more than one handshake every 5s is refused for its client certificate, for 10m |
| `EdgeGuardClientCertHeaderRefused` | more than one request every 10s has its `[trusted_client_cert_header]` refused, per reason, for 10m |
| `EdgeGuardUpstreamPoolDown` (critical) | no target of a pool is in rotation, for 1m |
| `EdgeGuardUpstreamTargetOut` | one target of a pool is out of rotation while another is in, for 5m |
| `EdgeGuardUpstreamTargetFlapping` | a pool target is ejected 3 times or more in 15m, for 5m |
| `EdgeGuardProxyProtocolRefused` (critical) | more than one connection every 10s is closed for an `untrusted` or `invalid` PROXY header, for 5m |
| `EdgeGuardProxyProtocolRefusedLowRate` | connections are closed for an `untrusted` or `invalid` PROXY header in the last hour and none was proxied, for 30m (the low-traffic case of the alert above) |
| `EdgeGuardProxyProtocolMissing` | connections from `proxy_protocol_trusted` arrive without a PROXY header and none with one, for 15m |
| `EdgeGuardForwardedForUntrusted` | more than half of the requests carry an `X-Forwarded-For` from outside `server.trusted_forwarders`, at more than one request every 20s, for 15m |

Each has a unit test in [`prometheus/alerts.test.yml`](prometheus/alerts.test.yml), as do
`EdgeGuardCrlStale` and the expiry alert on a client certificate: an input that
makes it fire, and inputs that must not, such as a quiet upstream under the traffic guard or a
listener under the threshold. Run them with
`promtool test rules monitoring/prometheus/alerts.test.yml`.

## The versioned bundle

The alert rules (`prometheus/alerts.yml`) and the dashboards (`grafana/dashboards/*.json`) are
versioned together as one bundle; the version is in [`VERSION`](VERSION). It follows SemVer:

- **major**: an alert or dashboard renamed or removed, or a metric it reads renamed (your routing or
  links break);
- **minor**: a new alert or panel;
- **patch**: a threshold, a description or a layout fix.

On Kubernetes with the Prometheus Operator, the rules file becomes a `PrometheusRule` unchanged:
indent it under `spec:`. The dashboards go into a ConfigMap labelled for the Grafana sidecar
(`grafana_dashboard: "1"` in kube-prometheus-stack). The Enterprise control-plane Helm chart ships
both, stamped with the bundle version (`monitoring.prometheusRule.enabled`,
`monitoring.grafanaDashboards.enabled`).

## Files

```
monitoring/
├── compose.yaml                 # Podman/Docker Compose: edgeguard + upstream + traffic + prometheus + grafana
├── edgeguard.demo.toml          # demo proxy config (public/private split, limiter on, WAF report mode)
├── upstream.conf                # nginx stub backend (static 200)
├── VERSION                      # the bundle version (alerts.yml + dashboards)
├── prometheus/
│   ├── prometheus.yml           # scrape config (bundled demo + commented host-gateway target)
│   ├── alerts.yml               # alerting rules (part of the bundle)
│   └── alerts.test.yml          # promtool unit tests for the edgeguard-api alerts
└── grafana/
    ├── provisioning/
    │   ├── datasources/prometheus.yml   # auto-wired Prometheus datasource
    │   └── dashboards/edgeguard.yml     # dashboard provider
    └── dashboards/
        ├── edgeguard-overview.json      # the reference dashboard (publishable template)
        └── edgeguard-api-usage.json     # routes, upstreams, edge overhead, consumers
```
