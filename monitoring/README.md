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
| **Grafana** | http://localhost:3000 | anonymous, no login → dashboard **EdgeGuard / eggrd — Overview** (folder *EdgeGuard*) |
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
`edgeguard_waf_hits_total`, `edgeguard_csp_reports_total`) — no relabeling required.

### Metrics referenced

| Metric | Type | Labels | Panels |
|---|---|---|---|
| `edgeguard_requests_total` | counter | `outcome` | request rate, success ratio, outcome breakdowns, totals |
| `edgeguard_request_duration_seconds` | histogram | `le` | p50/p90/p99 + avg latency |
| `edgeguard_ratelimit_hits_total` | counter | `scope` (`ip`/`route`/`key`) | rate-limit hits |
| `edgeguard_waf_hits_total` | counter | `rule` (`sqli`/`xss`/`path_traversal`/`custom`) | WAF hits |
| `edgeguard_csp_reports_total` | counter | — | CSP reports |
| `up` | gauge | `job` | Targets up (scrape health) |

## Files

```
monitoring/
├── compose.yaml                 # Podman/Docker Compose: edgeguard + upstream + traffic + prometheus + grafana
├── edgeguard.demo.toml          # demo proxy config (public/private split, limiter on, WAF report mode)
├── upstream.conf                # nginx stub backend (static 200)
├── prometheus/
│   └── prometheus.yml           # scrape config (bundled demo + commented host-gateway target)
└── grafana/
    ├── provisioning/
    │   ├── datasources/prometheus.yml   # auto-wired Prometheus datasource
    │   └── dashboards/edgeguard.yml     # dashboard provider
    └── dashboards/
        └── edgeguard-overview.json      # the reference dashboard (publishable template)
```
