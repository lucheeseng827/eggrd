# Reference: Prometheus + Grafana with monitoring bundle 1.6.2

Prometheus and Grafana for eggrd 0.7.0, built on the repository's monitoring bundle
(`monitoring/`, version 1.6.2: the Overview and API-usage dashboards and the alert rules), plus a
dashboard and two alerts for the listener series new in 0.7. `./smoke.sh` brings it up against a
live 0.7.0 edge with traffic and checks that every series, alert and dashboard is there.

## When to use it

- You run eggrd anywhere (the other reference setups) and want its dashboards and alerts.
- You want to see, before deploying, what each 0.7 series looks like with traffic in it.

## Architecture

```
traffic ──► front (nginx, appends X-Forwarded-For) ──► edge :443 (TLS, API keys) ──► app
   └────────────────── straight to edge :443 (no header; plaintext; bare TCP) ──┘
edge :9090 /__edgeguard/metrics ◄── prometheus (bundle alerts.yml + rules-0.7.yml) ◄── grafana
```

| File | What it is |
|---|---|
| `compose.yaml` | The edge, an L7 `front`, the app, a traffic generator, Prometheus 2.54.1, Grafana 11.2.0. Mounts the bundle from `../../../monitoring`. |
| `config/edgeguard.toml` | An edge set up so every dashboard panel has data. |
| `prometheus/prometheus.yml` | Scrapes `edge:9090`; loads the bundle's `alerts.yml` and `rules-0.7.yml`. |
| `prometheus/rules-0.7.yml` | `EdgeGuardForwardedForFallback`, `EdgeGuardTlsHandshakeFailureRatio`, with `promtool` tests in `rules-0.7.test.yml`. |
| `grafana/dashboards/edgeguard-0.7-listeners.json` | Requests in flight, connections vs cap, TLS handshakes and failure ratio, connections closed before a ClientHello, X-Forwarded-For resolution, PROXY protocol headers. |
| `grafana/provisioning/` | The datasource (uid `edgeguard-prometheus`, which the bundle's dashboards expect) and the dashboard provider. |

| Open | URL |
|---|---|
| Grafana (anonymous viewer) | http://127.0.0.1:3000, folder *EdgeGuard*: Overview, API usage, 0.7 listeners |
| Prometheus | http://127.0.0.1:9091 (Status → Rules: the bundle's groups and `eggrd-0.7-listeners`) |
| The edge's metrics | http://127.0.0.1:9092/__edgeguard/metrics |

## The 0.7 series, and what to read in them

| Series | Means | Watch for |
|---|---|---|
| `edgeguard_requests_in_flight{listener}` | Requests being answered, head to last body byte | Rising with flat `connections_open`: the app is backing up. |
| `edgeguard_connections_open` / `_max` / `_rejected_total` | Connections against `server.max_connections` | `EdgeGuardConnectionsNearCap` (bundle) at 80%. Behind an NLB a refused connection looks open to the client until it writes. |
| `edgeguard_tls_handshakes_total{listener}` | Every handshake that ended | The denominator for failures. |
| `edgeguard_tls_handshake_failures_total{listener,reason}` | A subset: `client_cert`, `timeout`, `other` | `EdgeGuardTlsHandshakeFailureRatio` (here) over 20%. |
| `edgeguard_tls_no_client_hello_total{listener}` | Closed before any handshake byte: TCP and PROXY health checks, scans | A steady rate behind an NLB is its checks (about 0.6/s per target). Up to 0.7.0-rc.1 these counted as failures. |
| `edgeguard_forwarded_for_total{result}` | With `trust_forwarded_for`: `used`, or the TCP peer because the header was `absent`, `short`, `invalid` | `EdgeGuardForwardedForFallback` (here). `used` alone does not prove `forwarded_hops` is right: check the access log's `client_ip`. |
| `edgeguard_proxy_protocol_total{listener,result}` | PROXY headers | `EdgeGuardProxyProtocolRefused` (bundle) on `untrusted`/`invalid`. |
| `edgeguard_route_*`, `edgeguard_consumer_*`, `edgeguard_upstream_*`, `edgeguard_edge_overhead_seconds` | API usage by route, consumer and upstream | The bundle's API-usage dashboard and its `edgeguard-api` alerts. |

## Monitoring your own edges

Keep `prometheus` and `grafana`, drop the rest, and point `prometheus/prometheus.yml` at each
edge's admin listener (`server.admin_port`; it has no auth, so scrape it over a private network:
on Kubernetes the `eggrd-admin` Service from the `monitoring` namespace, which `../kubernetes`'
NetworkPolicy admits). Load `monitoring/prometheus/alerts.yml` and `rules-0.7.yml`, and route the
alerts with your Alertmanager. Behind an NLB with PROXY protocol, `EdgeGuardProxyProtocolRefused`
is the alert that catches client IP preservation being switched on (`../aws-nlb`).

## Hardening

Grafana here is anonymous **Viewer** and both UIs bind `127.0.0.1`: a local stack. On a shared
host put Grafana behind your SSO (or eggrd with `auth.mode`), keep Prometheus and the edges' admin
ports on a private network, and set `GF_SECURITY_ADMIN_PASSWORD` from a secret.

## Verify

`./smoke.sh` (Docker or Podman):

| Check | Expect |
|---|---|
| Bundle version | `monitoring/VERSION` is `1.6.2` |
| `doctor`, `promtool test rules` on `rules-0.7.test.yml` and the bundle's `alerts.test.yml` | pass |
| `up{job="edgeguard"}` | 1 |
| Loaded alerts | the bundle's (e.g. `EdgeGuardProxyProtocolRefused`, `EdgeGuardUpstreamPoolDown`, `EdgeGuardConnectionsNearCap`, `EdgeGuardCrlStale`, `EdgeGuardRouteLatencyRegression`) and both of `rules-0.7.yml` |
| After 40 s of traffic | in flight > 0, handshakes, handshake failures, no-ClientHello, `forwarded_for` `used` and `absent`, connections max = 512, ≥ 3 routes, ≥ 4 consumers, a `connect_error` upstream, edge overhead |
| Grafana | dashboards `edgeguard-overview`, `edgeguard-api-usage`, `edgeguard-07-listeners`; the datasource reaches Prometheus |
