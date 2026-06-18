# EdgeGuard load-test harness

A reproducible, containerized harness for measuring EdgeGuard's performance and validating its
behavior under sustained load. It produces the numbers and the methodology behind the
performance and security-efficacy sections of the white paper (`docs/WHITEPAPER.md`), and the
master plan that ties it together is `docs/TESTPLAN.md`.

The companion **micro**-benchmarks (`../benches/`, criterion) isolate the per-call cost of the
pure-Rust pipeline stages (auth gate, WAF regex, header assembly); this harness measures the
**end-to-end** system under realistic, concurrent traffic.

## Topology

```text
        k6 (load gen) ──HTTP──▶ edgeguard:8080 (public)  ──▶ upstream:80 (nginx stub, static 200)
                                edgeguard:9090 (admin)  ◀──scrape── prometheus ──▶ grafana
                                       │
                                       └── redis (shared-store limiter, redis scenarios)
```

The upstream is a deliberately trivial nginx (`return 200`) so **EdgeGuard is the bottleneck
under test** — a heavy backend would mask the proxy's own overhead. The ops endpoints run on the
private admin listener (`:9090`), so the load-bearing public port isn't serving metrics and the
public/private split is itself exercised under load.

## Prerequisites

- Docker + Docker Compose v2, `curl` on the host. No Rust toolchain needed (EdgeGuard is built
  in-image from the crate by `Dockerfile.edgeguard`).

## Quick start

```bash
cd loadtest

# Proxied baseline, then the SAME profile straight at the upstream — the delta is the proxy tax.
./run.sh baseline baseline
./run.sh baseline baseline --direct

# Cost of each feature, in isolation:
./run.sh auth-apikey auth
./run.sh waf-block   waf

# Limiter validation under 2x overload (run both backends and compare):
./run.sh ratelimit-local ratelimit
./run.sh ratelimit-redis ratelimit

# Realistic stacked policy: capacity (find the knee) and stability (endurance):
./run.sh full saturation
./run.sh full soak           # long-running; drive a hot-reload during it (see below)

# Optional dashboards while a run is in flight:
docker compose --profile observability up -d grafana   # http://localhost:3000 (anon admin)

docker compose down -v       # tear everything down
```

Each run writes `results/<scenario>-<script>-<ts>.{json,log}` (k6 summary + full output).
Prometheus is on http://localhost:9091 and holds the server-side `edgeguard_*` series for the
whole run, so client-side (k6) and server-side (proxy) views can be correlated.

## Scenarios (config × script)

| Config (`configs/*.toml`) | Pair with k6 script | Measures |
|---|---|---|
| `baseline`        | `baseline` (+ `--direct`) | intrinsic proxy overhead / "proxy tax" |
| `auth-apikey`     | `auth`        | API-key gate cost at throughput |
| `waf-block`       | `waf`         | WAF tax + block correctness (no false pos/neg on the corpus) |
| `ratelimit-local` | `ratelimit`   | in-process GCRA shedding under overload |
| `ratelimit-redis` | `ratelimit`   | **live Redis** shared-store limiter (the Phase-4 ◐ item) |
| `full`            | `saturation`  | realistic-policy ceiling + graceful degradation past it |
| `full`            | `soak`        | endurance: memory/FD/latency drift; hot-reload under load |

The k6 scripts are scenario-aware where it matters (the WAF script mixes attack payloads and
asserts 403s; the auth/saturation/soak scripts always send the API key, which auth=none ignores),
so most config×script combinations are valid — the table lists the intended pairings.

## Metrics captured

- **Client side (k6):** RPS achieved, `http_req_duration` p50/p90/p95/p99, error rate, and
  per-scenario custom metrics (admitted vs. shed for the limiter; false-pos/neg for the WAF).
- **Server side (Prometheus, from `edgeguard:9090/__edgeguard/metrics`):**
  `edgeguard_requests_total{outcome=...}`, `edgeguard_ratelimit_hits_total{scope=...}`,
  `edgeguard_waf_hits_total{rule=...}`, and the `edgeguard_request_duration_seconds` histogram.
- **Resource (manual):** sample `docker stats edgeguard-loadtest-edgeguard-1` (CPU %, RSS) over a
  run, and FD count, especially during `soak`. Flat RSS/FD == no leak.

## Multi-replica (distributed-limiter proof)

The headline claim of the shared store is that **N replicas enforce one global limit**. Scale the
proxy and point the limiter at Redis:

```bash
EG_SCENARIO=ratelimit-redis docker compose up -d --build --scale edgeguard=3 \
  edgeguard upstream redis prometheus
# then offer >5000/sec; the ADMITTED total across all 3 replicas should still be ~5000/sec,
# not 3x. Compare against --scale edgeguard=3 with ratelimit-LOCAL, which (correctly) allows ~3x.
```

> The `ports:` mapping in `docker-compose.yml` is for the single-replica case. For `--scale`,
> remove the host port mapping (or front the replicas with a load balancer) so Compose can start
> multiple instances; drive load from a k6 container on the compose network (`BASE_URL` via the
> service name) rather than the host port. See `docs/TESTPLAN.md` for the full multi-replica rig.

## Competitor comparison (EdgeGuard vs. the market)

The harness above measures EdgeGuard against *itself* (proxy tax vs. direct upstream). To validate
EdgeGuard is **competitive** against market proxies, the `compare/` overlay swaps the proxy-under-test
for nginx / HAProxy / Caddy / Traefik / Envoy in pure-passthrough config against the **same** upstream,
network, and k6 profile — the only apples-to-apples way (vendor white-paper RPS on foreign hardware is
not comparable). See [`../docs/COMPARISON.md`](../docs/COMPARISON.md) for methodology and fairness controls.

```bash
cd loadtest
./run-compare.sh edgeguard        # auto-detects docker or podman (COMPOSE_BIN=podman to force)
./run-compare.sh nginx
for t in edgeguard nginx haproxy caddy traefik envoy; do ./run-compare.sh "$t"; done
./compare/summarize.sh            # reduce results/compare-*.json to a Markdown table (needs jq)
docker compose -f docker-compose.yml -f docker-compose.compare.yml down -v   # teardown
```

Each run writes `results/compare-<target>-baseline-<ts>.{json,log,stats}` (k6 summary + CPU%/RSS samples).

## Reproducibility notes

Record these alongside results for the white paper: host CPU/RAM and core count, Docker/kernel
versions, pinned image tags (already pinned in `docker-compose.yml`), the EdgeGuard git commit,
and whether k6 ran co-located with the proxy (it does here — note the loopback caveat; for
headline numbers, run k6 on a separate machine over a real NIC to avoid the generator competing
with the proxy for CPU).
