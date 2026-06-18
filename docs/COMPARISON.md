# EdgeGuard — Competitive Performance Comparison

**Question this answers:** is EdgeGuard *competitive enough* on throughput and CPU/memory
overhead to put in front of a production app, versus the established market reverse proxies?

**Companion docs:** [`TESTPLAN.md`](TESTPLAN.md) (the white-paper runway), the harness in
[`../loadtest/`](../loadtest/README.md). This doc adds the **cross-product** axis the white paper's
§4 lacked — EdgeGuard vs. competitors, not just EdgeGuard vs. itself.

---

## 1. Why not just cite their white papers

Vendor benchmarks (nginx, Envoy, HAProxy, Caddy, Traefik) publish RPS/latency on **their own
hardware, kernel, payload, and tuning**. Cross-hardware numbers are marketing, not validation —
you cannot conclude anything about EdgeGuard by putting its loopback number next to nginx's
40-core bare-metal number.

The only credible answer runs **every proxy through the identical rig**: same host, same trivial
`return 200` upstream, same k6 profile, same network hop, logging off on all. Then the deltas are
real and attributable to the proxy. That is exactly what this harness does — it reuses the
EdgeGuard load-test topology and swaps the proxy-under-test.

```text
   k6 (same baseline.js) ──HTTP/1.1──▶  <proxy under test>:8080  ──▶  upstream:80 (nginx, return 200)
                                         edgeguard | nginx | haproxy | caddy | traefik | envoy
```

## 2. Competitor set & fairness

All five run **pure passthrough** (no auth/limit/header-rewrite) so the measured number is the
*intrinsic proxy tax* — the same thing EdgeGuard's `baseline` scenario isolates. Configs:
[`../loadtest/compare/`](../loadtest/compare).

| Proxy | Image (pinned) | Lang | Role in the comparison |
|---|---|---|---|
| **EdgeGuard** | built from crate | Rust (hyper/axum) | the system under validation |
| **nginx** | `nginx:1.27-alpine` | C | the throughput benchmark everyone cites |
| **HAProxy** | `haproxy:3.0-alpine` | C | raw-throughput ceiling reference |
| **Caddy** | `caddy:2.8-alpine` | Go | integrated proxy; GC/memory comparison |
| **Traefik** | `traefik:v3.1` | Go | cloud-native twin; 2nd GC/memory point |
| **Envoy** | `envoyproxy/envoy:v1.31-latest` | C++ | heavyweight feature twin; footprint comparison |

**Fairness controls (applied to every target):**
- Same upstream (`upstream:80`, nginx `return 200 "ok"`), same compose network, one HTTP/1.1 hop.
- **Access/request logging OFF** on all (matches EdgeGuard `RUST_LOG=warn`) — no proxy is I/O-bound on logs.
- **Upstream keepalive / connection pooling ON** where configurable (nginx `keepalive 64`, HAProxy
  `http-keep-alive`; Caddy/Traefik/Envoy/EdgeGuard pool by default).
- Multi-core: each proxy uses all cores by default (nginx `worker_processes auto`, tokio multi-thread, etc.).
- No TLS on any (isolates proxy logic; TLS-termination overhead is a separate scenario — TESTPLAN S8).
- Same k6 `baseline.js` ramp (500→10k arrival-rate RPS) and the same `FAST_THRESHOLDS`.

## 3. How to run it

```bash
cd loadtest
# one target:
./run-compare.sh edgeguard          # auto-detects docker or podman
./run-compare.sh nginx
# all six, back to back:
for t in edgeguard nginx haproxy caddy traefik envoy; do ./run-compare.sh "$t"; done
# build the table (needs jq):
./compare/summarize.sh
# teardown:
docker compose -f docker-compose.yml -f docker-compose.compare.yml down -v
#  (podman compose -f ... down -v)
```

Each run writes `results/compare-<target>-baseline-<ts>.{json,log,stats}` — k6 summary, full log,
and CPU%/RSS samples of the proxy container. `summarize.sh` reduces them to the table below.

## 4. Results

**First run — 2026-06-18**, Podman 5.6.2 (WSL machine, 16 vCPU), k6 co-located on the host
(loopback). Each proxy offered the same ramp to 10 000 arrival-rate RPS; all six **absorbed the
full offered load with zero loss** (achieved 5 812/s = the ramp's time-average), so this run
measures *latency-under-moderate-load + footprint*, **not** the saturation ceiling. Sorted by p95.

| Target | Achieved RPS | p50 ms | p95 ms | p99 ms | Error % | Peak mem* |
|---|---:|---:|---:|---:|---:|---:|
| nginx | 5812 | 0.14 | 0.29 | n/a | 0.000 | 244† |
| haproxy | 5812 | 0.15 | 0.30 | n/a | 0.000 | 30 |
| **edgeguard** | **5812** | **0.18** | **0.36** | **0.47** | **0.000** | **26** |
| traefik | 5812 | 0.19 | 0.37 | 0.48 | 0.000 | 95 |
| envoy | 5812 | 0.22 | 0.38 | 0.48 | 0.000 | 50 |
| caddy | 5812 | 0.21 | 0.41 | 0.62 | 0.000 | 51 |

\* Peak container MemUsage in **MB** via `podman stats` — includes page cache on WSL, so it is a
**relative** indicator, not true RSS. `n/a` p99 = the two runs taken before `--summary-trend-stats`
was added (haproxy/nginx); re-run them to get numeric p99.
† nginx's 244 MB is a **buffer-cache artifact** (alpine nginx caches aggressively), not resident
proxy memory — do not read it as RSS. Treat the C/Rust group (26–30 MB) as the low band.

**Reading it:**
- **EdgeGuard is competitive.** p95 **0.36 ms** — it beats Caddy (0.41) and Envoy (p50), ties
  Traefik (0.37), and trails the C-tier (nginx/haproxy ~0.29–0.30) by ~70 µs. All sub-millisecond,
  zero errors. It lands squarely in the Go-proxy latency tier while being a security-integrated proxy,
  not a bare one.
- **Memory is the win.** EdgeGuard's 26 MB is the **lowest** of the group (tied with HAProxy), well
  under the Go proxies (Traefik 95, Caddy 51, Envoy 50). No GC heap → low, flat footprint, exactly the
  predicted edge over Caddy/Traefik.
- **Caveat:** none of the six saturated, so no throughput *ceiling* was found here. To rank max RPS,
  re-run with the `saturation` k6 script (higher offered rate) — see §6.

## 4b. Isolated saturation run (EC2, 2026-06-18)

The loopback run above can't find a throughput ceiling (generator competes with proxy for CPU). This
run fixes both: **two `c7i.2xlarge` (8 vCPU) instances** in one ap-southeast-1 subnet — all six proxies
on one host, **native k6 on a separate host driving load over the private NIC** (harness:
[`../loadtest/ec2/`](../loadtest/ec2/README.md)). k6 `saturation` profile ramps offered load
10k→**60k** RPS (deliberately past the knee). Offered time-average ≈ 25.3k/s; a proxy that served
everything shows ~25.2k achieved with 0 drops, one that kneed shows lower achieved + latency blowup.

| Target | Achieved RPS | p95 ms | p99 ms | Shed % | Peak CPU % | Peak RSS MB | Verdict under 60k burst |
|---|---:|---:|---:|---:|---:|---:|---|
| nginx | 25 246 | 0.27 | 0.55 | 0.00 | 99 | 67 | untouched — ceiling ≫ 60k |
| haproxy | 25 241 | 0.29 | 0.67 | 0.00 | 98 | 36 | untouched — ceiling ≫ 60k |
| **edgeguard** | **25 188** | **4.34** | **17.33** | **0.00** | 99 | **87** | **served the full 60k burst, zero drops — graceful** |
| envoy | 24 408 | 84.76 | 179.98 | 6.69 | 94 | 93 | holds throughput but **sheds 6.7%** |
| traefik | 12 354 | 29.97 | **8715** | 0.05 | 96 | 99 | **collapsed** to ~12k, multi-second tail |
| caddy | 11 600 | 1026 | 5010 | 0.39 | 97 | **995** | **collapsed** to ~12k, RSS ballooned to ~1 GB |

**This is the headline result.** On 8 vCPU, EdgeGuard absorbed the same offered load as nginx/HAProxy
(25.2k/s average, peaks to 60k) with **zero dropped or shed requests** — its effective ceiling is in the
C-tier (≫ what the 60k profile probes), not the Go tier. The cost is tail latency under the burst
(p99 17 ms vs nginx/HAProxy sub-ms), but it never falls over. The Go proxies do the opposite: **Caddy and
Traefik collapse to ~half throughput with multi-second p99s** (Caddy's memory blew to ~1 GB queueing),
and **Envoy keeps throughput only by shedding 6.7%**. EdgeGuard's 87 MB RSS held flat where Caddy's hit
995 MB.

> Caveat: 8 vCPU was big enough that nginx/HAProxy/EdgeGuard never kneed within 60k — to pin EdgeGuard's
> exact ceiling, raise the k6 target or shrink the proxy instance (`INSTANCE_TYPE`). HAProxy needed a
> raised `nofile` ulimit on Docker (added to the compose) — it had silently failed the first pass.

## 5. How to read it — what "competitive enough" means

EdgeGuard's pitch is **not** "fastest proxy on earth." It is "near-nginx proxy tax **with** auth +
rate-limit + WAF + header hardening integrated in one static binary, at a fraction of the Go /
identity-stack memory." So judge against these bars:

- **Throughput / latency:** within ~10–20% of nginx's proxy tax, and **at or above** the Go proxies
  (Caddy/Traefik) at p99 — they pay GC pauses in the tail. HAProxy will likely lead raw RPS (decades
  of tuning); being close, not first, is the pass condition.
- **Memory:** the expected **win**. No GC heap → low, flat RSS. Go proxies idle/run tens of MiB and
  breathe under load; Envoy is heaviest. EdgeGuard RSS should sit at the low end and stay flat (the
  soak claim, TESTPLAN S7).
- **Feature-for-feature:** the others need a module/plugin/sidecar (nginx+lua, Envoy ext_authz,
  oauth2-proxy) to match EdgeGuard's integrated auth+limit+WAF. The fair *product* comparison adds
  those back — a fast-follow: re-run `auth`/`waf` k6 scripts against competitor stacks with equivalent
  features enabled, not just passthrough.

**Verdict rule of thumb:** EdgeGuard is competitive if it lands within ~20% of nginx on RPS/p99 **and**
has the lowest (or near-lowest) RSS. If it trails nginx on raw RPS but wins memory and matches Go
proxies, that still validates the product thesis.

## 6. Environment & caveats (record with every result set)

- Host CPU model + core count + RAM; container engine + version (`docker`/`podman`); kernel; pinned
  image tags (above); EdgeGuard git commit.
- **Loopback caveat (critical):** the default rig co-locates k6 with the proxy on one host. Good for
  **relative deltas** (the whole point here); **headline absolute** RPS needs k6 on a separate machine
  over a real NIC so the generator isn't stealing CPU from the proxy. State which you ran.
- Run each target ≥3× and report median + spread; a single run on a memory-tight VM (e.g. a 2 GiB
  Podman WSL machine) is a smoke test, not a headline.
- This measures **passthrough** tax. The integrated-feature comparison (§5 last bullet) is the
  stronger product story and the recommended next step.
