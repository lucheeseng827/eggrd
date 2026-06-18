# EdgeGuard — Test & Load-Test Plan (white-paper runway)

**Status:** active · **Target:** open-source publish, end of week (Fri 2026-06-19) ·
**Owner:** maintainers · **Companion docs:** [`WHITEPAPER.md`](WHITEPAPER.md) (the deliverable),
[`ROADMAP.md`](ROADMAP.md) (product phases), [`../loadtest/README.md`](../loadtest/README.md)
(the harness), [`../benches/`](../benches) (micro-benchmarks).

This plan defines **what must be tested, load-tested, and measured** to publish a credible
white paper alongside the open-source release. It is the bridge between the code that exists
today and the evidence the paper will cite. It is deliberately scoped to the launch: it closes
the gaps that would undermine a published performance/security claim, and explicitly defers the
rest.

---

## 1. Goal & deliverable

Publish a white paper that an external reader (operator, security engineer, or potential
contributor) can trust and reproduce. Concretely, the paper must be able to state, **with
evidence**:

1. **Correctness** — every advertised control (auth, rate limit, WAF, header hardening,
   TLS, the public/private split) does what the README says, proven by an automated suite.
2. **Performance** — the latency and throughput cost of putting EdgeGuard in front of an app,
   broken down per feature, with a reproducible methodology.
3. **Security efficacy** — the WAF's true/false-positive behavior on a known corpus, and the
   auth gate's correctness under load.
4. **Scaling** — the distributed limiter enforces one global limit across replicas.
5. **Honest limits** — what is *not* proven in-suite and why (and how a reader can prove it).

The paper is only as strong as the artifacts behind it. Those artifacts are the subject of
sections 3–6.

---

## 2. Current state (what already exists)

EdgeGuard already has a **strong functional test base** — this plan extends it, it does not
start from zero.

- **Unit tests** (`#[cfg(test)]` modules, ~94 tests): `parse_size`/`parse_rate`/`parse_duration`,
  `client_ip` (XFF), `harden_cookie`, `check_basic_auth` (plaintext + argon2), JWT/JWKS parsing,
  WAF detection per category, the GCRA quota math, the in-memory limiter store, `security_headers`,
  the `generate` targets.
- **Integration tests** (`tests/integration.rs`, 27 tests) drive the **real** pipeline
  (`build_state` + `build_router`) against an in-process stub upstream: 401/200/403/405/413/429/431/
  502/504, header injection + leaky-header stripping + cookie hardening, CSP report-only + sink,
  per-route/per-key limits, WAF off/report/block + custom rules, the distributed `memory` store,
  and the public/private split.
- **CI** (`.github/workflows/ci.yml`): fmt + clippy (`-D warnings`) + `cargo test --all-targets`
  + release build, on Linux **and** Windows.

**What does NOT exist yet (the gap this plan fills):**

- **No performance/load infrastructure at all** — no benchmarks, no load generator, no throughput
  or latency numbers anywhere. A white paper needs these and there are none.
- **Three subsystems are "compiled but unproven against a live dependency"** (the ◐ items in
  `ROADMAP.md`): the **Redis** limiter backend, **ACME** issuance, and the **Cloudflare Worker**.
  The in-crate suite covers their pure logic and in-process doubles, but not the live transport.
- **No documented methodology** (environment, configs, reproducibility) for any measurement.

---

## 3. Test-completeness plan (close the gaps)

Ordered by impact on the paper's credibility. ☐ = to do for launch · ◇ = nice-to-have / fast-follow.

### 3.1 Prove the ◐ subsystems against live dependencies
These are claimed in the README and roadmap; the paper must either show them working or disclose
them precisely. The harness makes the first two cheap to prove locally.

- ☐ **Distributed limiter against live Redis.** `loadtest/configs/ratelimit-redis.toml` +
  `k6/ratelimit.js` exercise the Redis-backed GCRA Lua script under 2× overload. **Acceptance:**
  admitted ≈ configured cap, no 5xx, hits counted under `scope="ip"`. Then the multi-replica rig
  (`--scale edgeguard=3`, see `loadtest/README.md`) proving the **global** cap holds (~1× cap
  across 3 replicas, vs. ~3× for the `local` store). Promote ROADMAP Phase 4 limiter ◐ → ☑.
- ☐ **ACME HTTP-01 end-to-end against [Pebble](https://github.com/letsencrypt/pebble)** (a tiny
  test ACME CA), as an `#[ignore]`-gated integration test + a compose service. Proves issuance,
  challenge response, and cert install without touching Let's Encrypt rate limits. Promote Phase 3
  ACME ◐ → ☑ (or document as Pebble-proven).
- ◇ **Cloudflare Worker against `wrangler dev`/miniflare** smoke (auth decision + header
  hardening + origin forward). Lower priority for launch — the worker is a detached crate and the
  paper can disclose it as wasm-compiled + unit-tested. Keep ◐, documented.

### 3.2 Harden the input-handling surface (it's a security tool)
- ☐ **Fuzz the config parser and the WAF** with `cargo-fuzz` targets: `parse_size`/`parse_rate`/
  `parse_duration`, the TOML overlay, the percent-decoder, and `WafEngine::evaluate`. RE2 already
  bounds regex time; fuzzing guards the *parsers* against panics on hostile input. Short CI run +
  a longer nightly. **Acceptance:** no panics/OOM over a fixed corpus + N minutes.
- ◇ **Property tests** (`proptest`) for the GCRA admit/shed invariant and `harden_cookie`
  idempotence (hardening an already-hardened cookie is a no-op).

### 3.3 Concurrency / lifecycle under load
- ☐ **Hot-reload under load** — flip policy (WAF mode, a rate) during the `soak` run; assert zero
  error blip and zero dropped connections (the arc-swap claim). Driven from `loadtest/`, asserted
  from the k6 output + Prometheus.
- ☐ **Graceful degradation past saturation** — `k6/saturation.js`: past the knee the proxy sheds
  (503/timeout) and recovers, it does not crash/deadlock/leak. Watch RSS/FD over the run.
- ◇ **Graceful shutdown / supervisor** — SIGTERM drains in-flight requests; the co-process
  supervisor restarts a crashing child and forwards signals (Unix). Partly covered by existing
  unit tests; add a scripted check.

### 3.4 Coverage visibility
- ◇ Wire `cargo-llvm-cov` into CI and report a line/region number in the paper's methodology
  (a figure, not a gate). Identify any untested branch in the request path before publish.

---

## 4. Load-test methodology

**Tooling: k6** (chosen for scriptable scenarios, clean percentile/threshold output, and easy
Prometheus/Grafana correlation). The full, runnable harness is in
[`../loadtest/`](../loadtest/README.md); this section is the methodology the paper documents.

### 4.1 Principle
Make **EdgeGuard the bottleneck**. The upstream is a trivial nginx (`return 200`), so measured
latency/throughput reflects the proxy, not the backend. Every feature scenario is compared to the
**baseline** (pure passthrough), and baseline is compared to **direct-to-upstream** (`--direct`)
to isolate the intrinsic "proxy tax."

### 4.2 Scenario matrix

| # | Config | k6 script | Question answered |
|---|---|---|---|
| S1 | `baseline` (+`--direct`) | `baseline` | Intrinsic proxy overhead: added p50/p99, max-RPS delta |
| S2 | `auth-apikey` | `auth` | Cost of the auth gate at throughput |
| S3 | `ratelimit-local` | `ratelimit` | In-process GCRA: admit/shed correctness + shed cost |
| S4 | `ratelimit-redis` | `ratelimit` | **Live-Redis** shared-store limiter; then multi-replica global cap |
| S5 | `waf-block` | `waf` | WAF tax + zero false-pos/neg on the corpus |
| S6 | `full` | `saturation` | Realistic-policy ceiling + graceful degradation past it |
| S7 | `full` | `soak` | Endurance: memory/FD/latency drift; hot-reload under load |
| S8 | `auth-apikey` (TLS on) | `auth` | TLS-termination overhead (TLS-on vs TLS-off delta) — *adds a `tls`-enabled config* |

(S8's TLS config is a small addition: a self-signed cert mounted into the edgeguard service with
`[tls] enabled = true`; the k6 script targets `https://` with `insecureSkipTLSVerify`.)

### 4.3 Metrics captured (every run)
- **Client (k6):** achieved RPS, `http_req_duration` p50/p90/p95/p99/p99.9, error rate, custom
  per-scenario metrics (admitted-vs-shed, WAF false-pos/neg).
- **Server (Prometheus → `edgeguard:9090`):** `edgeguard_requests_total{outcome}`,
  `edgeguard_ratelimit_hits_total{scope}`, `edgeguard_waf_hits_total{rule}`, and the
  `edgeguard_request_duration_seconds` histogram (server-side latency, to cross-check k6).
- **Resource:** CPU% and RSS via `docker stats`, FD count, sampled across the run (flat == healthy).

### 4.4 Environment & reproducibility (recorded with results)
Host CPU model + core count + RAM; kernel + Docker versions; pinned image tags (already pinned in
compose); EdgeGuard git commit; k6 placement. **Caveat to state in the paper:** the default
harness co-locates k6 with the proxy on one host (loopback) — fine for *relative* deltas
(feature-vs-baseline), but **headline absolute** numbers should be taken with k6 on a separate
machine over a real NIC so the generator doesn't compete with the proxy for CPU. Run each scenario
≥3× and report median + spread.

### 4.5 Micro-benchmarks (criterion, `../benches/`)
Out-of-band of the macro test, isolating per-call CPU cost of the hot-path stages so the paper can
*attribute* the end-to-end overhead:
- `auth.rs` — `authorize` across none / basic-plaintext / basic-argon2 / apikey / jwt-hs256
  (surfaces the deliberate argon2 ms-scale cost vs. sub-µs token checks).
- `waf.rs` — `evaluate` for clean/clean-with-decode/sqli-hit/traversal-decoded.
- `response.rs` — `security_headers` + `parse_size`/`parse_rate` (confirms these are *not* hot).

Run with `cargo bench` (or `make bench`). Smoke-validated: `security_headers` ≈ 175 ns,
`parse_size` ≈ 62 ns, `parse_rate` ≈ 48 ns on the dev box — i.e. header assembly and config
parsing are negligible, so the proxy tax is I/O + auth/WAF, exactly what S1–S5 isolate.

---

## 5. White-paper outline (what each section cites)

`docs/WHITEPAPER.md`, drafted from the artifacts above:

1. **Abstract & motivation** — the "missing front door" thesis (README framing).
2. **Architecture & threat model** — request/response pipeline, the `/__edgeguard/*` namespace,
   secure-by-default posture (README "Architecture" + SECURITY.md).
3. **Functional correctness** — the control matrix and the test that proves each row
   (§2 suite + §3 additions). One table: control → test → result.
4. **Performance** — methodology (§4) → results: S1 proxy tax, S2/S3/S5 per-feature deltas,
   latency percentile tables + throughput curves, attributed to the §4.5 micro-benchmarks.
5. **Security efficacy** — WAF corpus results (S5: false-pos/neg), auth correctness under load
   (S2), and the heuristic-limits honesty already in the README's WAF section.
6. **Scaling** — S4 distributed limiter, single- vs multi-replica global cap.
7. **Resilience** — S6 saturation/degradation, S7 soak + hot-reload-under-load.
8. **Limitations & future work** — the remaining ◐ (Worker live runtime), the loopback caveat,
   heuristic-WAF caveats; pointers to `ROADMAP.md`.
9. **Reproducibility appendix** — exact commands (`./run.sh ...`, `cargo bench`), environment
   capture, and where the raw `results/` land. The whole point: a reader can re-run it.

---

## 6. Timeline to end of week

| Day | Focus | Output |
|---|---|---|
| Mon | Plan + harness scaffolding (this doc, `benches/`, `loadtest/`) | ✅ landed |
| Tue | Run S1–S3 + micro-benchmarks; capture baseline/auth/limiter numbers | results/ + tables |
| Wed | S4 (live Redis + multi-replica) and S5 (WAF); Pebble ACME test; fuzz targets | ◐→☑ promotions |
| Thu | S6/S7 (saturation, soak, hot-reload); resource capture; draft WHITEPAPER.md §1–7 | paper draft |
| Fri | §8–9, reproducibility pass, proof-read, final clippy/test/CI green; **publish** | tagged release |

---

## 7. Definition of done (publish gate)

1. `make test-all` green (fmt + clippy + tests) and CI green on Linux + Windows.
2. `cargo bench` runs clean; micro-benchmark numbers recorded.
3. At least S1–S6 executed with results in `loadtest/results/` and summarized in the paper.
4. Live-Redis limiter and Pebble-ACME proven (or, if deferred, disclosed precisely in §8).
5. `WHITEPAPER.md` complete with the reproducibility appendix; every claim traces to an artifact.
6. No doc claims a capability the code/tests don't back (the existing ROADMAP discipline).
