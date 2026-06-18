# EdgeGuard

A drop-in Rust edge proxy that gives any HTTP app a secure front door — **authentication,
rate limiting, TLS, and hardened response headers** — with secure-by-default config and
**zero code changes** to the upstream app.

It's the missing front door for apps that were generated (vibe-coded) without one.
EdgeGuard owns the request path (auth, rate-limit, validation) and the response path
(CSP/HSTS/cookie hardening) in a single static binary.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)

> **Status: v0 shipped, v1 landed, v2 landed, v2.5 underway.** The barebone v0 slice is stable;
> the **v1** (self-hostable & production-usable) feature set below has landed and is tested
> in-process. The one exception is **ACME**, which is implemented and compiled but can only be
> proven against a live CA (see [Platform support](#tls--acme)). The **v2 (WAF-lite)** phase has
> landed: [input inspection](#waf-lite-input-rules) (off by default), a [shared-store rate
> limiter](#distributed-rate-limiting) for multi-replica deployments, and an optional
> [public/private split](#publicprivate-split) for the ops endpoints. (The Redis limiter
> backend, like ACME, is compiled but proven only against a live store.) **v2.5 (static/edge
> surface)** is underway: an [`edgeguard generate`](#static--edge-hosts) config generator for
> static hosts and a [Rust→WASM Cloudflare Worker](worker/README.md) (the worker, like ACME and
> Redis, compiles but is proven only against a live deploy). Codename "EdgeGuard" is a working
> title — see the [roadmap](docs/ROADMAP.md).

## Where it fits

EdgeGuard is a **reverse proxy you put directly in front of one app** — the secure front door
between the public internet (or your platform's load balancer) and your application process. It
terminates/authenticates the request, forwards it to your app *unchanged*, and hardens the
response on the way back.

```text
         public internet
    (clients · bots · scanners)
               │   :443 / :8080
               │   TLS · auth · rate-limit · WAF · request validation
               ▼
       ┌──────────────────┐
       │     EdgeGuard     │   ◀── this project (the secure front door)
       └──────────────────┘
               │   plain HTTP on APP_PORT, localhost only
               │   CSP · HSTS · cookie hardening · leaky-header stripping on the way back
               ▼
       ┌──────────────────┐
       │      your app     │   ◀── unchanged (Node / Python / Go / Rust / …)
       └──────────────────┘
               │
               ▼
        DB · internal APIs
```

In the larger picture it sits **between your edge (CDN / platform LB / DNS) and your app** — one
hop, one upstream:

```text
  DNS ─▶ [ CDN / platform LB ] ─▶ [ EdgeGuard ] ─▶ [ your app ] ─▶ [ DB / internal APIs ]
          optional: caching, DDoS    this project     unchanged
```

Run it as the container **entrypoint that wraps your app**, or as a **separate front service**
pointing at an upstream URL — see [Two deployment modes](#two-deployment-modes).

### What it does *not* replace

EdgeGuard is a focused security front door, not a platform. It does **not** replace:

- **Your CDN / DDoS edge** (Cloudflare, Fastly, CloudFront) — it hardens one origin; no global
  caching, anycast, or volumetric DDoS absorption. Run it *behind* the CDN.
- **A full WAF** (ModSecurity, Coraza, AWS WAF) — the built-in [WAF-lite](#waf-lite-input-rules)
  is heuristic and off by default: signatures, not a managed rule feed.
- **An identity provider** (Auth0, Keycloak, Cognito) — it *verifies* tokens (JWT/JWKS) and gates
  with Basic / API-key; it doesn't issue tokens, manage users, or run OAuth flows.
- **An API gateway / service mesh** (Kong, Istio, Envoy mesh) — one upstream, no service
  discovery, routing fabric, or request transformation beyond the security pipeline.
- **Your app's own authorization** — it's a coarse front-door gate (is this request allowed in at
  all); per-user / per-resource permissions still live in your app.
- **Platform-terminated TLS** — on most PaaS you leave TLS off and let the platform manage certs;
  TLS termination here is for the VPS / front-proxy path.

### Moving an existing app behind it

- **Exposed directly today, no proxy** (a Node/Python/Go server on a VPS or PaaS): make EdgeGuard
  the entrypoint and bind your app to `APP_PORT` (localhost). One Dockerfile change (see
  [`examples/`](examples/)) and the app gains auth + rate-limit + headers with **zero code
  changes** — your app stops listening on the public port, EdgeGuard does.
  ```bash
  # before:  node server.js                      # app listens on $PORT, public
  # after:   EdgeGuard binds $PORT, runs the app on APP_PORT
  PORT=8080 APP_PORT=3000 edgeguard --config edgeguard.toml --wrap "node server.js"
  ```
- **Behind plain nginx / Caddy** (TLS + reverse proxy only, no auth/limits): drop EdgeGuard
  between that proxy and the app, or replace the proxy — point `UPSTREAM` at your app and let
  EdgeGuard own TLS too.
  ```bash
  UPSTREAM=http://127.0.0.1:3000 edgeguard --config edgeguard.toml
  ```
- **Coming off a hosted gate** (oauth2-proxy + nginx, or Cloudflare Access in front): EdgeGuard
  folds the auth gate + rate-limit + header hardening into one static binary next to the app —
  fewer moving parts, no extra network hop, self-hostable and portable across providers.
- **Static / edge host** (Vercel, Netlify, Cloudflare Pages) where you can't run a long-lived
  proxy: use [`edgeguard generate`](#static--edge-hosts) to emit the hardening config, or the
  [Cloudflare Worker](worker/README.md) for auth + hardening at the edge.

## What it does

- **Reverse proxy** to one upstream (a wrapped child process, or an external URL).
- **Co-process supervisor**: launches your app, restarts it on crash, and forwards
  termination signals on shutdown (acts as a tiny container init). *Full process-group
  signaling on Unix; best-effort child kill on Windows.*
- **Authentication** — pick one gate via `auth.mode`:
  - **HTTP Basic** (plaintext for dev, or `$argon2` PHC hashes);
  - **static API key / bearer token** (constant-time compare, `Authorization: Bearer` or
    `X-API-Key`);
  - **JWT** (HS/RS/ES/PS/EdDSA) with a static key or a fetched, cached **JWKS** (keys
    selected by `kid`; the configured algorithm is pinned to block `alg` substitution).
- **Rate limiting** (GCRA), returns `429`: a global **per-IP** limit, optional **per-route**
  overrides (longest-prefix match), and an optional **per-key** limit keyed by the authenticated
  principal — backed by the in-process `governor` limiter or, for multi-replica deployments, a
  shared **Redis** store so N instances enforce one global limit.
- **WAF-lite input inspection** (`[waf]`, **off by default**): heuristic **SQLi / XSS /
  path-traversal** rulesets plus operator-defined **deny patterns**, with a **report-only**
  rollout mode. A match is logged and counted (`edgeguard_waf_hits_total`); in `block` mode it
  returns `403`. Screens the URL path/query by default (also percent-decoded); headers and body
  are opt-in.
- **TLS termination** via `rustls`, with optional **ACME / Let's Encrypt** (HTTP-01)
  automatic certificates.
- **Prometheus metrics** at `/__edgeguard/metrics` (request rate by outcome, rate-limit
  hits, WAF hits, latency histogram, CSP reports).
- **Public/private split** (optional): serve the internal `/__edgeguard/*` ops endpoints
  (health, readiness, metrics) on a separate **private listener** so they aren't exposed on the
  public port.
- **Config hot-reload**: edit the config file and policy swaps in atomically — no dropped
  connections, and a broken edit is rejected without taking the proxy down.
- **Response hardening**: injects CSP (with **report-only** mode + a violation **report
  sink**), HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`; forces `Secure; HttpOnly; SameSite` on `Set-Cookie`; strips leaky
  headers (`Server`, `X-Powered-By`).
- **Static & edge output** (`edgeguard generate`): emit the response-hardening policy as a
  `_headers` file / `vercel.json` / edge-middleware snippet for static hosts, or run the
  [Cloudflare Worker](worker/README.md) edge build (hardening **+** auth) where the proxy can't.
- **Body-size limit** (`413`), **header-size limit** (`431`), and **method allowlist**
  (`405`).
- **Env-first config** (`PORT` / `APP_PORT` / `UPSTREAM`) with an optional TOML overlay.
- **Structured JSON access logs** and `/__edgeguard/health` + `/__edgeguard/ready`
  endpoints.

## Two deployment modes

1. **Co-process (default for PaaS/VPS)** — EdgeGuard is the container entrypoint, binds the
   platform's `$PORT`, and runs your app on `APP_PORT`:
   ```bash
   edgeguard --config edgeguard.toml --wrap "node server.js"
   ```
2. **Front proxy (separate service)** — point EdgeGuard at an external upstream:
   ```bash
   UPSTREAM=http://app.internal:3000 edgeguard --config edgeguard.toml
   ```

## Quickstart (local)

```bash
cargo build --release

# Wrap any app that reads PORT from the env. EdgeGuard sets PORT=$APP_PORT for it.
PORT=8080 APP_PORT=3000 ./target/release/edgeguard \
  --config edgeguard.toml \
  --wrap "node server.js"

# now hit it (set the user/pass you configured in edgeguard.toml)
curl -u "$EDGEGUARD_USER:$EDGEGUARD_PASS" http://localhost:8080/
```

> ⚠️ The shipped config requires you to set a credential before it will authenticate —
> the default `users` value is a non-working placeholder. **Before exposing anything**,
> replace it with an `$argon2` hash (see [Configuration](#configuration)).

## Project layout

```text
.
├── Cargo.toml
├── edgeguard.toml        # annotated config reference (secure defaults)
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE               # Apache-2.0
├── src/
│   ├── main.rs           # CLI (serve / --hash / generate), bootstrap, graceful shutdown
│   ├── config.rs         # env-first config + TOML overlay, size/rate parsing
│   ├── proxy.rs          # request/response pipeline (auth, limit, hardening)
│   ├── generate.rs       # static-host / edge config generator (`edgeguard generate`)
│   └── supervisor.rs     # co-process supervisor (Unix signals / Windows fallback)
├── docs/
│   ├── REQUIREMENTS.md   # product requirements & scope
│   ├── DEPLOYMENT.md     # deployment & integration strategy
│   └── ROADMAP.md        # phased dev plan → OSS launch → product roadmap
├── examples/
│   ├── Dockerfile.node   # wrap-your-app template (Node)
│   ├── Dockerfile.python # wrap-your-app template (Python)
│   ├── render.yaml       # Render blueprint
│   └── fly.toml          # Fly.io config
└── worker/               # Rust→WASM Cloudflare Worker (edge build; detached crate)
```

## Configuration

All config is optional; EdgeGuard ships secure defaults. See
[`edgeguard.toml`](./edgeguard.toml) for the annotated reference. Environment overrides:

| Env | Meaning | Default |
|---|---|---|
| `PORT` | public listen port | `8080` |
| `APP_PORT` | internal port for the wrapped app | `3000` |
| `ADMIN_PORT` | private listener for the ops endpoints (overrides `server.admin_port`) | `0` (off) |
| `UPSTREAM` | external upstream URL (separate-service mode) | derived from `APP_PORT` |
| `WRAP_CMD` | start command (alternative to `--wrap`) | — |
| `EDGEGUARD_CONFIG` | config path (alternative to `--config`) | — |
| `EDGEGUARD_JWT_SECRET` | HS* JWT secret (overrides `auth.jwt.secret`) | — |
| `EDGEGUARD_API_KEYS` | API keys, comma-separated (overrides `auth.api_keys`) | — |
| `EDGEGUARD_REDIS_URL` | shared-store limiter URL (overrides `ratelimit.redis_url`) | — |
| `RUST_LOG` | log filter, e.g. `info`, `edgeguard=debug` | `info` |

Auth, rate limits, TLS/ACME, CSP reporting, and the header/size limits are configured in the
TOML file — see the annotated [`edgeguard.toml`](./edgeguard.toml). Editing that file while
EdgeGuard is running **hot-reloads** the policy in place (auth, limits, headers, validation);
changing the listen port or TLS settings still needs a restart.

**Hashing a password** (do this before any real deployment — the shipped placeholder will
not authenticate). EdgeGuard ships a built-in helper so you don't need an external tool:

```bash
# reads the password on stdin, prints an argon2id PHC hash
echo -n 'your-password' | edgeguard --hash
# paste the $argon2id$... string as the user's value in edgeguard.toml

# (alternatively, any argon2 PHC tool works, e.g. the `argon2` CLI:)
echo -n 'your-password' | argon2 "$(openssl rand -base64 16)" -id -e
```

> ⚠️ A plaintext `users` value is a **dev-only convenience** — it's compared in constant
> time but never stored hashed. Always use an `$argon2` hash for anything reachable.

## Deploy

Drop one of the wrap-your-app templates into your app repo as `Dockerfile`:

- [`examples/Dockerfile.node`](./examples/Dockerfile.node)
- [`examples/Dockerfile.python`](./examples/Dockerfile.python)

Then deploy to a container PaaS (the v0 target — where a long-running proxy can sit in
front of your app):

- **Railway** — deploy the repo; set `APP_PORT=3000`. Railway injects `$PORT`.
- **Render** — see [`examples/render.yaml`](./examples/render.yaml); health check
  `/__edgeguard/health`.
- **Fly.io** — see [`examples/fly.toml`](./examples/fly.toml).
- **VPS / Coolify** — run the binary under systemd, or `docker compose` with EdgeGuard as
  the front container.

The full strategy (interface patterns, platform matrix, rollout order) is in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

> Static/edge hosts (Vercel, Netlify, Cloudflare Pages) can't run a long-lived proxy
> process — see [Static & edge hosts](#static--edge-hosts) for the `edgeguard generate` config
> generator and the Rust→WASM Cloudflare Worker that cover that surface.

## Architecture

**Request:** client-IP resolution (honors `X-Forwarded-For` only when
`server.trust_forwarded_for = true`; disabled by default so clients cannot spoof
their IP) → header-size limit → rate-limit (per-IP / per-route) → auth → per-key
rate-limit → method allowlist → body-size limit → WAF input inspection (off by default) →
forward to upstream (bounded by `validation.upstream_timeout`, default 30s — a stalled
upstream returns `504` instead of pinning the request).
**Response:** security-header injection (CSP/CSP-Report-Only) → cookie hardening → strip
leaky headers.

Built on `axum` + `hyper` (server), `hyper-util` (upstream client), `governor` + `redis` (rate
limit), `argon2` + `jsonwebtoken` (auth), `rustls` + `instant-acme` (TLS/ACME), `arc-swap`
+ `notify` (hot-reload), `regex` (WAF), `tracing` (logs).

Internal endpoints (dedicated routes, exempt from auth/limits — restrict access to
`/__edgeguard/*` at the network layer, or move them to a private listener with
`server.admin_port`; see [Public/private split](#publicprivate-split)). The `/__edgeguard/*`
namespace is reserved — it is never forwarded upstream:

| Endpoint | Purpose |
|---|---|
| `/__edgeguard/health` | **liveness** — is EdgeGuard up (always `200`) |
| `/__edgeguard/ready` | **readiness** — `200` only when the upstream accepts a connection, else `503` |
| `/__edgeguard/metrics` | Prometheus metrics (text exposition v0.0.4) |
| `/__edgeguard/csp-report` | CSP violation report sink (`POST`, logs + counts, returns `204`) |

## Platform support

**Unix (Linux/macOS) is the supported production path.** The co-process supervisor uses
POSIX process groups and signals (`setsid`, then `SIGTERM`/`SIGKILL` to the child's group)
to cleanly start, restart, and shut down the wrapped app together with any grandchildren.

**Windows is best-effort.** With no POSIX process groups or signals, the supervisor falls
back to a `cmd /C` launch with a plain child kill on shutdown (`kill_on_drop`); grandchild
processes the wrapped command spawns may not be reaped. The proxy itself — auth,
rate-limiting, validation, header hardening — works fine on Windows; only the `--wrap`
supervisor is degraded. On Windows, prefer **front-proxy mode** (point `UPSTREAM` at a
separately managed app) over `--wrap`.

## TLS & ACME

Set `tls.enabled = true` and point `tls.cert_path` / `tls.key_path` at a PEM certificate
chain and private key to serve HTTPS directly (rustls; HTTP/1.1 via ALPN).

To get certificates automatically, enable `[tls.acme]` with your `domains`, contact `email`,
and `accept_tos = true`. EdgeGuard runs the ACME **HTTP-01** challenge (it binds **port 80**
for the validation, so that must be reachable from the internet), writes the issued chain and
key to `tls.cert_path` / `tls.key_path`, and serves them.

> ⚠️ ACME requires a real public domain and inbound port 80, so it can't be exercised by the
> in-process test suite. The flow is implemented against `instant-acme` and compiled in CI,
> but is **only proven against a live CA**. The default directory is **Let's Encrypt staging**
> (`tls.acme.directory_url`) so a first run can't burn the strict production rate limits —
> switch to production explicitly once it works against staging.

For a managed-TLS platform (most PaaS) you typically leave TLS off and let the platform
terminate it; TLS termination here is for the VPS / front-proxy path.

## WAF-lite (input rules)

EdgeGuard can screen requests for common attack signatures before they reach your app. It is
**off by default** and built to roll out safely. Configure it in `[waf]`:

```toml
[waf]
mode = "off"            # "off" (default) | "report" | "block"
sqli = true             # built-in SQL-injection heuristics
xss = true              # built-in cross-site-scripting heuristics
path_traversal = true   # built-in path-traversal heuristics
inspect_path = true     # screen the URL path + query (matched raw AND percent-decoded)
inspect_headers = false # screen header values (noisy — opt in)
inspect_body = false    # screen the (size-capped) request body (opt in)

# Operator-defined deny patterns, evaluated alongside the built-ins:
# [[waf.rules]]
# id = "block-wp-probes"
# pattern = "(?i)/wp-(admin|login)"
# target = "path"       # "path" | "headers" | "body" | "all"
```

- **Modes / report-first.** `report` evaluates every rule and **logs + counts** matches
  (`edgeguard_waf_hits_total`) but still forwards the request; `block` returns **`403
  Forbidden`** on a match (also counted under the `forbidden` request outcome). Start in
  `report`, watch the metric for false positives, then switch to `block`.
- **Heuristics, honestly.** The built-in rules are signature heuristics, not a full WAF — they
  will miss novel payloads and occasionally false-positive on benign input. That is exactly why
  they default off and ship a report-first workflow; tune them per category (`sqli` / `xss` /
  `path_traversal`) or lean on your own `[[waf.rules]]`.
- **Custom patterns are ReDoS-safe.** Patterns use the `regex` crate's RE2 syntax, which
  matches in linear time and rejects backreferences/lookaround, so an operator pattern can't
  cause catastrophic backtracking. A pattern that fails to compile (or an unknown `target`) is
  rejected at startup, and on a bad **hot-reload** the previous policy is kept — just like any
  other config error.
- **Scope.** Only locations whose `inspect_*` flag is on are examined; `inspect_headers` and
  `inspect_body` default off because header/body bytes (cookies, tokens, opaque blobs) are
  noisy. The path is matched both raw and percent-decoded, so `%2e%2e%2f` is caught as `../`.
- **Where it runs.** After auth and the size/method checks, just before the request is
  forwarded — so the internal `/__edgeguard/*` endpoints are never inspected.

## Distributed rate limiting

By default the limiter is in-process (`governor`), so each replica counts independently — three
instances behind a load balancer allow 3× the configured rate. For multi-replica deployments,
point the limiter at a shared store so all instances enforce **one global limit**:

```toml
[ratelimit]
enabled = true
rate = "60/min"
burst = 20
store = "redis"                     # "local" (default) | "redis" | "memory"
redis_url = "redis://10.0.0.5:6379" # or rediss:// for TLS; prefer EDGEGUARD_REDIS_URL
redis_prefix = "edgeguard"          # key namespace, so deployments can share one Redis
fail_open = false                   # store error -> 503 (closed). true -> allow (open).
```

The same `rate` / `burst`, `[[ratelimit.routes]]`, and `[ratelimit.per_key]` settings apply —
only the *storage* of the GCRA state changes. EdgeGuard runs the GCRA check-and-update
atomically as a Redis Lua script, so concurrent replicas can't race it. Replica clocks should be
roughly in sync (NTP).

- **`store = "local"`** (default): in-process `governor`. Fast, no dependency, per-replica.
- **`store = "redis"`**: shared across replicas via Redis (`redis://`, or TLS `rediss://`). The
  connection is established lazily and auto-reconnects.
- **`store = "memory"`**: the shared-store code path backed by an in-process map — equivalent to
  `local` for a single replica; mainly a reference/testing backend.
- **`fail_open`**: when the store is unreachable, fail **closed** (`503`, default — an outage
  can't silently disable limiting) or **open** (allow the request — availability over strict
  limiting).

> ⚠️ The Redis backend is implemented and compiled, but — like ACME — it can only be exercised
> against a live Redis, so it isn't covered by the in-process test suite (the GCRA algorithm and
> the in-memory store are). See [docs/ROADMAP.md](docs/ROADMAP.md), Phase 4.

## Public/private split

The internal `/__edgeguard/*` endpoints are normally served on the public port. To keep the ops
surface (health, readiness, **metrics**) off the public internet, give EdgeGuard a private admin
listener:

```toml
[server]
admin_port = 9090         # 0 (default) = keep internal endpoints on the public port
admin_addr = "127.0.0.1"  # loopback (same-host scraper); "0.0.0.0" for a private NIC
```

When `admin_port` is set, EdgeGuard binds a second, plain-HTTP listener serving
`/__edgeguard/health`, `/__edgeguard/ready`, and `/__edgeguard/metrics`. The public port then
serves only the proxy plus the browser-facing CSP report sink, and any other `/__edgeguard/*`
request to the public port returns `404` (never forwarded upstream). **Point your platform's
health check at the admin port** when you enable this, and keep the admin listener on a trusted
network (loopback, a private subnet, or a service-mesh interface) — it is plain HTTP with no auth.

## Static & edge hosts

Static/edge hosts (Netlify, Cloudflare Pages, Vercel) can't run EdgeGuard's long-lived proxy, but
you can still get EdgeGuard's hardening there in one of two ways.

**1. Generate platform config.** `edgeguard generate` renders the `[headers]` policy into the
native config a static host understands — from the *same* source of truth (`security_headers`) the
live proxy uses, so the generated output can't drift from runtime behavior:

```bash
edgeguard generate --target _headers            # Netlify / Cloudflare Pages `_headers` file
edgeguard generate --target vercel              # vercel.json headers block
edgeguard generate --target vercel-middleware   # Vercel Edge Middleware (middleware.ts)
edgeguard generate --target netlify-edge        # Netlify Edge Function
edgeguard generate --target _headers --out ./public/_headers   # write to a file (else stdout)
```

A static `_headers` file (or header-only middleware) can only *add* response headers — it can't do
EdgeGuard's cookie hardening, leaky-header stripping, auth, or rate limiting. For those at the
edge, use the worker.

**2. Deploy the Cloudflare Worker.** [`worker/`](worker/README.md) is a Rust→WASM build of the
response-hardening **and** edge-auth subset (HTTP Basic / static API key). It authenticates the
request, forwards to your origin, and hardens the response — the same security-header set and
cookie hardening as the proxy. Build and deploy with `worker-build` + `wrangler`; configure the
origin, auth, and hardening via `wrangler.toml` vars / secrets. Like ACME, it compiles to wasm but
is proven only against a live deploy; rate limiting and JWT are out of scope for the edge subset.

## Build & test

```bash
cargo build              # debug build
cargo build --release    # optimized static-ish binary
cargo test               # unit tests + in-process integration tests (stub upstream)
cargo clippy --all-targets -- -D warnings   # lints (CI denies warnings)
cargo fmt --all -- --check                  # formatting (CI checks this)
```

This crate is a member of the parent workspace; from the repo root you can target it with
`cargo build -p eggrd` (the crates.io package id; the binary/lib stay `edgeguard`). The edge worker in [`worker/`](worker/README.md) is a separate
(detached) crate — test its pure logic with `cargo test` in that directory, and build the wasm
artifact with `worker-build`.

## Roadmap

| Phase | Scope | Outcome |
| --- | --- | --- |
| v0 | Proxy + Basic auth + per-IP limit + header injection + logs | OSS single binary (this) |
| v1 | JWT/API-key auth, per-route limits, TLS/ACME, metrics, hot reload, CSP report-only | Self-hostable, production-usable |
| v2 | Heuristic input rules, custom deny patterns, distributed limiter | WAF-lite |
| v2.5 | Static-host config generator (`_headers`/edge middleware) + Rust→WASM Cloudflare Worker | Static/edge surface |

The detailed, checklisted plan lives in [docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). For design rationale
and scope, see [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
