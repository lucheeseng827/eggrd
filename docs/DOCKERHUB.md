# EdgeGuard (`mancube/eggrd`)

**A drop-in Rust edge proxy: authentication, rate limiting, hardened response headers, and TLS — with zero code changes to your app.**

EdgeGuard is the missing front door for any HTTP app (including the ones generated/vibe-coded without one). It owns the request path (auth, rate-limit, validation, WAF-lite) and the response path (CSP/HSTS/cookie hardening, leaky-header stripping) in a single static binary.

- **Image:** `mancube/eggrd` — static musl binary on **distroless/static**, runs as **nonroot**, no shell, CA roots included.
- **Size:** ~16 MB · **Arch:** `linux/amd64`, `linux/arm64`
- **Binary inside:** `/usr/local/bin/edgeguard` (entrypoint) · **Exposes:** `8080`
- **Default config (baked in):** `/etc/edgeguard/edgeguard.toml`
- **Source / full docs:** [github.com/lucheeseng827/eggrd](https://github.com/lucheeseng827/eggrd) · Apache-2.0

## Where it fits

EdgeGuard is the **secure front door**: one hop that sits **between your clients and
the app**, so traffic reaches the app only after it clears auth, rate limiting, and
validation. Your app stops listening on the public port — EdgeGuard does — and is
forwarded to *unchanged*. One upstream, one hop; it is not a CDN, an API gateway, or
an identity provider.

```
   CLIENTS                 EDGEGUARD                UPSTREAMS
   (public internet)       (this image)             (what it fronts)

 ┌───────────────┐
 │ Browsers      │  ─┐
 │ API callers   │   │          ┌────────────┐ plain HTTP  ┌───────────────┐
 │ LLM / SSE apps│   ├ TLS·auth▶│  edgeguard │ ─────────▶  │ your app      │
 │ bots·scanners │   │ rate-lim │  req path  │ (localhost) │ (unchanged)   │
 └───────────────┘   │ WAF·DLP  │ ────────── │             ├───────────────┤
 ┌───────────────┐   │          │  resp path │ ─────────▶  │ LLM provider  │
 │ CDN / LB / DNS│  ─┘ :443/8080│ CSP · HSTS │  hardened   │ static site   │
 │ (optional)    │              │  cookies   │  response   └───────────────┘
 └───────────────┘              └─────┬──────┘
                                      │
            ┌─────────────────────────┘
            ├──▶ Redis — one global rate-limit shared across replicas
            ├──▶ control plane — policy pull · usage · quota (managed mode)
            └──▶ Prometheus — scrapes /__edgeguard/metrics
```

- **Upstream** — every client hits EdgeGuard, never the app directly: browsers, API
  callers, streaming LLM/SSE apps, bots and scanners. It may sit behind a CDN /
  platform LB that forwards to it; EdgeGuard terminates TLS, authenticates,
  rate-limits, and screens (WAF / edge DLP) before anything is forwarded.
- **EdgeGuard** — the request path (auth, limit, validation) in, the response path
  (CSP/HSTS, cookie hardening, leaky-header stripping) out — one static binary, no
  required external services.
- **Downstream** — a wrapped child on `APP_PORT` or an external `UPSTREAM` URL: your
  own app, a streaming LLM backend, or a static frontend + `/api` backend split via
  `[[upstreams]]`. The app is forwarded to unchanged — zero code changes.
- **Side channels (optional)** — Redis for one global rate-limit across replicas, a
  control plane (managed mode) for policy pull + usage/quota, and Prometheus scraping
  `/__edgeguard/metrics`.

## Tags

| Tag | Notes |
|---|---|
| `latest` | newest release (= `0.2.1`) |
| `0.2.1` | cookie-hardening opt-out (`httponly_cookie_exempt`) for JS-readable / double-submit CSRF cookies |
| `0.2.0` | per-path upstreams, request IDs, gzip, WebSocket passthrough, IP access lists |

Pin a version in production: `mancube/eggrd:0.2.1`.

## Quick start

**Front-proxy mode** — put EdgeGuard in front of an existing upstream (the natural mode for this image):

```bash
docker run -p 8080:8080 \
  -e UPSTREAM=http://app.internal:3000 \
  mancube/eggrd:0.2.1 --config /etc/edgeguard/edgeguard.toml
```

Bring your own config (overrides the baked-in default):

```bash
docker run -p 8080:8080 \
  -e UPSTREAM=http://app.internal:3000 \
  -v "$PWD/edgeguard.toml:/etc/edgeguard/edgeguard.toml:ro" \
  mancube/eggrd:0.2.1 --config /etc/edgeguard/edgeguard.toml
```

> ⚠️ The shipped config's `users` value is a **non-working placeholder** — set a real credential before exposing anything (see [Auth](#auth--secrets)).

**Co-process mode** (EdgeGuard supervises your app as PID 1) needs your app in the same image. Copy the binary into your app's image instead of running this one directly:

```dockerfile
COPY --from=mancube/eggrd:0.2.1 /usr/local/bin/edgeguard /usr/local/bin/edgeguard
ENTRYPOINT ["/usr/local/bin/edgeguard", "--config", "/etc/edgeguard/edgeguard.toml", "--wrap", "node server.js"]
```

EdgeGuard binds the platform's `$PORT` and runs your app on `APP_PORT`. (Full process-group signaling on Unix; Windows is best-effort — prefer front-proxy mode there.)

## Configuration (env)

All config is optional — secure defaults ship in the baked-in `edgeguard.toml`. Common env overrides:

| Env | Meaning | Default |
|---|---|---|
| `PORT` | public listen port | `8080` |
| `APP_PORT` | internal port for the wrapped app | `3000` |
| `UPSTREAM` | external upstream URL (front-proxy mode) | derived from `APP_PORT` |
| `ADMIN_PORT` | private listener for the ops endpoints | `0` (off) |
| `EDGEGUARD_CONFIG` | config path (alternative to `--config`) | — |
| `EDGEGUARD_JWT_SECRET` | HS* JWT secret (overrides config) | — |
| `EDGEGUARD_API_KEYS` | API keys, comma-separated | — |
| `EDGEGUARD_REDIS_URL` | shared-store rate-limiter URL | — |
| `RUST_LOG` | log filter, e.g. `info`, `edgeguard=debug` | `info` |

Auth, rate limits, TLS/ACME, CSP, WAF-lite, and size/method limits are set in the TOML file. Editing it while running **hot-reloads** the policy in place (port/TLS changes still need a restart).

## What it does

- **Reverse proxy** to one upstream (wrapped child process or external URL).
- **Per-path upstreams** (`[[upstreams]]`, single upstream by default): route `/api` to a backend and everything else to a static frontend (longest-prefix wins) — a static-frontend + API-backend split in one proxy.
- **Streaming / passthrough**: SSE (`text/event-stream`) forwarded unbuffered, frame-by-frame (fronts streaming LLM backends without collapsing time-to-first-byte); optional WebSocket / `Upgrade` tunneling.
- **Request IDs** (`X-Request-Id`): reuse a well-formed inbound id or mint a UUID v4, forward it upstream, echo it on every response, tag the access log — one id correlates client, proxy, and app.
- **IP access control** (`[access]`, allow-all by default): coarse CIDR allow/deny lists evaluated by client IP before auth and rate limiting.
- **Response compression** (`validation.compress_responses`, off by default): gzip for clients that ask, skipping already-compressed types and SSE.
- **Auth** (`auth.mode`): HTTP Basic (`$argon2` PHC hashes), static API key / bearer (constant-time), or JWT (HS/RS/ES/PS/EdDSA, static key or cached JWKS; configured `alg` pinned).
- **Rate limiting** (GCRA → `429`): per-IP, optional per-route overrides, optional per-key; in-process `governor` or shared **Redis** store for multi-replica global limits.
- **WAF-lite** (off by default): SQLi / XSS / path-traversal heuristics + custom deny patterns, with a report-only rollout mode.
- **Response hardening**: CSP (+ report-only + report sink), HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`; adds `Secure; HttpOnly; SameSite` to cookies — with a per-cookie `httponly_cookie_exempt` opt-out so a JS-readable double-submit CSRF cookie stays readable; strips `Server` / `X-Powered-By`.
- **TLS** via rustls, optional **ACME / Let's Encrypt** (HTTP-01).
- **Limits**: body-size (`413`), header-size (`431`), method allowlist (`405`).
- **Config hot-reload**, **structured JSON access logs**, **Prometheus metrics**.

## Ops endpoints

The reserved `/__edgeguard/*` namespace is never forwarded upstream:

| Endpoint | Purpose |
|---|---|
| `/__edgeguard/health` | liveness (always `200`) |
| `/__edgeguard/ready` | readiness — `200` only when upstream accepts a connection, else `503` |
| `/__edgeguard/metrics` | Prometheus metrics |
| `/__edgeguard/csp-report` | CSP violation report sink |

Use `ADMIN_PORT` to move these onto a private listener and keep them off the public port.

## Auth / secrets

Hash a password with the built-in helper (distroless has no shell — pass `--hash` as an arg, feed the password on stdin):

```bash
echo -n 'your-password' | docker run -i --rm mancube/eggrd:0.2.1 --hash
# paste the $argon2id$... string as the user's value in edgeguard.toml
```

A plaintext `users` value is **dev-only** (compared in constant time, never stored hashed). Always use an `$argon2` hash for anything reachable.

## License

Apache-2.0. Codename "EdgeGuard" is a working title.
