# EdgeGuard — Cloudflare Worker (edge build)

The slice of [EdgeGuard](../README.md) that runs on a static/edge host that can't run the
long-lived proxy binary: **response-hardening** headers (CSP/HSTS/`X-Frame-Options`/…), cookie
hardening, leaky-header stripping, and a lightweight **edge-auth** gate (HTTP Basic or a static
API key) — compiled from Rust to WebAssembly and deployed as a Cloudflare Worker.

It fetches your configured origin, gates the request, and hardens the response on the way back.
It is the compute counterpart to `edgeguard generate` (which emits static `_headers` /
edge-middleware config): use the generator when you only need headers, use this worker when you
also want auth at the edge.

> **Status / honesty note.** Like ACME and the Redis limiter in the main crate, this worker is
> implemented and builds to wasm, but is **proven only against a live Cloudflare deploy** — the
> wasm `fetch` entrypoint can't run in EdgeGuard's in-process test suite. The pure logic it
> relies on (the security-header set, the auth decision, cookie hardening, header stripping,
> origin-URL joining, env parsing) *is* unit-tested on the native target: `cargo test` here.

## What it does

Request → **edge-auth** (Basic / API key, constant-time compared; `401` on failure) → forward to
`EDGEGUARD_ORIGIN` (method, headers, and body preserved; `X-Forwarded-Proto: https` added) →
**harden response** (inject security headers, strip `Server`/`X-Powered-By`, rewrite `Set-Cookie`
with `Secure; HttpOnly; SameSite`).

The header values mirror the proxy exactly — see `../src/proxy.rs` (`security_headers`,
`harden_cookie`) and `../src/auth.rs` (`constant_time_eq`).

**Out of scope for the edge subset:** rate limiting (needs a stateful binding — Durable Objects /
KV) and JWT/JWKS verification. For those, run the full EdgeGuard proxy.

## Build & deploy

```bash
cargo install worker-build        # once
npm install -g wrangler           # or use `npx wrangler`

# from this directory:
wrangler deploy                   # runs `worker-build --release`, then deploys
wrangler dev                      # local run against the configured origin
```

## Configuration

Non-secret knobs live in [`wrangler.toml`](./wrangler.toml) `[vars]`; credentials are Worker
**secrets** (`wrangler secret put <NAME>`). A secret takes precedence over a var of the same name.

| Variable | Meaning | Default |
|---|---|---|
| `EDGEGUARD_ORIGIN` | Origin URL to front (**required**) | — |
| `EDGEGUARD_AUTH_MODE` | `none` \| `basic` \| `apikey` | `none` |
| `EDGEGUARD_REALM` | Basic-auth realm | `EdgeGuard` |
| `EDGEGUARD_BASIC_USER` / `EDGEGUARD_BASIC_PASS` | Basic credentials (**secret**) | — |
| `EDGEGUARD_API_KEYS` | Comma-separated accepted keys (**secret**) | — |
| `EDGEGUARD_API_KEY_HEADER` | Header carrying the API key (also accepts `Authorization: Bearer`) | `X-API-Key` |
| `EDGEGUARD_HSTS` | Send HSTS | `true` |
| `EDGEGUARD_CSP` | Content-Security-Policy value (empty disables) | `default-src 'self'` |
| `EDGEGUARD_CSP_REPORT_ONLY` | Send CSP as report-only | `false` |
| `EDGEGUARD_CSP_REPORT_URI` | Append a `report-uri` directive | — |
| `EDGEGUARD_FRAME_OPTIONS` | `X-Frame-Options` (empty disables) | `DENY` |
| `EDGEGUARD_REFERRER_POLICY` | `Referrer-Policy` (empty disables) | `no-referrer` |
| `EDGEGUARD_PERMISSIONS_POLICY` | `Permissions-Policy` (empty disables) | `geolocation=(), microphone=(), camera=()` |
| `EDGEGUARD_FORCE_SECURE_COOKIES` | Harden `Set-Cookie` | `true` |
| `EDGEGUARD_STRIP` | Comma-separated response headers to strip | `Server,X-Powered-By` |

Example, locking down an origin with Basic auth at the edge:

```bash
wrangler secret put EDGEGUARD_BASIC_USER   # -> admin
wrangler secret put EDGEGUARD_BASIC_PASS   # -> <a strong password>
# set EDGEGUARD_AUTH_MODE = "basic" and EDGEGUARD_ORIGIN in wrangler.toml, then:
wrangler deploy
```

## Test the pure logic

```bash
cargo test          # native target: header set, auth decisions, cookie hardening, env parsing
```

This crate is a **detached workspace** (note the empty `[workspace]` in `Cargo.toml`): it targets
wasm and depends on the Cloudflare `worker` runtime, so it is intentionally excluded from the
monorepo's native build and from module_52's CI. Build it only with `worker-build` / `wrangler`.
