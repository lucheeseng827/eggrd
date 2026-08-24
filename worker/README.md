# EdgeGuard — Cloudflare Worker (edge build)

The slice of [EdgeGuard](../README.md) that runs on a static/edge host that can't run the
long-lived proxy binary: **response-hardening** headers (CSP/HSTS/`X-Frame-Options`/…), cookie
hardening, leaky-header stripping, and a lightweight **edge-auth** gate (HTTP Basic or a static
API key) — compiled from Rust to WebAssembly and deployed as a Cloudflare Worker.

It fetches your configured origin, gates the request, and hardens the response on the way back.
It is the compute counterpart to `edgeguard generate` (which emits static `_headers` /
edge-middleware config): use the generator when you only need headers, use this worker when you
also want auth at the edge.

> **Status / honesty note.** This worker now **runs**, and was checked by running it rather than
> by reading it. `worker-build --release` produces the deployable bundle, and the bundle was
> executed on **workerd — the same runtime Cloudflare runs in production** — via `wrangler dev`.
> Against a live origin, on 2026-08-24:
>
> | Request | Result |
> |---|---|
> | No credentials, `AUTH_MODE=basic` | `401` with `WWW-Authenticate: Basic realm="EdgeGuard"` |
> | Wrong password | `401` |
> | Correct password | `200`, fetched from the origin, response hardened |
>
> The `200` carried all six hardening headers — HSTS, CSP, `Permissions-Policy`,
> `Referrer-Policy`, `X-Content-Type-Options`, `X-Frame-Options` — and `Server` /
> `X-Powered-By` were stripped.
>
> **The remaining gap is deployment, not execution.** It has not been deployed to a Cloudflare
> account and served public traffic, so account-level concerns — routes, custom domains, secret
> bindings, quotas — are still untested. What is settled is that the wasm builds, loads and
> handles requests correctly in the real runtime.
>
> The pure logic it relies on (the security-header set, the auth decision, cookie hardening,
> header stripping, origin-URL joining, env parsing) is additionally unit-tested on the native
> target: `cargo test` here.

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
the parent workspace's native build and from this crate's CI. Build it only with `worker-build` / `wrangler`.

## Reproducing the proof

Two containers, no host toolchain needed. **Run these from this directory** — the mount is
the parent, so `worker/` resolves the same way regardless of what sits above it.
First build the bundle:

```sh
podman run --rm -v "$PWD/..":/w -w /w/worker \
  docker.io/library/rust:1.90 bash -c '
    rustup target add wasm32-unknown-unknown
    cargo install worker-build --locked
    worker-build --release'
```

That must emit `build/index.js` and `build/index_bg.wasm` (~415 KB). Then run it:

```sh
podman run --rm -v "$PWD/..":/w -w /w/worker \
  docker.io/library/node:22 bash -c '
    npx --yes wrangler@latest dev --local --port 8787 --ip 127.0.0.1 &
    sleep 20
    curl -s -o /dev/null -w "no creds:    %{http_code}\n" http://127.0.0.1:8787/
    curl -s -o /dev/null -w "wrong pass:  %{http_code}\n" -u alice:wrong http://127.0.0.1:8787/
    curl -s -I -u alice:correct-horse http://127.0.0.1:8787/ | grep -iE "^(strict-transport|content-security|x-frame|server|x-powered-by):"'
```

Set `EDGEGUARD_AUTH_MODE = "basic"` plus `EDGEGUARD_BASIC_USER` / `EDGEGUARD_BASIC_PASS` in the
config you pass. Expect `401`, `401`, then a `200` whose headers include the hardening set and
exclude `Server` and `X-Powered-By`.

### Why `strip` is absent from `[profile.release]`

Adding `strip = true` does not shrink this crate — it **breaks the build**, with an error that
points nowhere near the cause:

```
error: failed to generate catch wrappers
caused by: externref table required for catch wrappers
```

`worker-build` invokes wasm-bindgen with `--force-enable-abort-handler`, which generates catch
wrappers that need the externref table; stripping removes the symbols wasm-bindgen uses to find
it. The message names neither `strip` nor `Cargo.toml`, and reads like a toolchain
incompatibility — it was misdiagnosed as one for weeks.

Bisected by holding everything else fixed:

| `lto` | `strip` | Build |
|---|---|---|
| true | true | fails |
| false | true | fails |
| false | none | **succeeds** |
| true | none | **succeeds** |

LTO was never involved. Keep `lto = true`; never add `strip`.
