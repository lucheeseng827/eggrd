# EdgeGuard (`mancube/eggrd`)

**A drop-in Rust edge proxy: authentication, rate limiting, hardened response headers, and TLS and mutual TLS on every hop — with zero code changes to your app.**

EdgeGuard is the missing front door for any HTTP app (including the ones generated/vibe-coded without one). It owns the request path (auth, rate-limit, validation, WAF-lite) and the response path (CSP/HSTS/cookie hardening, leaky-header stripping) in a single static binary, and since 0.7 it can balance and fail over across a pool of upstreams and report API usage by route, consumer and upstream.

- **Image:** `mancube/eggrd` — static musl binary on **distroless/static**, runs as **nonroot**, no shell, CA roots included.
- **Size:** ~7.6 MB compressed (`amd64`), ~7.3 MB (`arm64`), measured on 0.7.0 · **Arch:** `linux/amd64`, `linux/arm64` (both built natively)
- **Binary inside:** `/usr/local/bin/edgeguard` (entrypoint) · **Exposes:** `8080`
- **Default config (baked in):** `/etc/edgeguard/edgeguard.toml`
- **Source / full docs:** [github.com/lucheeseng827/eggrd](https://github.com/lucheeseng827/eggrd) · Apache-2.0

## Where it fits

EdgeGuard is the **secure front door**: one hop that sits **between your clients and
the app**, so traffic reaches the app only after it clears auth, rate limiting, and
validation. Your app stops listening on the public port — EdgeGuard does — and is
forwarded to *unchanged*. One hop, to one upstream or a pool of them (balanced, health-checked,
failing over), over plain HTTP, TLS or mutual TLS; it is not a CDN, an API gateway, or an
identity provider.

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
  platform LB that forwards to it (the client's address comes from a PROXY protocol
  header or the balancer's `X-Forwarded-For` entry); EdgeGuard terminates TLS, verifies
  client certificates if asked, authenticates, rate-limits, and screens (WAF / edge DLP)
  before anything is forwarded.
- **EdgeGuard** — the request path (auth, limit, validation) in, the response path
  (CSP/HSTS, cookie hardening, leaky-header stripping) out — one static binary, no
  required external services.
- **Downstream** — a wrapped child on `APP_PORT`, an external `UPSTREAM` URL, or a pool
  of targets per path: your own app, a streaming LLM backend, or a static frontend +
  `/api` backend split via `[[upstreams]]`. `https://` upstreams are verified, with
  mutual TLS if needed. The app is forwarded to unchanged — zero code changes.
- **Side channels (optional)** — Redis for one global rate-limit across replicas, a
  control plane (managed mode) for policy pull + usage/quota, and Prometheus scraping
  `/__edgeguard/metrics`.

## Tags

| Tag | Notes |
|---|---|
| `latest` | newest release (= `0.7.2`) |
| `0.7` | newest `0.7.x` release (= `0.7.2`) |
| `0.7.2` | Security release: the CSP report sink limits each client (120 a minute, `429` past it), drops bodies that are not CSP reports, strips query strings from reported URLs, and in managed mode forwards identical reports folded into one request every 10 s instead of one request each; two new metrics for what it dropped and sent |
| `0.7.1` | Security release: credentials in a configured upstream, pool, Redis or collector URL no longer reach the logs, `doctor` or the status pages; the WAF Host allow-list rule now sees the host of every request (cleartext HTTP/2, absolute-form, no `Host`), and a request with no host or two that disagree gets `400`; WebSocket handshakes go through the WAF; `server.trusted_forwarders`; unknown config keys reported (**see the upgrade note**) |
| `0.7.0` | Mutual TLS on every hop (client certificates with CRLs, TLS and mTLS to upstreams, a control plane on a private CA); upstream pools with failover, weighted round robin, least connections, hashing, sticky sessions and active health checks; PROXY protocol; connection hardening (header-read timeout, connection cap, graceful drain); API-usage monitoring by route, consumer and upstream; `[outbound]` defaults for an egress proxy and private CA; security fixes for repeated credential headers and `X-Forwarded-For` (**see the upgrade note**) |
| `0.7.0-rc.1` | prerelease of 0.7.0, superseded by it |
| `0.5.0` | Certificates rotate on their own: ACME and self-signed renewal, and a running proxy hot-swaps a new certificate with no restart; `GET /__edgeguard/tls` and cert-expiry metrics; managed-mode edges report the certificate they serve (**see the upgrade note**) |
| `0.4.0` | Self-signed TLS + `:80`→HTTPS redirect + `edgeguard cert`; access-log query redaction, **now on by default** (**see the upgrade note**); `aws-lc-sys` dropped — image ~9 MiB smaller |
| `0.3.1` | `--version` added; unknown arguments now rejected instead of silently ignored |
| `0.3.0` | ACME issuance fixed (0.7.2 could not read Let's Encrypt's current authorization payload); `linux/arm64` restored |
| `0.2.2` | doc-comment changes only — **`amd64` only**, arm64 was not published for this tag |
| `0.2.1` | cookie-hardening opt-out (`httponly_cookie_exempt`) for JS-readable / double-submit CSRF cookies |
| `0.2.0` | per-path upstreams, request IDs, gzip, WebSocket passthrough, IP access lists |

There is no `0.6.0` image (its hardening shipped in 0.7.0) and no `0.7.0-rc.2` image.

Pin a version in production: `mancube/eggrd:0.7.2`.

> **Upgrading from 0.7.1 to 0.7.2.** No config change. A client that floods `/__edgeguard/csp-report` now gets `429`; browsers stay far below the limit. Crate users: the library API changed (see the changelog); the image is not affected.

> **Upgrading from 0.7.0 to 0.7.1: check these before rolling out.**
>
> - An HTTP/1.1 or HTTP/2 request with no host or an empty `Host`, and any request with two `Host`
>   headers, a `Host` that is not ASCII text, or an HTTP/2 `:authority` (or absolute-form target)
>   that differs from `Host`, now gets `400` (outcome `bad_request`). HTTP/1.0 may still omit
>   `Host`. An HTTP/2 intermediary that rewrites one but not the other is refused
>   on every request.
> - With the Host allow-list rule, an HTTP/1.0 request without `Host` on a proxied path gets
>   `403`; point such health checks at `/__edgeguard/health`.
> - With `websocket_passthrough` and the WAF in `block` mode, upgrade handshakes are screened by
>   every enabled rule. Run in `report` mode first.
> - `doctor` fails on a config key the parser ignores.

> **Upgrading to 0.7.0: check these before rolling out.** Every new feature is off by default and
> a 0.5 configuration loads as before, except:
>
> - **`trust_forwarded_for` now takes the `X-Forwarded-For` entry `server.forwarded_hops` from
>   the right**, not the first (which any client could write). Set `forwarded_hops` from what the
>   proxies in front append: **`2` behind a GCP external Application Load Balancer** (it appends
>   two entries) **or CloudFront → ALB** (and lock the ALB to CloudFront); `1`, the default, behind
>   an AWS ALB in its default `append` mode, Cloudflare, Azure Application Gateway, nginx or
>   Traefik. Too low makes every client the balancer: one rate-limit bucket for everyone. Anything
>   else, check what reaches EdgeGuard first.
> - **A client that sends its credential header twice now gets `401`** (`Authorization` for
>   `basic`/`jwt`, the key header for `apikey`).
> - **Connecting to an upstream times out after 5 s with `502`**, where it waited out the 30 s
>   upstream timeout; `validation.upstream_connect_timeout = "0"` restores it.
> - **Keep-alive connections idle for 30 s are closed** (`server.header_read_timeout`).
> - **The app no longer receives the client's `X-Real-IP`, `True-Client-IP`, `Forwarded` or
>   `X-Forwarded-Host`:** `X-Real-IP` and `Forwarded` carry the resolved client, `X-Forwarded-Host`
>   the `Host` EdgeGuard received, and `True-Client-IP` is removed. A repeated header now reaches
>   the app with every value, in order.
> - **ACME requests time out** (10 s connect, 30 s per request), and a bad ACME client setting now
>   fails at startup rather than at the next renewal.
>
> **Upgrading to 0.5.0 turns certificate rotation on.** `[tls] watch`, `[tls.acme] renew` and
> `self_signed_renew` all default to on, so a running proxy now reloads a certificate replaced on
> disk (cert-manager, Vault Agent, certbot) and renews its own ACME or self-signed certificate at
> two-thirds of its lifetime — no restart. A self-signed renewal reuses the existing key unless
> `self_signed_rotate_key = true`, and a CA-issued certificate at `cert_path` is never overwritten.
> With `redirect_port = 80` the redirect listener now answers the renewal's HTTP-01 challenge. In
> managed mode an idle edge now sends its usage report every interval (as a heartbeat) instead of
> skipping it.
>
> **Upgrading to 0.4.0 changes what lands in your access logs.** `[log] query` now defaults to
> `redact`: query-string values that look like a credential (by name — `token`, `key`, `secret`,
> `password`, `auth`, `code`, `state`, `email`, …, plus `[log] redact_params`; or by shape — a
> JWT, a long high-entropy token) are written as `<redacted>`. This is the log only — the
> upstream, WAF, rate limiting and DLP all still see the full request byte-for-byte. If a
> dashboard or SIEM rule depends on the full query string being logged, set
> `[log] query = "full"` to keep the previous behaviour.
>
> **Upgrading to 0.3.1 changes how bad command lines are treated.** Arguments the proxy does
> not recognise are now an error at startup instead of being silently discarded. If a container
> currently passes a flag that was being ignored — including a typo like `--confg` — it will now
> fail to start rather than run with settings it was never given. Check your `command:` /
> `args:` before rolling this out broadly.
>
> **If you are on `0.2.x` and use `[tls] acme = true`, upgrade.** ACME issuance was
> broken in those images — the proxy started and then never obtained a certificate,
> failing with ``missing field `token` ``. Fixed in 0.3.0 and verified against
> Let's Encrypt staging.
>
> **If you are on `arm64`, avoid `0.2.2`** — that tag was published `amd64` only.
> `0.3.0` builds both architectures natively again.

## Quick start

**Front-proxy mode** — put EdgeGuard in front of an existing upstream (the natural mode for this image):

```bash
docker run -p 8080:8080 \
  -e UPSTREAM=http://app.internal:3000 \
  mancube/eggrd:0.7.2 --config /etc/edgeguard/edgeguard.toml
```

Bring your own config (overrides the baked-in default):

```bash
docker run -p 8080:8080 \
  -e UPSTREAM=http://app.internal:3000 \
  -v "$PWD/edgeguard.toml:/etc/edgeguard/edgeguard.toml:ro" \
  mancube/eggrd:0.7.2 --config /etc/edgeguard/edgeguard.toml
```

> ⚠️ The shipped config's `users` value is a **non-working placeholder** — set a real credential before exposing anything (see [Auth](#auth--secrets)).

**Co-process mode** (EdgeGuard supervises your app as PID 1) needs your app in the same image. Copy the binary into your app's image instead of running this one directly:

```dockerfile
COPY --from=mancube/eggrd:0.7.2 /usr/local/bin/edgeguard /usr/local/bin/edgeguard
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

- **Reverse proxy** to an upstream (wrapped child process or external URL), over plain HTTP, verified TLS, or **mutual TLS** (`[upstream_tls]`).
- **Per-path upstreams and pools** (`[[upstreams]]`, single upstream by default): route `/api` to a backend and everything else to a static frontend (longest-prefix wins), and give a path a pool of `targets` — priority, weighted round robin, least connections, consistent hashing or sticky cookies, a `backup` tier, active HTTP/TCP health checks, and failover when a target cannot be reached.
- **Client certificates (mTLS)** (`[tls.client_auth]`, `auth.mode = "mtls"`): verify clients against your CA with CRLs, or read the certificate a TLS-terminating load balancer forwards.
- **Behind a load balancer**: PROXY protocol v1/v2 from trusted addresses, or `X-Forwarded-For` with `forwarded_hops`; `[outbound]` sets one egress proxy and private CA for every call the edge makes (control plane, log/OTLP shipping, JWKS, ACME).
- **Connection hardening**: a header-read timeout against slowloris clients, a connection cap, and a graceful drain on `SIGTERM`.
- **Streaming / passthrough**: SSE (`text/event-stream`) forwarded unbuffered, frame-by-frame (fronts streaming LLM backends without collapsing time-to-first-byte); optional WebSocket / `Upgrade` tunneling.
- **Request IDs** (`X-Request-Id`): reuse a well-formed inbound id or mint a UUID v4, forward it upstream, echo it on every response, tag the access log — one id correlates client, proxy, and app.
- **IP access control** (`[access]`, allow-all by default): coarse CIDR allow/deny lists evaluated by client IP before auth and rate limiting.
- **Response compression** (`validation.compress_responses`, off by default): gzip for clients that ask, skipping already-compressed types and SSE.
- **Auth** (`auth.mode`): HTTP Basic (`$argon2` PHC hashes), static API key / bearer (constant-time), or JWT (HS/RS/ES/PS/EdDSA, static key or cached JWKS; configured `alg` pinned).
- **Rate limiting** (GCRA → `429`): per-IP, optional per-route overrides, optional per-key; in-process `governor` or shared **Redis** store for multi-replica global limits.
- **WAF-lite** (off by default): SQLi / XSS / path-traversal heuristics + custom deny patterns, with a report-only rollout mode.
- **Response hardening**: CSP (+ report-only + report sink), HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`; adds `Secure; HttpOnly; SameSite` to cookies — with a per-cookie `httponly_cookie_exempt` opt-out so a JS-readable double-submit CSRF cookie stays readable; strips `Server` / `X-Powered-By`.
- **TLS** via rustls, optional **ACME / Let's Encrypt** (HTTP-01), with **automatic certificate rotation**: ACME and self-signed certificates renew at two-thirds of their lifetime, and a certificate replaced on disk is hot-swapped without a restart (`[tls] watch`).
- **Limits**: body-size (`413`), header-size (`431`), method allowlist (`405`).
- **Config hot-reload**, **structured JSON access logs** (who called, which route and upstream, how long, how many bytes), **Prometheus metrics** per route, consumer and upstream, with a Grafana dashboard and alert rules in the monitoring bundle.

## Ops endpoints

The reserved `/__edgeguard/*` namespace is never forwarded upstream:

| Endpoint | Purpose |
|---|---|
| `/__edgeguard/health` | liveness (always `200`) |
| `/__edgeguard/ready` | readiness — `200` only when upstream accepts a connection (or, for a pool at `/`, while a target is in rotation), else `503`; `503` while draining |
| `/__edgeguard/metrics` | Prometheus metrics |
| `/__edgeguard/csp-report` | CSP violation report sink |
| `/__edgeguard/tls` | served certificate: source, serial, validity, days left, last renewal attempt; client certificates presented, client-auth CAs and CRLs |
| `/__edgeguard/upstreams` | each route's targets, which are in rotation, and why one is out |

Use `ADMIN_PORT` to move these onto a private listener and keep them off the public port.

## Auth / secrets

Hash a password with the built-in helper (distroless has no shell — pass `--hash` as an arg, feed the password on stdin):

```bash
echo -n 'your-password' | docker run -i --rm mancube/eggrd:0.7.2 --hash
# paste the $argon2id$... string as the user's value in edgeguard.toml
```

A plaintext `users` value is **dev-only** (compared in constant time, never stored hashed). Always use an `$argon2` hash for anything reachable.

## License

Apache-2.0. Codename "EdgeGuard" is a working title.
