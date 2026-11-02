# Deployment & integration strategy

**Decision:** ship the non-k8s deploy story first, k8s sidecar later. The target user is
the vibe-coder without devops, and that user isn't on Kubernetes — they're on a PaaS or a
small VPS. K8s is a v3 concern for the teams/agencies tier.

## Where these users actually deploy (2026)

Deployment in 2026 is effectively a three-box decision: frontend on an edge/CDN host,
backend on a container PaaS, and state on a managed DB. That split dictates where an edge
proxy can even run:

| Category | Typical targets | Can a front proxy run here? | EdgeGuard fit |
| --- | --- | --- | --- |
| Full-stack container PaaS | Railway, Render, Fly.io, Northflank, DO App Platform | Yes — long-running container/process | ✅ Primary v0 target |
| Self-host / VPS | DigitalOcean droplet, Hetzner, Coolify | Yes — native binary or compose | ✅ v0 target |
| All-in-one vibe platforms | Lovable Cloud, Replit, Hostinger Horizons | Sometimes (only if custom Dockerfile/container allowed) | ⚠️ Conditional |
| Static / edge hosts | Vercel, Netlify, Cloudflare Pages | No — serverless/edge, no persistent front process | ❌ Different surface (see below) |

Full-stack PaaS (Railway/Render/Fly/Northflank) is where AI apps with a real backend live
and where a proxy can actually sit in front. Static/edge hosts (Vercel/Netlify/CF Pages)
are great for frontend-only apps but won't run a long-lived proxy process — so they need a
different delivery model, not the binary.

## Core interface patterns

The invariant in every non-k8s mode: **the app binds to an internal port; EdgeGuard
becomes the public listener and forwards to it.** Four ways to wire that:

1. **Co-process entrypoint (default, simplest).** EdgeGuard is the container `ENTRYPOINT`,
   binds the platform-injected `$PORT`, spawns the user's app on `127.0.0.1:<internal>`,
   and proxies to it. One deployable unit, one service to pay for — ideal for a non-devops
   user. Ship a ready Dockerfile template that wraps a Node/Python app
   (see [`../examples/`](../examples)).
2. **Separate public/private service (cleaner separation).** EdgeGuard runs as the public
   service; the app runs as a private/internal service reachable over the platform's
   private network. Two services, better isolation — the path teams graduate to.
3. **Native binary on a VPS.** A systemd unit (or `docker compose` with EdgeGuard as the
   front container); the app listens on localhost. Full feature set, fully owned.
4. **Edge-function build for static hosts (implemented — Phase 5).** For Vercel/Netlify/CF
   Pages, the response-hardening half (headers/CSP/cookies) plus lightweight edge auth ship as
   either *generated platform config* (`edgeguard generate` → a `_headers` file / `vercel.json` /
   edge-middleware snippet) or a **Rust→WASM Cloudflare Worker** (`../worker/`). This is a
   separate product surface, not the proxy binary. (Rate limiting stays proxy-only — it needs
   shared state.)

## Target rollout order

| Phase | Targets | Interface delivered |
| --- | --- | --- |
| v0 | Railway, Render, Fly.io • generic Docker/VPS | Co-process entrypoint + Dockerfile template; native binary + systemd example |
| v1 | Northflank, DO App Platform; separate public/private service mode | Two-service pattern, internal networking docs, one-click templates |
| v2 | Static/edge hosts (Vercel/Netlify/CF Pages) | Config generator + Rust→WASM Worker for the response-hardening + edge-auth subset |
| v3 | Kubernetes | Sidecar container + Helm chart / operator |

## Implications for the build

- **Config from env first.** Read `PORT` (public, platform-injected) and `APP_PORT` /
  `UPSTREAM` for the internal app, so EdgeGuard drops into any PaaS that injects `$PORT`
  with zero edits. The TOML file layers on top for richer policy. *(Implemented.)*
- **Process supervision.** In co-process mode EdgeGuard launches and supervises the child
  app process (restart on crash, forward signals, propagate exit) — a tiny init for the
  container. *(Implemented for Unix; Windows uses a best-effort child kill — see
  [ROADMAP.md](./ROADMAP.md).)*
- **Stack auto-detect (nice-to-have).** A `--wrap "<start command>"` flag plus detection of
  `package.json` / `requirements.txt` lets the template work for most apps without the user
  thinking about ports. *(`--wrap` implemented; auto-detect is future.)*
- **Distribution artifacts:** (1) a single static binary, (2) a base Docker image to
  `FROM`, (3) per-platform deploy templates (Railway/Render/Fly) so "add EdgeGuard" is
  copy-paste.

## Platform notes

- **Railway** — deploy the repo; set `APP_PORT=3000`. Railway injects `$PORT`; EdgeGuard
  binds it.
- **Render** — see [`../examples/render.yaml`](../examples/render.yaml); health check
  `/__edgeguard/health`.
- **Fly.io** — see [`../examples/fly.toml`](../examples/fly.toml).
- **VPS / Coolify** — run the binary under systemd, or `docker compose` with EdgeGuard as
  the front container.

> Health vs readiness: `/__edgeguard/health` is liveness (is EdgeGuard itself up);
> `/__edgeguard/ready` probes the upstream and reports ready only once it's reachable. Point
> a platform's *health* check at the former and its *readiness*/rolling-deploy gate at the
> latter.
>
> Static/edge hosts (Vercel, Netlify, Cloudflare Pages) can't run a long-lived proxy
> process; those are a separate surface — now implemented in Phase 5 as `edgeguard generate`
> (config generation) and the Rust→WASM Worker (`../worker/`), not this binary.

## TLS — three ways to get a certificate

EdgeGuard terminates TLS with `rustls` and serves **whatever certificate chain + key you give it**
— it doesn't validate who issued them, so a cert from a public CA, an internal/corporate CA, or a
self-signed cert all work the same way.

| | needs a public domain | needs inbound `:80` | publicly trusted | use for |
|---|---|---|---|---|
| `[tls] self_signed = true` | no | no | **no** | localhost, private network, staging |
| `[tls.acme]` | **yes** | **yes** | yes | a public site |
| your own PEM files (below) | no | no | depends on issuer | corporate/internal CA |

### Option A — let EdgeGuard generate one (`self_signed`)

Nothing to prepare: set `self_signed = true` and it writes a certificate to `cert_path`/`key_path`
on first boot (key mode `0600`), then serves it. Generation is skipped once the files exist.

```toml
[server]
port = 8443

[tls]
enabled     = true
cert_path   = "/etc/edgeguard/tls/cert.pem"
key_path    = "/etc/edgeguard/tls/key.pem"
self_signed = true
self_signed_hosts = ["app.internal", "10.0.0.5"]   # empty = localhost/127.0.0.1/::1
```

To make the files ahead of time (a Docker build stage, a compose init container, a config-management
run), use the standalone subcommand — it needs no config file and starts no listener:

```bash
edgeguard cert --host app.internal --days 90 --cert-out ./tls/cert.pem --key-out ./tls/key.pem
```

Mount a writable volume at the certificate directory if you rely on first-boot generation; a
read-only mount means the proxy cannot write what it is about to serve. This is the option to reach
for when TLS is *within* your perimeter — a sidecar hop, a service mesh leg, a staging box behind a
VPN — where you control the clients and can trust the certificate explicitly
(`curl --cacert cert.pem …`). It is **not** the option for a public site: browsers will show an
interstitial. Use ACME there.

### Option B — bring your own certificate

1. **Prepare two PEM files.**
   - **Certificate chain** (`fullchain.pem`) — **leaf first**, then any intermediates. The
     **root CA does not go in this file** — it lives in the *client's* trust store.
   - **Private key** (`key.pem`) — PKCS#8, PKCS#1, or SEC1.

2. **Point the config at them** and listen on 443:
   ```toml
   [server]
   port = 443

   [tls]
   enabled   = true
   cert_path = "/etc/edgeguard/tls/fullchain.pem"
   key_path  = "/etc/edgeguard/tls/key.pem"
   ```

3. **Mount the files** (keep keys out of the image):
   ```bash
   docker run -p 443:443 \
     -v "$PWD/tls:/etc/edgeguard/tls:ro" \
     -v "$PWD/edgeguard.toml:/etc/edgeguard/edgeguard.toml:ro" \
     mancube/eggrd:latest --config /etc/edgeguard/edgeguard.toml
   ```
   On Kubernetes, mount a `Secret` at that path and map the secret keys to `fullchain.pem` and
   `key.pem` (or create the Secret with those exact filenames). A default `kubernetes.io/tls`
   Secret exposes `tls.crt` / `tls.key`, so use `items` in the volume definition to remap them,
   or use `kubectl create secret generic` with the expected key names instead.

4. **Make clients trust the issuer.** For a public CA this is automatic. For an **internal/own CA**,
   distribute your CA root to the clients' trust stores (OS/browser, or `curl --cacert ca.pem …`) —
   EdgeGuard sends the chain, the client validates it against the root it trusts. For a
   **self-signed leaf**, clients must trust that cert directly (e.g. `curl --cacert cert.pem …`)
   — there is no CA root to validate against.

**Notes & limits.**
- A file-provided certificate is reloaded when its files change (and checked hourly), so
  replacing it needs no restart.
- Client certificates (mutual TLS) are verified with `[tls.client_auth]`, or read from a load
  balancer's header; see [Client certificates](#client-certificates--where-they-can-be-verified).
- Prefer **automatic certificates** instead? Set `[tls.acme]` (Let's Encrypt, HTTP-01) — it obtains
  and renews the cert for you (staging directory by default).

## The client's address behind a load balancer

Rate limits, `[access]` rules, the access log and `X-Forwarded-For` to the app all key on the
client's address. Behind a balancer, the connection comes from the balancer, so what sits in front
decides where the client's real address is:

| In front of EdgeGuard | Where the client's address is | Configure |
|---|---|---|
| Nothing | The connection's own peer | Nothing |
| An L7 balancer (AWS ALB, a GCP HTTPS LB, nginx `http`, Envoy, Cloudflare) | `X-Forwarded-For` | `server.trust_forwarded_for = true` |
| An L4 balancer that keeps the client's address (an NLB with client IP preservation, a passthrough GCP network LB, `externalTrafficPolicy: Local`) | The connection's own peer | Nothing |
| An L4 balancer that does not (an NLB with IP targets, HAProxy `mode tcp`, nginx `stream`, a GCP TCP proxy) | A PROXY protocol header at the start of the connection | `server.proxy_protocol = true` |

**Behind an L4 balancer** (`server.proxy_protocol`). The balancer writes one line (v1) or a binary
block (v2) naming the client before anything else on the connection, and before the TLS handshake
on a TLS listener. EdgeGuard reads either, but believes it only from the balancer's own addresses:

```toml
[server]
proxy_protocol = true
proxy_protocol_trusted = ["10.0.0.0/20"]   # the balancer's subnets
```

| Balancer | Its setting |
|---|---|
| AWS NLB | Target group attribute `proxy_protocol_v2.enabled = true`. On EKS, the Service annotation `service.beta.kubernetes.io/aws-load-balancer-proxy-protocol: "*"`. Trust the NLB's subnets. |
| HAProxy | `send-proxy-v2` (or `send-proxy`) on the `server` line. Add `check-send-proxy` too, or its health checks arrive without a header and count as `missing`. |
| nginx `stream` | `proxy_protocol on;` in the `server` block. |
| GCP external proxy network LB (TCP proxy) | `--proxy-header=PROXY_V1` on the target TCP proxy. |

How each connection is treated:
- **From `proxy_protocol_trusted`, with a header:** the header's client is the connection's
  address for every request on it.
- **A header that names no client** (v2 `LOCAL`, v1 `UNKNOWN`): this is the balancer's own health
  check, so it is served as the balancer.
- **From `proxy_protocol_trusted`, without a header:** also served as the balancer, and counted as
  `missing`.
- **From any other peer, with a header:** closed (`untrusted`). Otherwise any client could choose
  its own address.
- **From any other peer, without a header:** served as itself (`direct`). Pods calling each other
  and probes keep working.
- **A header that does not parse, or nothing within `header_read_timeout`:** closed (`invalid`,
  `timeout`).

`edgeguard_proxy_protocol_total{listener,result}` counts each case.

**Notes.**
- A refused header closes the connection instead of serving it as the balancer. An `[access]`
  rule that allows the balancer's subnet would otherwise let every client through when the
  balancer's addresses change.
- An NLB with **client IP preservation** on still sends the header, but from the client's address,
  so every connection is refused. Turn preservation off, or leave `proxy_protocol` off, since the
  peer already is the client.
- Don't combine it with `trust_forwarded_for`: an L4 balancer passes the client's own
  `X-Forwarded-For` through (`doctor` warns).
- Applies to the public and redirect listeners. The admin listener never reads a header: probes and
  scrapes reach it directly.
- `[trusted_client_cert_header]` is still trusted by the connection's own peer, the hop that wrote
  it, not by the client a PROXY header names. Behind an L4 balancer that peer is the balancer,
  and the client writes the header, so leave the balancer out of `trusted_proxies` (`doctor`
  warns). An L7 balancer that also sends PROXY headers (HAProxy `mode http` with `send-proxy`)
  writes both itself, and belongs in both lists.
- Listener settings: read at startup, not on reload.

## Client certificates — where they can be verified

A client certificate exists only in the TLS handshake, so it can be checked only by whatever
terminates the client's TLS. What sits in front of EdgeGuard decides how:

| In front of EdgeGuard | Does the certificate reach EdgeGuard? | Configure |
|---|---|---|
| Nothing (EdgeGuard terminates TLS), or a TCP-passthrough L4 balancer (AWS NLB, a passthrough GCP network LB, HAProxy `mode tcp`) | Yes, in the handshake | `[tls.client_auth]` |
| An L7 balancer that does the client mTLS and forwards the certificate (ALB in verify mode, Envoy or Istio, nginx, HAProxy, Traefik) | In a header | `[trusted_client_cert_header]` |
| An L7 balancer that terminates TLS without client certificates | No | Not possible: authenticate with API keys or JWT, or move to passthrough |

**Behind an L7 balancer** (`[trusted_client_cert_header]`). The balancer verifies the certificate
and writes it into a header, and EdgeGuard believes that header only on connections from the
balancer's own addresses:

```toml
[trusted_client_cert_header]
name = "X-Amzn-Mtls-Clientcert"          # the balancer's header
format = "pem"                           # pem | der | xfcc
trusted_proxies = ["10.0.0.0/20"]        # the balancer's subnets: the TCP peer, not X-Forwarded-For

[auth]
mode = "mtls"                            # the forwarded certificate is the principal
```

| Balancer | Its setting | `name` | `format` |
|---|---|---|---|
| AWS ALB, mTLS verify mode | trust store on the listener | `X-Amzn-Mtls-Clientcert` | `pem` |
| AWS ALB, mTLS passthrough mode | (forwards without verifying) | `X-Amzn-Mtls-Clientcert` | `pem`, **and set `ca_path`** |
| nginx | `ssl_verify_client on;` `proxy_set_header X-Client-Cert $ssl_client_escaped_cert;` | `X-Client-Cert` | `pem` |
| HAProxy | `verify required` on the `bind`; `http-request set-header X-Client-Cert %[ssl_c_der,base64]` | `X-Client-Cert` | `der` |
| Envoy / Istio | `forward_client_cert_details: SANITIZE_SET`, `set_current_client_cert_details: { cert: true, uri: true }` | `X-Forwarded-Client-Cert` | `xfcc` |
| Traefik | `passTLSClientCert` middleware with `pem: true` | `X-Forwarded-Tls-Client-Cert` | `der` |

Any other balancer that writes the certificate as PEM or base64 DER works the same way.
- With `format = "xfcc"` and no `Cert` in the header (Istio's default), the names and hash it
  reports are used. `ca_path` then has nothing to verify and refuses the request.
- The header is removed before forwarding. Set `tls.client_auth.forward_client_cert = "xfcc"` to
  give the app the verified certificate as `X-Forwarded-Client-Cert`.

**Trust the hop, not just its address.**
- `trusted_proxies` must be addresses only *your* balancer uses. A shared edge network's ranges
  carry everyone's traffic, so anyone can send through them with any header.
- A certificate is public, so `ca_path` alone does not prove the client holds its key.
- Where the balancer's addresses are shared, trust it by its certificate instead: have it
  present a TLS client certificate to EdgeGuard, and name that certificate in
  `trusted_proxy_names`. The handshake then proves the hop, and the header names the client.
  From a trusted hop, the header's certificate is the client's, and the hop's own never is.

  ```toml
  [tls.client_auth]
  mode = "optional"                      # or "required" if nothing else connects directly
  ca_path = "/etc/eggrd/ingress-ca.pem"  # the CA that issued the balancer's client certificate

  [trusted_client_cert_header]
  name = "X-Forwarded-Client-Cert"
  format = "xfcc"
  trusted_proxy_names = ["spiffe://prod.example/ns/ingress/*"]
  ```

  Name a certificate issued to *you*: an Envoy or Istio ingress with its own SPIFFE ID, or a
  per-hostname origin certificate. A provider's default origin certificate, shared by all its
  customers, proves no more than its shared ranges do. Listing addresses too
  (`trusted_proxies`) makes both required.
- `edgeguard_client_cert_header_total{result="untrusted_peer"}` counts headers dropped from
  elsewhere. A rise means a forgery attempt, or balancer addresses that are no longer listed.

## Behind a corporate egress proxy or CA

An edge in a locked-down network often has no direct route out and sits on an internal PKI. Its
own clients (the control plane, log and span shipping, OTLP metrics, the JWKS fetch, alerts, the
ACME CA, the DNS provider's API) then need the egress proxy, the corporate CA and often a client
certificate.
`[outbound]` sets them once for all of those:

```toml
[outbound]
proxy = "http://egress.corp:3128"            # CONNECT proxy: TLS stays end to end
extra_ca_path = "/etc/eggrd/corp-ca.pem"     # trusted beside the public roots
client_cert_path = "/etc/eggrd/edge.pem"     # the edge's identity, for endpoints that ask
client_key_path = "/etc/eggrd/edge.key"

[log.ship]
enabled = true
url = "http://127.0.0.1:9000/edge"           # a local collector: the proxy cannot reach it
proxy = "none"
```

- Use `extra_ca_path` here, not a section's `ca_path`, for a CA that public endpoints are not
  signed by. It is added to the public roots, so a chat webhook or a SaaS identity provider still
  verifies. A TLS-inspecting proxy's CA belongs here too. A section's own `ca_path` replaces the
  public roots, for the one endpoint that should trust only a private CA.
- A section's own value wins over `[outbound]`, key by key. `proxy = "none"` sends a section
  direct. A proxy set here does not read `NO_PROXY`, so a local or LAN collector needs that.
- Run `edgeguard doctor`: it lists which sections take which `[outbound]` keys, and warns about a
  section on plain `http://` to another machine, where the CA and certificate do not apply.
- Proxied traffic to your upstreams is separate (`[upstream_tls]`).
- The ACME client takes `[outbound]` too, so certificates are issued and renewed through the
  proxy. It verifies the ACME CA against the host's trust store plus `extra_ca_path`, not the
  binary's built-in roots, so an internal ACME CA installed on the host keeps working.

## Failover between sites — an upstream pool

An edge in front of on-prem servers with a cloud standby, or the reverse, can spread load and
fail over without a load balancer in between:

```toml
[[upstreams]]
path = "/"
name = "app"
targets = ["http://10.0.1.5:8080", "http://10.0.1.6:8080"]
balance = "round_robin"                  # or "priority": the first takes everything
backup = ["https://app.dr.example.com"]  # only when neither on-prem server will
[upstreams.health_check]
path = "/healthz"

[[upstream_tls.targets]]                 # the standby's own TLS settings, by host and port
target = "https://app.dr.example.com"
ca_path = "/etc/eggrd/dr-ca.pem"
```

**Notes.**
- **Routing:** the on-prem servers take requests in turn; the standby takes none while either is
  in rotation. If one is bigger, give it a larger share:
  `targets = [{ url = "http://10.0.1.5:8080", weight = 2 }, "http://10.0.1.6:8080"]`. If request
  costs vary widely (reports beside reads, long-lived WebSockets), `balance = "least_conn"`
  sends each request to the server with the fewest in flight instead. A health check takes a dead server out within `unhealthy_after` × `interval`
  (10 s by default), and the other takes all its requests.
- **Sessions in memory:** if the app keeps sessions in process memory, add
  `sticky_cookie = "eg_upstream"`. Each browser then stays on the server that first answered it,
  while that server is in rotation. When a server leaves rotation, its users move and log in again.
  Shared sessions (a database, Redis) avoid that. `sticky_cookie_max_age = "8h"` keeps the
  pairing across browser restarts, and `sticky_cookie_strip = true` keeps the edge's cookie out of
  the app's request.
- **Before the check notices:** a request that cannot connect is sent to the next target, the
  standby last, and the dead one is ejected for `eject_for`.
- **Up but broken:** a server whose process answers but whose database is gone passes a
  shallow health check. `eject_after_5xx = 5` takes it out after five `5xx` answers in a row.
  Those five still reach their clients. Better still, have `/healthz` check what the app
  depends on. If it reports that in its body while answering `200`, set
  `health_check.expect_body = '"status":"ok"'` so the check reads it.
- **Losing the site:** with both on-prem servers out, every request goes to the standby until one
  passes its checks again.
- **Partitions:** `validation.upstream_connect_timeout` (5 s) is what makes a partition, where
  packets are dropped rather than refused, fail over in seconds rather than at `upstream_timeout`.
- **Failback:** a server takes traffic again after `healthy_after` passing checks. Expect a short
  split while a standby request finishes.
- **Health endpoint:** point `health_check.path` at an unauthenticated endpoint, or send what it
  needs with `health_check.headers` (a token; a `Host` for an app that routes by name). A `401`,
  or a `404` from a wrong path, takes every target out. Requests still go through then, since nothing
  in rotation means every target is tried, but readiness fails and `EdgeGuardUpstreamPoolDown`
  fires.
- **No retries after an answer:** a request is never retried once a target answered it, even
  with a `5xx`, nor when its body was streamed. Make long uploads idempotent, or keep
  `stream_requests` off on the pool's routes.

## Catch plaintext traffic — HTTP → HTTPS redirect

Terminating TLS protects only the traffic that *reaches* the TLS port. A visitor who types a bare
hostname, a `curl` in someone's runbook, an old bookmark, a webhook configured years ago — all try
`:80` first. With nothing listening there they get a connection error; with the app still bound
there they get plaintext. `tls.redirect_port` closes that gap with a second, tiny listener:

```toml
[server]
port = 443

[tls]
enabled         = true
redirect_port   = 80                     # 0 (default) = off; also settable via REDIRECT_PORT
redirect_status = 308                    # preserves method + body; 301 for the older convention
redirect_hosts  = ["app.example.com"]    # empty = reflect any syntactically valid Host
```

```bash
docker run -p 80:80 -p 443:443 \
  -v "$PWD/tls:/etc/edgeguard/tls" \
  -v "$PWD/edgeguard.toml:/etc/edgeguard/edgeguard.toml:ro" \
  mancube/eggrd:latest --config /etc/edgeguard/edgeguard.toml
```

**Notes & limits.**
- `308` is the default rather than `301` so a `POST` that lands on the plaintext port is replayed
  over TLS instead of being silently downgraded to a `GET`.
- Binding `:80` needs privilege or `CAP_NET_BIND_SERVICE`. On Kubernetes, prefer a Service that
  maps `:80` to a high port and set `redirect_port` to that instead of running as root.
- The `Host` header is attacker-controlled. A malformed host (spaces, CR/LF, userinfo, over-long)
  is always answered `400` rather than reflected into `Location`; set `redirect_hosts` to pin
  redirects to the names you serve, which is what stops a forged `Host` from producing a redirect
  that appears to come from your domain.
- `/.well-known/acme-challenge/` is answered `404`, never redirected — a CA must read the HTTP-01
  token in plaintext, and bouncing it to the port whose certificate is being issued would deadlock
  the order. With `[tls.acme]` on, issuance runs first and the redirect listener binds `:80`
  afterwards, so the two never contend for the port.
- Leave this off when a load balancer or platform edge already redirects; two hops are wasteful,
  not harmful.
