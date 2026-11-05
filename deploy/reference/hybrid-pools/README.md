# Reference: hybrid pools (on-prem + cloud), mTLS to upstreams, an egress proxy, ACME through it

eggrd 0.7.0 in front of an app that runs on two on-prem servers with a cloud standby, in a network
whose only way out is an egress proxy. It shows the 0.7 pool features, mutual TLS to an upstream,
`[outbound]`, and a certificate ordered from an ACME CA through the proxy. `./smoke.sh` runs the
whole topology on one machine with stand-ins (nginx for the servers, squid for the proxy, Pebble
for the CA) and checks every claim below.

## When to use it

- An edge in a data centre or branch, in front of servers you run, with a cloud copy to fail over to.
- Traffic to the cloud copy must be encrypted and authenticated (mTLS), across a network you do
  not control.
- The edge must have no direct internet access: an egress proxy (often TLS-inspecting, on a
  corporate CA) is the only way out, for ACME, a JWKS, log and metric collectors. Here the
  topology enforces it: the edge is on an internal network only, and clients come in through a
  TCP ingress that passes their address in a PROXY protocol header.

## Architecture

```
                     ┌──────────────── site network (internal: no route out) ───────────────┐
 clients ─:443──► ingress (TCP, PROXY v2) ──► edge ──► "/"  round robin 2:1, sticky ─► onprem-a :8000 (weight 2)
                  │                                            ─► onprem-b :8000             │
                  │                     backup, mTLS ──────────► cloud.example.internal :8443 │
                  │      "/api/"      priority: a, then b, then the cloud tier               │
                  │      "/cache/"    hash on path        "/tenant/" hash on X-Tenant       │
                  │   health checks: GET :8081/health over http, Host: health.example.internal│
                  │   (the cloud's via check_host cloud-mgmt.example.internal)               │
                  └─ ACME, collectors, JWKS ──CONNECT──► egress :3128 ───► ACME CA (internet)  │
                     └──────────────────────────────────────────────────────────────────────┘
```

| File | What it is |
|---|---|
| `config/edgeguard.toml` | The edge: four pools, `[upstream_tls]`, `[outbound]`, `[tls.acme]` through the proxy. |
| `compose.yaml` | The edge (hardened as in `../compose-single-vm`) on the internal network only, the ingress, the stand-ins, three networks. |
| `ingress/haproxy.cfg` | The way in: TCP passthrough to the edge's 443/80/9090 with PROXY protocol v2. |
| `upstreams/*.conf.template` | nginx as the on-prem servers (app on :8000, health on :8081) and the cloud target (TLS on :8443 requiring a client certificate, health on :8081). |
| `egress/squid.conf` | The egress proxy: CONNECT only, to allow-listed ports. |
| `smoke.sh` | The test. Makes a throwaway PKI with `../tools/mkpki.sh`. |

## The pool settings, and what each is for

| Setting | Here | Why |
|---|---|---|
| `targets` with `weight` | `onprem-a` weight 2, `onprem-b` 1 | a has twice the capacity: 20 of 30 requests. |
| `balance` | `round_robin` (`/`), `priority` (`/api/`), `hash` (`/cache/`, `/tenant/`) | spread; strict primary/secondary; same key, same server. `least_conn` suits requests of very different cost. |
| `hash_on` | `path`, `header:x-tenant` | Rendezvous hashing: a server leaving moves only its own keys. Also `client_ip`, `cookie:<n>`, `query:<n>`. |
| `backup` | the cloud target | Only when no main target is in rotation, or all refused the request. |
| `sticky_cookie`, `_max_age`, `_strip` | `eg_upstream`, `8h`, `true` | In-memory sessions: a browser stays on its server across restarts; the app never sees the edge's cookie. A preference, not a security boundary. |
| `health_check.port` / `scheme` | `8081` / `http` | The servers' health lives on a management port over plain HTTP, even for the `https://` cloud target. |
| `check_host` (per target) | `cloud-mgmt.example.internal` | The cloud target's check goes to its management address; requests still go to `url`. |
| `health_check.method` / `headers` | `GET` / `Host: health.example.internal` | For a health endpoint that routes by name or wants a token. The status endpoint shows header *names* only. |
| `expect_status` / `expect_body` | `200` / `ok` | A `200` that says it is degraded fails. `expect_body_regex` for a pattern. |
| `type = "tcp"` | `/cache/` | For servers without a health endpoint. Cannot tell a hung app from a healthy one. |
| `eject_after` / `eject_for` | `1` / `10s` | A refused connection takes a target out at once, longer on repeats (up to `eject_for_max`). |
| `eject_after_5xx` | `3` | Up but broken: three `5xx` in a row. Each still reaches its client; never the last target in rotation. |
| `validation.upstream_connect_timeout` | `2s` | A partitioned site (packets dropped) fails over in 2 s, not at `upstream_timeout`. 0.7's default is 5 s. |

## Client addresses through the ingress

The ingress names each client in a PROXY v2 header, and the edge's rate limits, `[access]` rules
and access log use that address. It is the client's real address only if nothing between the
client and the ingress replaced it:

- **Rootful Docker with `userland-proxy` disabled, or Podman rootful:** published ports keep the
  source address (iptables/nftables DNAT). This is the setup to deploy.
- **Docker's default userland proxy, and rootless Docker or Podman:** published-port forwarding
  connects to the ingress from the forwarder's own address, so every client shares one address
  (one rate-limit bucket, `[access]` rules that see the host). Disable `userland-proxy`, or on
  rootless Docker use RootlessKit v3.0 or later with the userland proxy off, the `slirp4netns`
  port driver, or `pasta` with the `implicit` port driver.
- **An L4 balancer in front instead of a published port** (the production shape): have it send
  the PROXY header itself, trust its addresses in `proxy_protocol_trusted`, and drop the ingress.

Check it once deployed: request the site from a known address and look for that address as
`client_ip` in the edge's access log. `smoke.sh` does this from a container on the public network
(published ports on a rootless test host would show the forwarder's address instead).

## mTLS to upstreams and the egress proxy

- `[upstream_tls]` trusts only the private CA (`ca_path`) for `https://` targets and presents the
  edge's client certificate (`cert_path`/`key_path`); `[[upstream_tls.targets]]` gives one target
  its own settings (`server_name` for a target dialled by IP). No option skips verification. A
  connection that presents a certificate never resumes a TLS session, so a rotated certificate
  takes effect on the next connection. eggrd warns as the certificate nears expiry; nothing here
  renews it.
- `[outbound]` sets the proxy, an extra CA (beside the public roots, never instead: there is no
  `[outbound] ca_path`) and the edge's client certificate once for every client the edge opens
  itself: ACME, `[log.ship]`, `[tracing]`, `[metrics.otlp]`, the JWKS fetch, `[alerts]`, a control
  plane. A section's own key wins; `proxy = "none"` sends one section direct (a collector on the
  same LAN). Upstreams never use it. `doctor` lists which section takes which key.
- **ACME through the proxy.** Every ACME request goes out as a `CONNECT` through the proxy, TLS end
  to end (0.5's ACME client ignored proxies, even `HTTPS_PROXY`). `[tls.acme] ca_path` trusts only
  the CA's root; for a public CA leave it out (the host's trust store plus `extra_ca_path`). A bad
  `ca_path`, proxy or directory now fails at startup rather than at the renewal two months later.
  Let's Encrypt's HTTP-01 check still has to reach the edge on `:80` from the internet; where it
  cannot, use DNS-01 (`[tls.acme] challenge = "dns-01"`, `[tls.acme.dns]` takes the proxy too).

## Hardening checklist

- [ ] Proxy-only egress enforced by the topology: the edge is attached to the internal `site`
      network alone, so it has no route out but the proxy. Clients reach it through the ingress,
      the only container on both `public` and `site`, which forwards only to the edge's ports
      and names each client in a PROXY v2 header (`proxy_protocol_trusted` is the ingress's
      address alone). Do not add the edge to a routed network to "make it reachable": that is the
      bypass. `./smoke.sh` checks the edge's networks and that `site` reaches nothing outside.
      The proxy admits only the ports it needs (`egress/squid.conf`), and logs every CONNECT.
      On a VM without Compose, the same rule is a host firewall that drops the edge's egress
      except to the proxy.
- [ ] `[upstream_tls] ca_path` set (only the private CA), client certificate presented, the target
      refuses clients without one (the smoke test checks the cloud target answers `400` to a
      client without a certificate).
- [ ] Health checks point at an endpoint that checks what the app depends on; `expect_body` when it
      reports degradation in a `200`.
- [ ] `eject_after_5xx` set, but not so low that one buggy endpoint ejects a working server.
- [ ] The ACME account file is `0600` (0.7 writes it `0644`; `smoke.sh` prints the modes). The
      key eggrd writes is `0600`.
- [ ] Container hardening as in `../compose-single-vm` (read-only, non-root, capabilities, limits,
      digest pin, admin on loopback).

## Verify

`./smoke.sh` (Docker or Podman):

| Check | Expect |
|---|---|
| `doctor` | 0 errors |
| The edge's first start | `starting ACME order`, `ACME certificate stored`; squid logged `CONNECT pebble:14000` |
| The certificate the edge serves | issued by the CA (`Pebble Intermediate CA`) |
| ACME file modes | `key.pem` 600, `acme/account.json` **644** (0.7; chmod it) |
| The edge's networks | the internal `site` network only |
| From `site`, without the proxy: the CA, a public address | unreachable (`000`); through the proxy the CA answers `200` |
| Clients through the ingress | `edgeguard_proxy_protocol_total{listener="public",result="proxied"}` rising |
| A client at 10.233.11.150 on the public network | the edge logs `"client_ip":"10.233.11.150"` |
| The edge recreated at a new address | the same ingress (not restarted) reaches it: runtime DNS |
| 30 requests to `/` without a cookie | onprem-a 20, onprem-b 10 |
| The sticky cookie | `Set-Cookie: eg_upstream=…; Max-Age=28800`; 6 requests with it reach one server; the app sees `theme=dark`, not `eg_upstream` |
| `/cache/a.png` ×5, eight paths | one server; both servers |
| `X-Tenant: acme` ×4 | one server |
| `GET :9090/__edgeguard/upstreams` | `check_host`, `scheme: http`, header names without values |
| 12 × `/boom` (500 on onprem-b) | onprem-b ejected (`edgeguard_upstream_ejections_total{reason="http_5xx"}`); the rest go to onprem-a |
| The cloud target, no client certificate | `400` |
| Both on-prem servers stopped | `/` and `/api/` answered by the cloud backup, which saw `CN=edge`; pool `state: backup`; `/ready` `200` |
| On-prem servers started again | `/api/` back on onprem-a after `healthy_after` checks |
