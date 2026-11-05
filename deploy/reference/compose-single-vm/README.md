# Reference: one VM, Docker Compose

eggrd 0.7.0 terminating TLS on a single VM, in front of one app, with every hardening setting on.
`./smoke.sh` brings it up, checks each claim below, and takes it down again.

## When to use it

- One server (a cloud VM, a bare-metal box) with a public IP and a DNS name, and no load balancer.
- An app that already runs in a container, or can.
- You want TLS, a WAF, rate limits and security headers in front of it without touching its code.

Not for several replicas (the `local` rate limiter counts per process; see `../kubernetes/` and
`store = "redis"`), and not behind a load balancer (see `../aws-nlb/` and `../aws-alb/` for how the
client's address changes there).

## Architecture

```
              :443 (TLS)  ┌──────────────────────────┐  backend network (internal)
 internet ───────────────►│ edge  eggrd 0.7.0        │──────────────► app :8000
              :80 → 308   │ read-only, uid 65532     │
                          │ admin :9090 ─► host 127.0.0.1:9090 only
                          └─────────▲────────────────┘
                                    │ GET /__edgeguard/ready every 10 s
                          edge-health (busybox): the healthcheck, and chmod 600 on ACME files
```

| File | What it is |
|---|---|
| `compose.yaml` | The edge, a one-shot `edge-init` that gives the state volume to uid 65532, the `edge-health` sidecar, and a sample app (`traefik/whoami`, which echoes the request it got). |
| `config/edgeguard.toml` | Local variant: a self-signed certificate for `app.example.test`. |
| `config-acme/edgeguard.toml` | Production variant: Let's Encrypt via ACME HTTP-01 for `app.example.com`. Same policy. |
| `compose.logging.yaml` | Optional override: ship the edge's logs with the engine's logging driver. |
| `smoke.sh` | The test. |
| `../tools/host-rule.sh` | Writes the Host allow-list rule for your name. |

## Deploy it

1. Point DNS for your name at the VM. Open 80 and 443 to the world, and nothing else (SSH through
   your provider's session manager or a bastion; never 9090).
2. Copy this directory to the VM. In `config-acme/edgeguard.toml` replace `app.example.com` (in
   `redirect_hosts` and `[tls.acme] domains`) and `ops@example.com`, then regenerate the Host
   rule: `../tools/host-rule.sh your.host.name` and paste its output over the existing
   `[[waf.rules]]` entry.
3. Replace the `app` service with yours, keeping it on the `backend` network only and its
   hardening (read-only, `cap_drop: ALL`, a non-root user, limits). Point `server.upstream` at it.
4. Check the config with the image you will run:
   ```bash
   docker run --rm -v "$PWD/config-acme:/cfg:ro" \
     docker.io/mancube/eggrd:0.7.0@sha256:b19278b379a457e626954e148effffa2fe559613d55ff497fdaa862c8c4096f6 \
     doctor --config /cfg/edgeguard.toml          # 0 error(s)
   ```
5. `EDGE_CONFIG_DIR=./config-acme docker compose up -d`. The first start orders the certificate
   (on `:80`), then starts serving. Try the staging directory first if you are unsure DNS is right:
   remove the `directory_url` line (staging is the default), and delete the state volume's
   `cert.pem`/`key.pem` before switching to production.
6. Run the checks under **Verify** against your real name.

## Hardening checklist

Every item is in `compose.yaml` or the config, and `smoke.sh` asserts the ones marked ✔.

| | Setting | Why |
|---|---|---|
| ✔ | Image pinned by digest (`mancube/eggrd:0.7.0@sha256:b19278b3…96f6`) | A tag can move; the digest is what was tested. The 0.7.0 index covers amd64 and arm64. |
| ✔ | `read_only: true`, `tmpfs: /tmp` | Nothing in the image is writable; state lives on one named volume. |
| ✔ | `cap_drop: [ALL]`, `cap_add: [NET_BIND_SERVICE]` | A non-root process may bind 443 and 80, and do nothing else privileged. |
| ✔ | `security_opt: no-new-privileges` | No setuid escalation, ever. |
| ✔ | `user: "65532:65532"` | The distroless `nonroot` user. `edge-init` hands it the state volume. |
| ✔ | `mem_limit: 192m`, `cpus: 0.5`, `pids_limit: 256` | A flood or a leak takes the edge down, not the VM. Raise for heavy traffic. |
|   | `restart: unless-stopped` | Comes back after a crash or a reboot. One supervisor: do not also wrap it in a systemd unit that restarts it. |
| ✔ | Admin listener published on `127.0.0.1:9090` only | Health, metrics, upstream and TLS status have no auth. The public port answers `404` for `/__edgeguard/*`. |
| ✔ | `:80` answers `308` to `https://`, for `redirect_hosts` only | Plaintext visitors are upgraded; a forged `Host` gets `400`, never a redirect that looks like yours. |
| ✔ | Host allow-list rule (`[[waf.rules]] host-allowlist`) | A raw-IP or forged `Host` gets `403`. Scanners hitting the IP never reach the app. 0.8 replaces it with `allowed_hosts`. |
| ✔ | WAF `block`, `inspect_headers = true` | SQLi, XSS, traversal refused at the edge. See the rollout note below. |
| ✔ | `allow_methods` = the seven standard methods | `PROPFIND`, `TRACE` and other WebDAV/debug methods get `405`. |
| ✔ | Rate limits: 120/min per IP, 5/min on `/login` | Credential stuffing is slowed where it pays. |
| ✔ | CSP, HSTS, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Server` stripped | Browser-side hardening without an app change. |
| ✔ | `header_read_timeout = "30s"`, `max_connections = 1024` | A slowloris or a connection flood cannot hold sockets forever. |
| ✔ | `drain_delay` + `drain_timeout` under `stop_grace_period` | A restart finishes in-flight requests instead of cutting them. |
|   | `trust_forwarded_for = false` | Nothing is in front: the TCP peer is the client. Turning it on here would let any client pick its address. |
|   | ACME files `0600` (`edge-health` chmods every 5 min) | 0.7 writes the ACME account and key `0644`; 0.8 writes them `0600`. |
| ✔ | The app has no published port and sits on an `internal` network | Only the edge reaches it, and it reaches nothing. |

**Roll the WAF out report → review → block.** The configs ship in `block` because that is where
you end up. On an app that already has users, start with `mode = "report"`, read the
`WAF rule matched (report-only)` lines for a few days (`docker compose logs edge | grep WAF`), fix
or exempt anything legitimate (a JSON body with SQL keywords, a cookie that looks like XSS), then
switch to `block`. Keep `inspect_body = false` until a report-mode run over real traffic says it is
safe. The Host rule needs `inspect_headers = true` and block mode to do anything.

**CSP** the same way: `csp_report_only = true` with `csp_report_uri = "/__edgeguard/csp-report"`,
read the reports in the access log, then enforce.

**`auth.mode = "none"`** draws a `doctor` warning. It is deliberate here: the app authenticates its
own users. Set `apikey`, `basic` or `jwt` if the edge should.

## The healthcheck, without a shell

The image is distroless: no shell, no `wget`, so a Compose `healthcheck` on the edge has nothing to
run. Three answers, from cheapest:

1. **The `edge-health` sidecar** (in `compose.yaml`): a 16 MB busybox that asks
   `http://edge:9090/__edgeguard/ready` every 10 s. `docker compose ps` shows its health, and other
   services can `depends_on` it with `condition: service_healthy`. It is on the `backend` network
   because the admin port is not published beyond the host's loopback.
2. **A host watchdog** for hangs. Docker restarts a container that exits, never one that is merely
   unhealthy (outside Swarm). If you want that too, a systemd timer on the VM:
   ```ini
   # /etc/systemd/system/eggrd-watchdog.service  (with an eggrd-watchdog.timer, OnUnitActiveSec=30s)
   [Service]
   Type=oneshot
   ExecStart=/bin/sh -c 'curl -fsS -m 5 http://127.0.0.1:9090/__edgeguard/health >/dev/null || docker restart eggrd-ref-edge-1'
   ```
   Use `/health` (the process answers) for restarts, not `/ready` (`503` while the upstream is down,
   which a restart of the edge does not fix).
3. **An external check** from your uptime monitor on `https://your.host/` (a real request through
   the edge), which is the one that tells you users can reach it.

## Hot reload, and what it needs

The config is mounted as a **directory** (`./config:/etc/edgeguard:ro`). eggrd watches the
directory for a change to `edgeguard.toml`; a single-file bind mount
(`./edgeguard.toml:/etc/edgeguard/edgeguard.toml`) never delivers that event, so edits there do
nothing until a restart, and an editor that replaces the file leaves the container reading the old
one. Edit the file on the VM and policy sections apply within a second: `[waf]`, `[ratelimit]`,
`[headers]`, `[validation]` (but `upstream_connect_timeout`), `[auth]`, `[access]`, `[cors]`,
`[[upstreams]]`. Listener settings (`[server]` ports and timeouts, `[tls]`, `[log]`) need
`docker compose restart edge`. A broken edit is refused (`config reload failed` in the log) and the
previous policy keeps serving.

A config folder on a Windows or macOS host, bind-mounted into Docker Desktop's or Podman's VM,
delivers no change events either. On those machines edit the file and restart; `smoke.sh` keeps its
copy on the engine's own filesystem for that reason.

## Log shipping (optional)

- **Logging driver** (no agent on the VM): `docker compose -f compose.yaml -f compose.logging.yaml
  up -d` sends stdout, the JSON access records included, to CloudWatch Logs; the file has journald
  and Fluentd alternatives. The JSON-file default keeps 5 × 20 MB on the VM.
- **`[log.ship]`** in the config: eggrd POSTs schema-2 NDJSON records to a collector you run
  (Vector, Fluent Bit's HTTP input, an OTLP collector's HTTP receiver). It survives a logging driver
  change and carries `principal`, `route`, `upstream` and byte counts as fields:
  ```toml
  [log.ship]
  enabled = true
  url = "https://logs.example.com/eggrd"
  headers = [["Authorization", "Bearer <collector token>"]]   # the file then holds a secret: 0600
  ```
  `principal = "hash"` (set here) writes callers pseudonymously.

## Verify

`./smoke.sh` (Docker or Podman; it moves the ports to 28443/28080/29090 on 127.0.0.1 and needs no
privilege) runs `doctor` on both configs and then checks:

| Check | Expect |
|---|---|
| `GET https://app.example.test/` | `200`, with HSTS, CSP, `X-Frame-Options`, no `Server` |
| `GET http://app.example.test/login?next=1` | `308`, `Location: https://app.example.test/login?next=1` |
| `Host: evil.example` on `:80` | `400` |
| `Host: evil.example` or a raw IP on `:443` | `403` (Host rule) |
| `?q=1 UNION SELECT password FROM users`, `/../../etc/passwd` | `403` (WAF) |
| `PROPFIND /`, `TRACE /` | `405` |
| 10 × `GET /login` | a `429` (5/min, burst 3), while `/` stays `200` |
| `127.0.0.1:9090/__edgeguard/ready` and `/health` | `200`; `/__edgeguard/metrics` on 443 is `404` |
| The app's view of `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `X-Forwarded-Host` sent by the client | replaced or removed; `Forwarded: for=<client>` set by the edge |
| `docker inspect` of the edge | uid 65532, read-only root, capabilities, `no-new-privileges`, limits, the digest |
| `edge-health` | `healthy` |
| Remove `DELETE` from `allow_methods` in the running config | `DELETE` turns `405` without a restart; `config reloaded` logged |
| `SIGTERM` | `/ready` `503` at once, `/health` and traffic still `200` during `drain_delay`, then `draining connections` |

On the real host, by hand:

```bash
curl -sI https://your.host/ | grep -i -e strict-transport -e content-security
curl -s -o /dev/null -w '%{http_code}\n' http://your.host/            # 308
curl -sk -o /dev/null -w '%{http_code}\n' "https://$(curl -s ifconfig.me)/"   # 403
curl -s http://127.0.0.1:9090/__edgeguard/tls                        # on the VM: certificate, renewal
stat -c '%a %n' /var/lib/docker/volumes/*edge-state/_data/acme/*      # 600
```
