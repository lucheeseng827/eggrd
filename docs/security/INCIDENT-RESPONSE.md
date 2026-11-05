# Incident response with eggrd

A runbook for a suspected breach of an application behind eggrd, or of eggrd itself, in the
phases of NIST SP 800-61 (preparation; detection and analysis; containment, eradication and
recovery; post-incident activity), made concrete for eggrd **0.7.0**. Most containment levers below
were exercised against a running 0.7.0 edge, and their times are measured ones; the table says which
were not (revoking a client certificate, stopping the edge). The evidence scripts were run on Docker
(dind) and on k3s. What was run and what was written only is in
[README.md](README.md#what-was-tested).

- [0. Before the incident](#0-before-the-incident)
- [1. Detection signals](#1-detection-signals)
- [2. Triage: the first 15 minutes](#2-triage-the-first-15-minutes)
- [3. Preserve evidence first](#3-preserve-evidence-first)
- [4. Containment levers](#containment-levers)
- [5. Eradication and recovery](#5-eradication-and-recovery)
- [6. Post-incident](#6-post-incident)
- [7. Playbooks](#7-playbooks)

---

## 0. Before the incident

What this runbook assumes is already true. Without these, several steps below have nothing to
work with.

| Need | Why | Item |
|---|---|---|
| Logs off the host, kept a year, with integrity controls | Nothing to investigate otherwise | [EG-HARD-243](HARDENING-CHECKLIST.md#eg-hard-243--logs-leave-the-host-as-they-are-written-and-are-kept), [LOGGING-AND-EVIDENCE.md](LOGGING-AND-EVIDENCE.md#what-to-collect-and-for-how-long) |
| `RUST_LOG=info,edgeguard::serve=debug` | TLS and connection failures are DEBUG | [Events](LOGGING-AND-EVIDENCE.md#events) |
| The bundle's alerts routed to on-call | Most signals below are alerts | [EG-HARD-244](HARDENING-CHECKLIST.md#eg-hard-244--the-monitoring-bundles-alerts-are-deployed-and-routed) |
| A config directory mount, or a pod roll on every change | Whether a lever takes 0.2 s or a restart | [EG-HARD-242](HARDENING-CHECKLIST.md#eg-hard-242--config-changes-reach-the-running-edge-the-way-you-think-they-do) |
| The config in version control; the image pinned by digest | "Known good" exists | [EG-HARD-220](HARDENING-CHECKLIST.md#eg-hard-220--the-image-is-pinned-by-its-multi-arch-index-digest) |
| The evidence scripts on hand, tested once | Evidence before change | [examples/](examples/) |
| Names: incident commander, edge owner, app owner, legal / privacy contact | Someone decides | below |

**Roles.** The *incident commander* (IC) owns the decisions below and the timeline. The *edge
owner* runs the levers and the evidence collection on eggrd. The *app owner* investigates the app
and its data. *Legal / privacy* decides on notification. One person can hold several roles; the IC
role is never left empty.

---

## 1. Detection signals

| Signal | Where it shows | What it may mean | First look |
|---|---|---|---|
| WAF block spike | `EdgeGuardWafBlockSpike`; `WAF blocked request` lines | A scan, or an exploit campaign against a known CVE | WAF hits by rule and address; is one address also getting 2xx on the same path? |
| WAF report-mode matches that reached the app with a 2xx | `WAF rule matched (report-only)` + an access record with `status` 2xx | A payload the app may have executed | The request end to end; the app's log for that `x-request-id` |
| The app's 5xx after a run of probes | `EggrdAppServerErrors`; "IPs that probed and then saw a 5xx" | An exploit attempt hitting an error path (injection, deserialisation, traversal) | That address's full timeline |
| A new principal, or a known one from new addresses | "Principals: who, from where, when" | A leaked API key, token or client certificate | The principal's timeline; `bytes_out` per request |
| Authentication failure spike | `EdgeGuardAuthFailureSpike` | Credential stuffing; a leaked key being tried; a client broken by a rotation | 401s by address and `user_agent` |
| Unusual upstream errors | `EdgeGuardUpstreamErrorRatio`, `…NotAnswering`, `upstream unreachable` lines with `UnknownIssuer` | An upstream replaced, impersonated or down | `/__edgeguard/upstreams`; the upstream's certificate |
| Upstream answers change shape | `bytes_out` or latency per route jumps; `EdgeGuardRouteLatencyRegression` | A compromised upstream serving something else | Compare a route's responses with yesterday's |
| Certificate or ACME changes you did not make | `starting ACME order`, `ACME certificate stored` outside the renewal window; a new `edgeguard_tls_cert_not_before_seconds`; `EdgeGuardAcmeBudgetLow`; Certificate Transparency entries for your names | A stolen ACME account key or DNS access | CT log search for your names; the ACME account's orders |
| A config reload nobody made | `config reloaded` outside a change window; `config reload failed` | Someone with write access to the config | The config directory's history; who has write access |
| A restart nobody made | `EggrdEdgeRestarted`; `EdgeGuard listening` lines; runtime events | A crash (OOM, a bug) or a change | The previous container's log; `docker inspect` / `kubectl describe` |
| An image you did not deploy | the running digest differs from the pinned one | Supply chain or host compromise | Evidence first, then section 5 |
| Client addresses that make no sense | `EdgeGuardForwardedForFallback`, `EggrdForwardedForInvalid`; one address for everyone; private addresses as `client_ip` | A spoofing attempt, or a misconfigured `forwarded_hops` | Playbook 7.8 |
| Scanner flood | `EdgeGuardRateLimitSaturation`, `EggrdMostlyRateLimited`, `EdgeGuardConnectionsNearCap` | Noise, or an L7 DoS | Playbook 7.2 |
| An outside report | a customer, a researcher, a CT monitor, a leaked-credential scanner | Anything | Treat as a signal: confirm in the logs |

Background noise that is **not** a signal on its own: `Illegal SNI extension` warnings,
`/.env`, PHP, WordPress and VPN-appliance probes answered 403/404/429, TLS 1.0/1.1 handshake
failures, hit-and-run addresses. In the deployments reviewed for this corpus they were a third of
all requests and none of them was an incident.

---

## 2. Triage: the first 15 minutes

### Severity

| Severity | Examples | Response |
|---|---|---|
| **SEV1** | Confirmed data access or code execution in the app; eggrd's host or container compromised; the TLS key or ACME account key known to be leaked; a forged identity accepted by the edge | IC now; preserve evidence, contain within the hour; legal / privacy informed the same day |
| **SEV2** | An exploit attempt that reached the app with a 2xx and is not yet ruled out; a leaked API key or JWT secret with use from unknown addresses; a compromised upstream suspected | IC now; evidence; contain the path or credential within hours |
| **SEV3** | A targeted scan or stuffing run that the edge refused; a spoofing attempt that the config stopped; a misconfiguration found (trust settings, report-mode WAF) with no sign of use | Next business day: fix (the hardening item), tune alerts, keep the evidence |
| **SEV4** | Background noise; a false positive | Note it; tune |

Raise the severity whenever in doubt; lowering it later costs less than the reverse.

### The first 15 minutes

1. **Name an IC** and open a timeline (section 6.1). Write down the time, in UTC, of every step.
2. **Do not restart, redeploy or "fix" anything yet.** A restart resets every counter and, on
   Kubernetes, leaves only the current and previous container's log.
3. **Snapshot the volatile state** (2 minutes; section 3): the admin endpoints and the container
   log. If the scripts are at hand, run them now.
4. **Scope with the queries** of [LOGGING-AND-EVIDENCE.md](LOGGING-AND-EVIDENCE.md#investigation-queries):
   which addresses, which principals, which paths, since when. Is the activity still going on?
5. **Decide**, using the table below. Record who decided what, and why.

| Decision | Who | Default |
|---|---|---|
| Severity | IC | the higher one |
| Contain now (with evidence taken) or watch first | IC with the edge and app owners | contain for SEV1/2 once evidence is taken; watching an attacker is a deliberate, approved choice |
| Take a route or the whole site offline | IC, with the business owner for SEV2 | a path first (403), the site only for SEV1 |
| Rotate secrets | edge owner (eggrd's), app owner (the app's) | every secret the compromised component held (section 5) |
| Notify customers, regulators, law enforcement | legal / privacy | per section 6.4 |

---

## 3. Preserve evidence first

Order of volatility for an eggrd edge, most volatile first:

1. **Metrics**: in memory, reset by any restart.
2. **Runtime events**: Kubernetes keeps events for about an hour.
3. **The container log**: lost with the container (`docker rm`), or after two restarts on
   Kubernetes, or to json-file rotation.
4. **The admin endpoints' view**: `tls` (which certificates are live), `upstreams` (pool state).
5. **The config and the state volume** (certificate, key, ACME account): changed by your own
   remediation.
6. **The image**: changed by your own redeploy.
7. **The host**: disk, other containers, the runtime's own logs.

The edge's image is distroless: there is no shell to `exec` into, and nothing should be run inside
it. Everything below works from outside.

### Docker host

[`examples/collect-evidence-docker.sh`](examples/collect-evidence-docker.sh) does all of this
read-only and hashes the result (tested against a 0.7.0 edge on Docker 28):
```sh
sudo ADMIN=http://127.0.0.1:9090 TLS_NAME=app.example.com ./collect-evidence-docker.sh eggrd 72h
```
By hand, the same steps:
```sh
C=eggrd; E=/var/tmp/eggrd-ir-$(date -u +%Y%m%dT%H%M%SZ); umask 077; mkdir -p "$E"
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$E/clock.txt"
for p in metrics tls upstreams ready; do curl -s -m 5 "http://127.0.0.1:9090/__edgeguard/$p" > "$E/admin-$p.txt"; done
docker inspect "$C" > "$E/container-inspect.json"
docker image inspect "$(docker inspect --format '{{.Image}}' "$C")" > "$E/image-inspect.json"   # .RepoDigests: the pulled digest
docker logs --timestamps --since 72h "$C" > "$E/eggrd-stdout.log" 2>&1
LP=$(docker inspect --format '{{.LogPath}}' "$C"); [ -n "$LP" ] && [ -f "$LP" ] && cp -p "$LP"* "$E/"   # json-file driver only: empty with awslogs/journald
docker events --since 72h --until "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --filter "container=$C" > "$E/docker-events.txt"
docker diff "$C" > "$E/filesystem-diff.txt"; docker top "$C" > "$E/processes.txt"
docker cp "$C:/etc/edgeguard" - > "$E/config.tar"                               # works without a shell
docker cp "$C:/var/lib/edgeguard" - > "$E/state.tar"                            # cert, KEY, ACME account
openssl s_client -connect 127.0.0.1:443 -servername app.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -serial -dates -fingerprint -sha256 > "$E/served-cert.txt"
# The whole state volume, when it is a named volume: INTO $E, before hashing, so it is in the bundle.
# Root in the container, since the volume is 0700 and owned by the edge's user; umask 077 so the
# tarball (it holds the TLS and ACME account keys) is 0600, and owned by the collector afterwards.
docker run --rm -e OWNER="$(id -u):$(id -g)" -v eggrd-state:/s:ro -v "$E":/e \
  docker.io/library/alpine:3.21@sha256:ee16d92f96db08d9d2d07da48555a27f3a69d8f0759021dbc601195ed0d2b5bd \
  sh -c 'umask 077 && tar -C /s -czf /e/state-volume.tgz . && chown "$OWNER" /e/state-volume.tgz'
# Last: hash, bundle, check the bundle reads back, and only then remove the unpacked copy. One
# chain: if any step fails (a full disk, a permission error), nothing is deleted.
(cd "$E" && sha256sum -- * > SHA256SUMS) \
  && tar -C "$(dirname "$E")" -czf "$E.tgz" "$(basename "$E")" \
  && tar -tzf "$E.tgz" > /dev/null \
  && (cd "$(dirname "$E")" && sha256sum "$(basename "$E").tgz" | tee "$(basename "$E").tgz.sha256") \
  && rm -rf -- "$E"   # the unpacked copy holds the same secrets; the .tgz is the evidence
```
Anything collected after the `rm` is outside the bundle and its hashes: collect everything first.
If the chain stops, the unpacked copy is still there: fix the cause and run the chain again.
On a cloud VM, also snapshot the disk (an EBS snapshot) before any remediation: it keeps what the
container could not see.

### Kubernetes

[`examples/collect-evidence-k8s.sh`](examples/collect-evidence-k8s.sh) (tested on k3s v1.31 against
the reference deployment):
```sh
SNAPSHOT_PVC=eggrd-acme ./collect-evidence-k8s.sh eggrd-edge app=eggrd 72h
```
By hand:
```sh
NS=eggrd-edge; E=eggrd-ir-$(date -u +%Y%m%dT%H%M%SZ); umask 077; mkdir -p "$E"
kubectl -n $NS get events --sort-by=.lastTimestamp -o wide > "$E/events.txt"           # first: they expire
kubectl -n $NS get deploy,rs,pod,svc,cm,pvc,networkpolicy -o yaml > "$E/objects.yaml"    # includes the edge's config
kubectl get ns $NS -o yaml > "$E/namespace.yaml"
kubectl -n $NS get pod -l app=eggrd -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.nodeName}{"\t"}{range .status.containerStatuses[*]}{.image}{" "}{.imageID}{" restarts="}{.restartCount}{end}{"\n"}{end}' > "$E/pods-images.tsv"
for P in $(cut -f1 "$E/pods-images.tsv"); do
  kubectl -n $NS logs "$P" --timestamps --since=72h > "$E/logs-$P.log"
  kubectl -n $NS logs "$P" --timestamps --previous > "$E/logs-$P-previous.log" 2>/dev/null
  kubectl -n $NS port-forward "pod/$P" 19090:9090 & PF=$!; sleep 2      # not subject to NetworkPolicy
  for p in metrics tls upstreams; do curl -s "http://127.0.0.1:19090/__edgeguard/$p" > "$E/admin-$P-$p.txt"; done
  kill $PF
done
kubectl -n $NS get secret -o custom-columns=NAME:.metadata.name,TYPE:.type,CREATED:.metadata.creationTimestamp > "$E/secrets-list.txt"
(cd "$E" && sha256sum -- * > SHA256SUMS) && tar -czf "$E.tgz" "$E" && tar -tzf "$E.tgz" > /dev/null \
  && sha256sum "$E.tgz" | tee "$E.tgz.sha256" \
  && rm -rf -- "$E"   # only after a bundle that reads back; the unpacked copy holds the same secrets
```
The state volume (ACME certificate and account): the script's `SNAPSHOT_PVC` starts a short-lived,
`restricted`-compliant pod on the edge's node that mounts the claim read-only and tars it (tested;
`kubectl cp` does not work on the distroless image, which has no `tar`). Prefer a CSI
`VolumeSnapshot` where the storage class supports one. A TLS certificate kept in a Secret is
exported only with `EXPORT_SECRETS=1`.

`status.containerStatuses[].imageID` is the digest the node pulled. Kubernetes' audit log (who
changed the ConfigMap, who ran `kubectl exec`) lives with the API server: export the window.

### Chain of custody

Every bundle holds secrets (the TLS key, the ACME account key, possibly API keys). Encrypt it before
it leaves the host, and log every hand-over:

| # | Time (UTC) | Item | SHA-256 | Collected / transferred by | From → to | Purpose |
|---|---|---|---|---|---|---|
| 1 | 2026-11-04T13:21:39Z | `eggrd-ir-host1-20261104T132137Z.tgz` | `517036ba…` | edge owner | host1 → evidence bucket (object lock) | collection |
| 2 | | | | | | |

Verify before every analysis: `sha256sum -c eggrd-ir-….tgz.sha256`, and inside the bundle
`sha256sum -c SHA256SUMS`. Analyse copies, never the original.

---

## Containment levers

Measured against `mancube/eggrd:0.7.0` with the config directory on a volume (so hot reload fires),
from the moment the new file was in place to the first request that showed the new behaviour, polled
every 50 ms. A reload waits 200 ms for an editor's burst of writes to settle, so 0.2–0.35 s is the
floor. "Hot" levers rebuild the policy atomically: requests in flight finish under the old one, and
no connection drops.

| Lever | Change | Applies by | Measured | Side effects |
|---|---|---|---|---|
| Block an address or CIDR | `[access] deny` | hot reload | 0.25 s | Global; a spoofed left `X-Forwarded-For` entry cannot dodge it (measured 403) |
| WAF report → block, plus a custom rule | `[waf] mode`, `[[waf.rules]]` | hot reload | 0.21 s | Possible false positives (body inspection above all) |
| Tighten a rate limit | `[ratelimit]`, `[[ratelimit.routes]]` | hot reload | 0.29 s | **Every local bucket resets** on the reload (Redis-backed state survives) |
| Restrict methods | `validation.allow_methods` | hot reload | 0.21 s | Clients using a removed method get 405 |
| Take a path offline | a WAF path rule (403), case-insensitive and tolerant of `//`, `./`, `;` | hot reload | 0.25 s | None beyond the path; 17 spelling variants measured 403 (below) |
| *Trap:* remove the path's `[[upstreams]]` prefix | delete the route | hot reload | 0.34 s | **The path is NOT offline**: it falls back to `server.upstream` (measured: 200 from the default app) |
| Point a prefix at nothing | `target = "http://127.0.0.1:9"` | hot reload | 0.25 s | 502 `upstream_error` for the prefix; no maintenance page in 0.7 |
| Require authentication | `[auth] mode` | hot reload | 0.25 s | **The whole site**: no per-path auth in 0.7 (measured: `/` became 401 too) |
| Rotate API keys (`EDGEGUARD_API_KEYS_FILE`) | replace the key file, then touch `edgeguard.toml` | hot reload of the config | 0.21 s after the touch | The key file alone triggers nothing (measured: old key still 200 after 3 s) |
| Rotate a JWT HS256 secret | new `EDGEGUARD_JWT_SECRET_FILE` content, then touch `edgeguard.toml` | hot reload of the config | 0.25 s | Every token signed with the old secret is refused at once |
| Eject an upstream target | remove it from `targets` | hot reload | 0.34 s | Its share of traffic moves to the others; health state of the remaining targets is kept |
| Revoke a client certificate | add it to the CRL file in `crl_paths` | file watch (and hourly) | not measured here | New handshakes only; open connections keep their verification until they close |
| Turn on mTLS, change `[tls]`, `proxy_protocol*`, `header_read_timeout`, `max_connections`, `admin_*` | config + **restart** | restart | 0.4 s of refused connections in a container restart (the runtime's own stop and start took 5–9 s) | A restart resets metrics; take evidence first |
| Any change on Kubernetes with a generated ConfigMap | new ConfigMap name, pod roll | roll | 13–14 s for a one-replica `Recreate` hostPort edge, about 2 s refusing | A roll is also a restart |
| Stop the edge | `docker stop` / scale to 0 | immediate | not measured | The site is down (the balancer answers). The ultimate fail-closed |

How the change reaches eggrd decides which column you are in:

- **Directory mount** (the reference setups): hot reload, as measured above.
- **Single-file bind mount**, or a host folder bind-mounted into Docker Desktop's or Podman's VM:
  no reload. Write the file in place (`cat new > file`, not an editor that replaces it, or the
  container keeps the old inode) and restart.
- **Kubernetes ConfigMap volume edited in place**: the kubelet swaps the `..data` symlink when it
  syncs the volume, and on k3s v1.31.14 (containerd) eggrd 0.7.0 reloaded then, 27–62 s after the
  edit (four of four). One run on k3s v1.33.4 with the Docker runtime saw no reload within 90 s;
  other platforms are untested. Never with `subPath`. Roll the pods instead (`kubectl rollout
  restart`, or a new generated ConfigMap).

Every change: confirm with `config reloaded` in the log (or the new pod), *then* test the
behaviour with the request that should now be refused. `config reload failed; keeping previous
config` means nothing changed.

### Block an address or a range

```toml
[access]
deny = ["203.0.113.0/24", "198.51.100.77"]
```
Lockdown (only known ranges may connect, for SEV1 on an internal tool):
```toml
[access]
allow = ["192.0.2.0/24", "10.20.0.0/16"]
```
Refused requests are `403` with `outcome: ip_denied` (counted as `other` in
`edgeguard_requests_total` in 0.7). The list keys on the resolved client address, so it is only as
good as EG-HARD-040/041/044. Build the list from the log ("deny-list candidates" query).

**No automatic ban in 0.7.** For a ban that follows the attacker: a fail2ban-style job that runs the
deny-list query over the last N minutes, rewrites the `deny` list in the config directory, and lets
the hot reload apply it (keep the list in a file of its own that the job owns, assembled into
`edgeguard.toml`, so a bad run cannot break the rest); or the cloud WAF / network ACL in front of
the balancer, which drops the traffic before it costs the edge anything.

### Turn the WAF to block, and add a rule for the exploit

```toml
[waf]
mode = "block"
sqli = true
xss = true
path_traversal = true
inspect_path = true
inspect_headers = true
inspect_body = true

[[waf.rules]]
id      = "incident-2026-11-04-sort-injection"
target  = "path"
pattern = '(?i)/api/items\?.*\bsort=[^&]*\('

[[waf.rules]]
id      = "incident-2026-11-04-middleware-header"
target  = "headers"
pattern = '(?mi)^x-middleware-subrequest:'
```
Measured: before the switch the exploit request got 200 (report mode forwards); 0.21 s after it,
403, and the header rule refused `x-middleware-subrequest` at once. Patterns use the Rust `regex` crate's syntax (RE2-like: no lookaround,
no backreferences, linear time); a pattern that does not compile is rejected and the previous policy kept. Name
rules after the incident so their log lines are easy to find later.

### Tighten the rate limit

```toml
[ratelimit]
enabled = true
rate = "60/min"
burst = 10

[[ratelimit.routes]]
path = "/api/login"
rate = "5/min"
burst = 3
name = "login"

[ratelimit.per_key]
enabled = true
rate = "300/hour"
burst = 20
```
Measured: the fourth login attempt in the burst got 429 0.29 s after the reload, while other paths
kept the global limit. The reload empties every local bucket, so an attacker already limited gets a
fresh burst; tighten once, not repeatedly.

### Restrict methods

```toml
[validation]
allow_methods = ["GET", "HEAD", "POST"]
```

### Take a route offline

The safe way is a WAF path rule: the edge answers 403 and nothing reaches the app.
```toml
[[waf.rules]]
id      = "offline-admin"
target  = "path"
pattern = '(?i)^/+(\./+)*admin([/;?]|$)'
```
Needs `[waf] mode = "block"` and `inspect_path = true`. The WAF does not normalise paths and your
app probably does, so the pattern must catch every spelling the app maps to `/admin`. A naive
`^/admin(/|\?|$)` misses `//admin`, `/ADMIN`, `/./admin` and `/admin;x`. Measured on 0.7.0 with the
pattern above, 0.25 s after the reload:

| Result | Paths |
|---|---|
| 403 | `/admin`, `/admin/`, `/admin/users`, `/ADMIN`, `/Admin`, `//admin`, `///admin`, `/./admin`, `/.//admin`, `/admin;x`, `/admin;jsessionid=1`, `/admin?x=1`, `/%61dmin`, `/%2fadmin`, `/%2e/admin`, `/admin%2f`, `/x/../admin` (the last by the built-in traversal rules) |
| not matched (200 from the app) | `/administrator`, `/adminx`, `/admin.php` |

The path counts as offline only for spellings that return 403: test the variants your app accepts
(`curl --path-as-is`), and extend the pattern if it maps others (a `.json` suffix, a locale prefix).

**Do not remove the route's `[[upstreams]]` entry to take it offline**: the prefix then falls back to
the default upstream (`server.upstream`). Measured: with `/api/` removed, its requests went on being
answered 200 by the default app. To return a 502 for a prefix instead (no app reached), point it at
a closed port:
```toml
[[upstreams]]
path = "/api/"
target = "http://127.0.0.1:9"
```
0.7 has no maintenance response; for a page, serve one from a tiny static upstream and point the
prefix there.

### Require authentication or mTLS

`[auth]` applies to every proxied request, so this closes the whole site to anyone without a key:
```toml
[auth]
mode = "apikey"
```
(keys from `EDGEGUARD_API_KEYS_FILE`). For one path only, use the WAF rule above and reach the path
over a private network, or a second eggrd in front of that surface. Mutual TLS (`[tls.client_auth]`)
is listener-wide and startup-only: a restart, for the whole listener.

### Rotate eggrd's credentials

| Credential | Rotate by | Applies |
|---|---|---|
| API keys | new `EDGEGUARD_API_KEYS_FILE` content, then touch `edgeguard.toml` (or restart) | hot (measured 0.21 s after the touch) |
| JWT HS256 secret | new `EDGEGUARD_JWT_SECRET_FILE` content, then touch `edgeguard.toml` (or restart); the secret never goes in the config (EG-HARD-181) | hot (measured 0.25 s) |
| JWT keys at the IdP (JWKS) | rotate at the IdP; eggrd refetches after `jwks_cache_secs` (300 s default); a config reload rebuilds the JWT client | ≤ 5 min, or on reload |
| Basic passwords | new argon2 hashes in `[auth.users]` | hot |
| A client certificate | add its serial to the CA's CRL, write the CRL file | new handshakes; restart to drop open connections |
| eggrd's TLS key, ACME account key, upstream client certificate | section 5 | — |

### Eject an upstream

```toml
[[upstreams]]
path = "/api/"
targets = ["http://10.0.1.5:8080"]   # 10.0.2.5 removed
```
Measured: all `/api/` traffic on the remaining target 0.34 s after the reload. A pool with
`backup` targets can also be cut back to them by removing every primary.

### Fail closed or fail open

| Setting | Closed (secure) | Open (available) |
|---|---|---|
| `ratelimit.fail_open` (Redis store) | `false` (default): 503 when Redis is down | `true`: no rate limiting while it is down |
| WAF body inspection on streamed uploads | buffer (no `stream_requests`) or `[[validation.stream_inspect]]` | `stream_requests` without it: bodies not inspected |
| `control_plane.boot_without_policy` (managed mode) | `"refuse"`: 503 until a policy arrives | the local file |
| The edge itself | stopped: the balancer answers 503 | running with a degraded policy |
| `[auth] mode` | a gate | `none` |

During an incident, prefer closed for the affected surface and say so on the status page.

---

## 5. Eradication and recovery

When the edge itself, its host, or a secret it held may be compromised:

1. **Rebuild, do not clean.** A new host or node, the image by its pinned digest
   (`mancube/eggrd:0.7.0@sha256:b19278b3…96f6`, or a newer release), and the config from version
   control at a commit from before the incident window, diffed against what was running (the
   evidence bundle has the running copy).
2. **Rotate every secret eggrd held**, whether or not it is known to be read:
   - **TLS private key**: issue a new certificate on a new key (ACME orders a new key when
     `key.pem` is absent: move the old pair aside). Then revoke the old certificate (with the ACME
     account, or the CA's revocation using the old key).
   - **ACME account key**: **In this order** (the old account can only be deactivated with its own key, which is in that
     file): (1) copy `acme/account.json` aside into the evidence store, encrypted; (2) deactivate the
     old account at the CA with an ACME client that can load the key and account URL from that file
     (eggrd has no command for it); (3) only then delete `acme/account.json`, so the next order
     registers a new account. Once the file is gone without a copy, deactivation is impossible, and
     CAA plus Certificate Transparency monitoring are the only controls left; see playbook 7.7.
   - **API keys, Basic passwords, JWT secret**: new values, distributed to clients; old ones
     removed.
   - **Upstream client certificate** (`[upstream_tls]`) and **the control-plane edge token**
     (managed mode): reissue, and revoke the old at their CA / plane.
   - **Anything in the environment** (`EDGEGUARD_*`, `[log.ship] headers` tokens, Redis URL with a
     password).
3. **Re-issue certificates** for every name on the edge; check Certificate Transparency for
   certificates you did not order during the window.
4. **Verify before traffic:**
   ```sh
   docker run --rm -v "$PWD/config:/etc/edgeguard:ro" docker.io/mancube/eggrd:0.7.0@sha256:b19278b379a457e626954e148effffa2fe559613d55ff497fdaa862c8c4096f6 doctor --config /etc/edgeguard/edgeguard.toml   # 0 errors
   ```
   and the reference setup's `smoke.sh` for your topology (`deploy/reference/*/smoke.sh`), then the
   verify step of each [hardening item](HARDENING-CHECKLIST.md) touched by the incident.
5. **Re-enable in stages.** Keep the containment rules (WAF block, deny list, offline path) while
   traffic returns; watch the detection signals of section 1 for a day; then lift the incident
   rules one at a time, oldest risk last. Leave the WAF in block mode.
6. **Watch for return.** The same addresses, the same payloads, the old credentials being tried
   (`unauthorized` from the addresses that used them).

---

## 6. Post-incident

### 6.1 Timeline template

Keep it from the first minute, in UTC.

| Time (UTC) | Source | Event | Evidence (file, query, line) | Who |
|---|---|---|---|---|
| 2026-11-04T11:45:55Z | eggrd access log | first probe from 203.0.113.50 | `eggrd-stdout.log`, top offenders query | — |
| 2026-11-04T11:46:09Z | eggrd WAF event | `exploit-sort-injection` blocked | `WAF blocked request` line | — |
| 2026-11-04T11:52:00Z | on-call | alert acknowledged | pager | IC |
| | | evidence collected (bundle sha256) | custody log #1 | edge owner |
| | | containment: WAF block (0.21 s) | `config reloaded` line | edge owner |

### 6.2 Which logs prove what

| Question | Evidence | Limits |
|---|---|---|
| Did address X reach path Y, and what did it get? | access record (`client_ip`, `target`, `status`, `outcome`, `upstream`) | `client_ip` is only as good as the trust settings at the time (check the config in the bundle) |
| Did the app execute the payload? | the app's log for the `request_id`; database logs | eggrd never sees past the response status and size |
| Was a credential used, from where? | `principal` per record; `edgeguard_consumer_*` | Hashed principals need the candidate names to match |
| How much data left? | `bytes_out` per record, per principal; `edgeguard_consumer_bytes_total` | Sizes, not content |
| Was the request refused at the edge, and why? | `outcome`, WAF events (`rule`, `location`) | WAF events have no request id: join on address, path and second |
| Did a TLS client present a certificate / fail to? | `client_cert`; `TLS handshake failed` (DEBUG) and `edgeguard_tls_handshake_failures_total` | Without DEBUG, failures are counts only |
| What policy was live? | config history + `config reloaded` / `EdgeGuard listening` lines | A reload logs that it happened, not what changed |
| Which certificate was served? | `edgeguard_tls_cert_not_*`, `/__edgeguard/tls`, CT logs | Metrics reset on restart |
| What bypassed the edge? | the balancer's and the app's own logs: requests the app logged that have no eggrd record | Needs both kept |

### 6.3 Feed the checklist

For every finding, record the [hardening item](HARDENING-CHECKLIST.md) that would have prevented or
shortened it, and whether the item was in place. Add an item when none fits (IDs are never reused;
take the next free one in the layer). Re-run the levers drill (EG-HARD-247) if a lever surprised
you.

### 6.4 Notification

Generic pointers; your legal / privacy contact decides.

- Personal data involved: regulators may need notice within fixed windows (the GDPR's is 72 hours
  from awareness), and affected people "without undue delay" when the risk is high.
- Payment card data: the card brands' and your acquirer's rules (PCI DSS incident response).
- Sector and state rules (health, finance, US state breach-notification laws), and contracts with
  customers that set their own windows.
- A certificate key compromise: the CA's terms require prompt revocation.
- Keep what you sent, when, and to whom, in the timeline.

---

## 7. Playbooks

Each assumes sections 2 and 3 are done (IC named, evidence taken).

### 7.1 Credential stuffing

**Signals.** `EdgeGuardAuthFailureSpike` (edge auth) or a rise of the app's 401s on the login route;
many addresses, few requests each, one `user_agent` family (`okhttp`, `python-requests`); a
successful login from one of those addresses.

**Contain.**
1. Route limit on the login path (0.29 s): `[[ratelimit.routes]] path = "/api/login" rate = "5/min" burst = 3`.
2. Deny the worst sources (0.25 s) from the "top offenders" query filtered to the login route.
3. With a distributed run (most addresses under the route limit): the app's per-account lockout and
   breached-password check, a CAPTCHA, or the cloud WAF's bot rules. eggrd's limits are per address
   (and per key).

**Investigate.** Logins answered 200 from addresses that also failed (the account is likely
compromised):
```jq
include "eggrd";
[recs | access | select(.target | startswith("/api/login"))] | group_by(.client_ip)
| map(select(any(.[]; .status == 200) and any(.[]; .status == 401))
      | {ip: .[0].client_ip, ok: (map(select(.status == 200)) | length), failed: (map(select(.status == 401)) | length)})[]
```
**Recover.** Reset the affected accounts' sessions and passwords (app); keep the route limit.

### 7.2 Scanner flood or L7 DoS

**Signals.** `EdgeGuardRateLimitSaturation`, `EggrdMostlyRateLimited`, `EdgeGuardConnectionsNearCap`,
`EdgeGuardHighLatencyP95`; a few addresses with thousands of requests, still sending after their
first 429.

**Contain.**
1. Most floods are already absorbed: check `edgeguard_ratelimit_hits_total` against the app's load.
2. Deny the top sources (0.25 s); tighten the global limit (0.29 s, buckets reset).
3. Refuse the probe paths at the edge (EG-HARD-083, 0.21 s) so even the first request of each new
   address costs the app nothing.
4. Volumetric or very distributed: the balancer's or CDN's DDoS protection and a cloud WAF rate
   rule. eggrd is not a volumetric DDoS absorber.
5. Connection exhaustion: `max_connections`, `header_read_timeout` (restart).

**Investigate.** "Top offenders", "requests after the first 429", "hit-and-run probers". A flood
that hides an exploit attempt: run playbook 7.3's query over the same window.

### 7.3 An exploited app path (traversal, SQL injection, deserialisation got through)

**Signals.** A WAF report-mode match with a 2xx; `EggrdAppServerErrors` after probes; the app
reporting unexpected queries or files; data seen outside.

**Contain.**
1. WAF to block with a custom rule for the payload (0.21 s), or take the path offline with a WAF
   path rule (0.25 s). Not by removing its route (it falls back to the default upstream).
2. Deny the source addresses (0.25 s).
3. Turn body inspection on if the payload was in the body (`inspect_body = true`).

**Investigate.** Every request to the path in the window, by address, with status and size; the
same addresses' other requests; the app's log for each `request_id`:
```jq
include "eggrd";
recs | access | select(path_only == $p) | [.ts, .client_ip, .method, .target, .status, .bytes_out, .request_id] | @tsv
```
(`--arg p /api/download -r`). Large `bytes_out` on a 200 is data that left.

**Eradicate.** Fix the app; deploy; keep the WAF rule until the fix is verified, then decide
whether it stays.

### 7.4 A leaked API key or JWT signing key

**Signals.** A principal from new addresses ("Principals" query), at odd hours, on paths it never
used, with more `bytes_out`; a secret-scanning alert; the key found in a public repository.

**Contain.**
1. API key: remove it from `EDGEGUARD_API_KEYS_FILE`, touch `edgeguard.toml` (0.21 s); issue the
   client a new one. The access log names it as `apikey:<16 hex>`, a 64-bit hash of the key. To get
   the leaked key's id: put that key in a staging edge's `EDGEGUARD_API_KEYS_FILE` (an edge that
   does not hold the key answers 401 and logs no principal), send one request with it, and read
   `principal` from the record. Measured: the same key gave the same id on 0.7.0-rc.1, 0.7.0 and a
   rebuild of main with a newer Rust toolchain (rustc 1.99.1); 0.5 does not log principals at all.
   Prefer a staging edge on the version the incident ran (EG-HARD-104).
2. JWT HS256 secret: a new secret in `EDGEGUARD_JWT_SECRET_FILE`, then touch `edgeguard.toml` (0.25 s); every token is invalid, clients must re-authenticate.
   Asymmetric keys: rotate at the IdP and publish the new JWKS; eggrd picks it up within
   `jwks_cache_secs`, or at once on a config reload.
3. `ratelimit.per_key` bounds what the next leaked key can do.

**Investigate.** The principal's timeline (jq, LogQL or Insights above): first use from a new
address, every path, `bytes_out`. Then the app's log for those request ids.

### 7.5 A compromised upstream

**Signals.** `upstream unreachable` with `UnknownIssuer` (a different certificate), responses that
change size or latency, `EdgeGuardUpstreamTargetFlapping`, the app team's own alert, or content
complaints from users.

**Contain.**
1. Eject the target from the pool (0.34 s), or point the route at a known-good target.
2. If it was the only target: take the route offline (WAF path rule, 0.25 s) rather than serve from
   it.
3. With `[upstream_tls]`: a replaced upstream without the right certificate is already refused
   (502); keep it that way.

**Investigate.** `upstream` and `upstream_ms` per record show which target served what and when;
`/__edgeguard/upstreams` (in the bundle) the pool state at collection.

**Eradicate.** Rebuild the upstream; rotate the upstream client certificate eggrd presents to it
(it may have been read there) and every credential the app held.

### 7.6 A compromised eggrd host or container

**Signals.** An image digest you did not deploy; a restart or reload nobody made; `docker diff`
showing writes on a read-only image; outbound connections from the edge to places it never calls
(the NetworkPolicy's or the security group's flow logs); the host's own alerts.

**Contain.**
1. Evidence first (section 3), including a disk snapshot.
2. Take the edge out of the balancer (deregister the target; on Kubernetes, scale the Deployment to
   0 on that node or cordon and drain it) and isolate the host (security group with no ingress or
   egress, kept running for forensics).
3. Assume every secret it held is known (section 5, step 2): TLS key, ACME account key, API keys,
   JWT secret, upstream client certificate, environment variables. And every request and response
   that passed through it since the compromise was readable.

**Eradicate and recover.** Section 5 in full: a new host from a clean image, the pinned digest, the
config from version control, every secret rotated, certificates re-issued.

### 7.7 A leaked TLS key or ACME account key

**Signals.** The key found where it should not be; `ls -la` showing `account.json` world-readable on
a host others can log into (0.7 writes it `0644`, EG-HARD-180); a certificate for your names in
Certificate Transparency that you did not order; `EdgeGuardAcmeBudgetLow`.

**Contain and recover.**
- **TLS key**: move `cert.pem` and `key.pem` aside; restart the edge (ACME orders a new key and
  certificate) or install a new pair; revoke the old certificate. Until the revocation propagates,
  the old key can impersonate the site to clients that do not check revocation.
- **ACME account key**: anyone holding it can order certificates for names the account has
  validated (while the CA's authorisation reuse window lasts) and revoke yours. In this order:
  copy `acme/account.json` aside, encrypted, as evidence; deactivate the old account at the CA with
  an ACME client that can load that key and account URL (eggrd has none); only then delete
  `acme/account.json`, so the next order registers a new account. Deleting it first makes
  deactivation impossible. Then check CT for orders since the leak and revoke any you did not make,
  and add a CAA record naming your CA (and, where supported, your account URI with
  `accounturi`) so other accounts cannot issue.
- `chmod 600` the new files (until 0.8 does it).

### 7.8 A spoofed client address (`trust_forwarded_for` / `forwarded_hops` wrong)

**Signals.** One address for every client (a site-wide 429; `[access]` allowlists locking everyone
out): `forwarded_hops` too low or the balancer not appending. Client addresses that look chosen
(documentation ranges, `127.0.0.1`, addresses in your own office range from the internet), a
rate-limited client that keeps getting fresh buckets, `[access]` deny entries being dodged: hops too
high, the header trusted without a balancer, or clients reaching the edge directly.
`EdgeGuardForwardedForFallback`, `EggrdForwardedForInvalid`.

**Contain.**
1. Fence the traffic port to the balancer only (EG-HARD-001): the fix for "around the balancer".
2. Correct `forwarded_hops` from the per-provider table (EG-HARD-041); it is a request-path setting
   and hot-reloads. `trust_forwarded_for` itself is safest treated as a restart.
3. For eggrd older than 0.7.0: upgrade. Before 0.7.0 the leftmost, client-written entry was used,
   so any client could choose its address through the balancer.

**Investigate.** Measure what eggrd resolves (EG-HARD-041's verify step). Then re-read the window
knowing that `client_ip` was unreliable: correlate with the balancer's own access log, which records
the real peer, before trusting any address-based conclusion (rate-limit evasion, `[access]`
bypasses, the addresses in a deny list).
