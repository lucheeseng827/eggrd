# Logging and evidence for eggrd

For eggrd **0.7.0** and 0.7.1 (measured on 0.7.0). What the edge writes, what to collect and for how long, how to ship it, and
ready-made queries for an investigation. Every field, message and metric name here was checked
against `src/` at 0.7.0 and seen in the output of the released image; the jq and LogQL queries were
run against a synthetic log made by driving a local 0.7.0 edge with probes, a WAF rollout, rate
limiting, spoofing attempts and an API-key timeline (no production data). The CloudWatch Logs
Insights queries were written to the documented grammar and not run. Details in
[README.md](README.md#what-was-tested).

- [What eggrd emits](#what-eggrd-emits)
  - [The access record (schema 2)](#the-access-record-schema-2)
  - [Events](#events)
  - [Metrics that matter in an investigation](#metrics-that-matter-in-an-investigation)
  - [What eggrd does not record](#what-eggrd-does-not-record)
- [What to collect, and for how long](#what-to-collect-and-for-how-long)
- [Shipping](#shipping)
- [Alerts](#alerts)
- [Investigation queries](#investigation-queries)

---

## What eggrd emits

Everything is one JSON object per line on **stdout**, in the `tracing` format:

```json
{"timestamp":"2026-11-04T11:45:50.053197Z","level":"INFO","fields":{"message":"request","request_id":"be9929ea-1638-4813-b8f6-959922dd42cb","method":"GET","path":"/dashboard","client_ip":"198.51.100.15","status":200,"outcome":"ok","latency_ms":0,"duration_ms":0,"route":"default","user_agent":"lab-client/1.0","upstream":"http://app:8000","upstream_ms":0,"bytes_in":95,"bytes_out":153,"tls_version":"TLSv1.3"},"target":"edgeguard::proxy"}
```

- `fields.message` is `"request"` for an access record and the event's text otherwise.
- `target` at the top level is the Rust module that wrote the line (`edgeguard::proxy`,
  `edgeguard::serve`, `edgeguard::reload`, `rustls::msgs::handshake`, …), not the request target.
- The level is set by `RUST_LOG` (default `info`). TLS handshake and connection failures are
  `DEBUG`: to keep them, run with `RUST_LOG=info,edgeguard::serve=debug` (one line per failed
  connection; on a scanned site a few thousand a week).
- A field with no value (no principal, no upstream) is left out of the stdout line.

With `[log.ship]`, the same access records are also POSTed as NDJSON to a collector, in a flat
**schema-2** record: every key always present (`null` when it does not apply), `target` for the
request target, plus `schema` (`2`), `ts` and `edge_id` (`control_plane.edge_id`, else the
`HOSTNAME`, which on Docker is the container id). Two differences matter in an investigation:
the shipped `ts` has **second** precision while the stdout `timestamp` has microseconds, and
`[log.ship]` carries access records only, none of the events below. It is best-effort by design:
records are dropped when its queue is full, and counted.

```json
{"schema":2,"ts":"2026-11-04T12:33:11Z","request_id":"fc2ed719-b21b-4a03-8d93-199114355535","method":"GET","target":"/dashboard","client_ip":"198.51.100.15","status":200,"outcome":"ok","latency_ms":0,"duration_ms":0,"edge_id":"0bba8ef365d5","route":"default","principal":null,"user_agent":"lab-client/1.0","upstream":"http://app:8000","upstream_ms":0,"bytes_in":95,"bytes_out":153,"tls_version":"TLSv1.3","client_cert":null}
```

[`examples/eggrd.jq`](examples/eggrd.jq) reads both shapes (and Docker's json-file wrapper) into
the schema-2 names, so the jq queries below work on any of them.

### The access record (schema 2)

One per proxied request, written when the response headers go out (a streamed response's when
its last byte does). Requests to the admin listener and the CSP sink leave no record.

| Field | What it is | What it is for in an investigation |
|---|---|---|
| `ts` / `timestamp` | When the record was written, UTC | The timeline. Order records by it, not by arrival. |
| `request_id` | The inbound `X-Request-Id` if well-formed (≤128 printable ASCII), else a new UUID v4. Sent upstream and returned to the client | Joins the edge's record with the app's log and the client's report. A client can choose it, so it is a correlation key, not proof. |
| `method` | HTTP method | Probing (`PROPFIND`, `CONNECT`, junk verbs), state-changing requests. |
| `target` / `path` | Path plus the **sanitised** query (see [what is not recorded](#what-eggrd-does-not-record)) | What was asked for: probe paths, exploit payloads, the endpoint of a data pull. |
| `client_ip` | The resolved client: the TCP peer, the PROXY-protocol client, or the `X-Forwarded-For` entry `forwarded_hops` from the right | Who. As trustworthy as EG-HARD-001/040/041/044 make it. A balancer's address here means the header was absent, short or invalid. |
| `status` | The status sent to the client | 2xx on a probe is a soft-200 or a hit; 5xx after probes is the classic exploit signal. |
| `outcome` | Why the edge answered as it did (table below) | Separates the edge's refusals from the app's answers. `ok` means "the upstream answered", whatever its status. |
| `latency_ms` | Time to the response headers | Slow-path payloads (time-based SQL injection), a struggling upstream. |
| `duration_ms` | Time until the record was written (a stream's last byte) | Long downloads and streams: exfiltration volume over time. |
| `edge_id` | The edge that served it (shipped records only) | Which replica, which host to take evidence from. |
| `route` | The matched route's label (`default`, a `[[upstreams]]` prefix, a `[[ratelimit.routes]]` name) | Which backend and which limit applied. |
| `principal` | The authenticated identity as `log.principal` records it: `apikey:<16 hex>` (a hash of the key), the Basic user, the JWT `sub`, the certificate's name; or `sha256:<16 hex>` with `principal = "hash"` | Whose credential was used, from which addresses, for what. |
| `user_agent` | Up to 256 bytes | Tooling fingerprints (`zgrab`, `python-requests`, `okhttp` in a stuffing run). Client-chosen. |
| `upstream` | `scheme://host:port` it was forwarded to (no userinfo); `null` when the edge answered | Which target served it: the compromised-upstream playbook starts here. |
| `upstream_ms` | Time from sending upstream to its response headers | Upstream-side slowness versus edge-side. |
| `bytes_in`, `bytes_out` | Request and response bytes, headers included | Data volume per principal or address. |
| `tls_version` | `TLSv1.3` / `TLSv1.2` when eggrd terminated TLS | Downgrade attempts; which hop terminated TLS. |
| `client_cert` | The verified client certificate's first name (`[tls.client_auth]` or a trusted forwarded header) | Which machine identity. |

**Outcomes** (`outcome` in the record; the label on `edgeguard_requests_total`):

| Outcome | Status | Meaning |
|---|---|---|
| `ok` | the app's | Forwarded and answered, including the app's own 4xx and 5xx |
| `rate_limited` | 429 | Per-IP, per-route or per-key limit (`edgeguard_ratelimit_hits_total{scope}`) |
| `forbidden` | 403 | A WAF rule in block mode (also an inbound DLP block or an LLM model refusal) |
| `ip_denied` | 403 | `[access]` deny, or not in `[access] allow`. **Counted as `other` in `edgeguard_requests_total` in 0.7** |
| `unauthorized` | 401 | The `[auth]` gate failed, including a duplicated credential header |
| `method_not_allowed` | 405 | Not in `validation.allow_methods` |
| `payload_too_large` / `header_too_large` | 413 / 431 | Over `max_body` / `max_header_bytes` |
| `not_found` | 404 | An unknown `/__edgeguard/*` path (the ops endpoints on the public port with `admin_port` set) |
| `bad_request` | 400 | 0.7.1 and later (#1748): the request names two hosts (`:authority` or an absolute-form target that differs from `Host`), sends `Host` twice, or (HTTP/1.1, HTTP/2) names no host at all |
| `upstream_error`, `bad_gateway`, `upstream_body_error`, `upstream_body_too_large` | 502 | The edge could not get an answer |
| `upstream_timeout` | 504 | `upstream_timeout` elapsed |
| `limiter_error` | 503 | The Redis limiter failed closed |
| `no_policy`, `over_quota` | 503, 429 | Managed mode only |
| `cors_preflight`, `ws_upgrade` | 204, 101 | Answered preflight; WebSocket tunnel (counted as `other` in the metric) |

### Events

Lines whose `message` is not `"request"`. The ones worth keeping, with their fields:

| `message` | Level, module | Fields | Meaning |
|---|---|---|---|
| `WAF blocked request` | WARN `edgeguard::proxy` | `rule` (the built-in class or your rule's `id`), `class` (`sqli`, `xss`, `path_traversal`, `custom`), `location` (`path`, `headers`, `body`), `client_ip`, `path` | A block-mode match; the request got 403 (`outcome: forbidden`). **No `request_id`**: join with the access record on `client_ip`, `path` and the second. |
| `WAF rule matched (report-only)` | WARN `edgeguard::proxy` | as above | A report-mode match; the request was forwarded. The rollout review reads these. |
| `WAF blocked a streamed request body; upload cut`, `WAF rule matched in a streamed request body (report-only)` | WARN | rule fields | `[[validation.stream_inspect]]` matches. |
| `config reloaded` | INFO `edgeguard::reload` | `path` | A new policy is live. One you did not make is an incident signal. |
| `config reload failed; keeping previous config` | ERROR `edgeguard::reload` | `error` (the parse or validation error, with line) | The edit did not apply; the old policy still runs. |
| `EdgeGuard listening (HTTPS)` / `EdgeGuard listening` | INFO `edgeguard` | `listen`, `upstream`, `auth`, `rate_limit`, `store`, `waf`, `tls`, `redirect_port` | Startup, with the effective auth mode and WAF mode: a cheap config fingerprint per start. |
| `EdgeGuard admin endpoints listening (health/ready/metrics)` | INFO | `listen` | Where the admin listener bound (check it is not public). |
| `shutdown signal received; draining`, `EdgeGuard stopped` | INFO | — | Every stop. A stop nobody announced is a signal. |
| `upstream unreachable`, `upstream timed out` | WARN `edgeguard::proxy` | `error` (the cause: `Connection refused`, `UnknownIssuer`, …), `upstream` (the configured base URL plus the sanitised path; **0.7.0 does not strip userinfo here, 0.7.1 redacts it**, EG-HARD-165) | Why a 502/504 happened. |
| `TLS handshake failed` | DEBUG `edgeguard::serve` | `error` (`received fatal alert: ProtocolVersion`, `peer is incompatible: NoKxGroupsInCommon`, `received corrupt message of type InvalidContentType` for plaintext to the TLS port), `peer`, `reason` (`client_cert`, `timeout`, `other`) | Old clients, scanners, mTLS refusals. Never in the access log: a refused handshake has no request. |
| `TLS handshake timed out`, `closed before sending a ClientHello` | DEBUG `edgeguard::serve` | `peer` | Port scans and health checks that only open a socket. |
| `connection ended with an error` | DEBUG `edgeguard::serve` | `error` (`read header from client timeout` is a slow client cut by `header_read_timeout`; `invalid URI`), `peer` | Slowloris and malformed requests. |
| `closed: PROXY protocol header refused` | DEBUG `edgeguard::serve` | `peer`, `result` | A PROXY header from outside `proxy_protocol_trusted`, or garbage. |
| `connection cap reached; closing new connections until one frees up`, `below the connection cap again` | WARN / INFO | `listen`, `max_connections` | A connection flood reached `max_connections`. |
| `Illegal SNI extension: ignoring IP address presented as hostname (…)` | WARN `rustls::msgs::handshake` | `log.*` | A client sent an IP literal as SNI (the hex is the address). Scanner noise (EG-HARD-027). |
| `starting ACME order` | INFO | `domains`, `directory` | An issuance or renewal began. |
| `ACME certificate stored`, `loading the renewed certificate`, `the live store serves the renewed certificate` | INFO | — | A new certificate is live: compare with Certificate Transparency. |
| `certificate renewal failed; still serving the current certificate`, `ACME renewal deferred by the issuance budget; still serving the current certificate` | WARN | `error` | Renewal trouble; weeks of margin remain. |
| `certificate files changed but do not load; still serving the previous certificate` | WARN | — | A bad pair was written to `cert_path`/`key_path` (by a tool, or by someone). |
| `client CA bundle or CRLs reloaded; new handshakes use them` | INFO | — | The mTLS trust changed. |
| `rate-limit store error; failing closed (503)` / `failing open (allowing request)` | WARN/ERROR | `error` | Redis trouble; with fail-open, limits are off. |
| `access-log shipping enabled`, `log collector rejected a batch` | INFO / WARN | `url`, status | The `[log.ship]` path. |

There is no admin API that changes state, so there are no admin audit events: the admin listener
serves read-only GETs, and its requests are not logged. Changes reach eggrd through the config
file (`config reloaded`) or a restart (`EdgeGuard listening`); audit those where they are made (the
repository, the deploy pipeline, the cluster's audit log).

CSP reports POSTed to `/__edgeguard/csp-report` are counted in `edgeguard_csp_reports_total` and
logged at DEBUG under `edgeguard::csp` with the violated directive only.

### Metrics that matter in an investigation

From `GET /__edgeguard/metrics` on the admin listener. Counters are in memory and **reset on every
restart** (they survive a hot reload), so take a copy early.

| Metric | Labels | Use |
|---|---|---|
| `edgeguard_requests_total` | `outcome` (as above; `ip_denied`, `cors_preflight`, `ws_upgrade` count as `other`) | Refusals by kind over time. |
| `edgeguard_route_requests_total` | `route`, `method`, `status_class` | The app's own 5xx per route (the outcome stays `ok`). |
| `edgeguard_waf_hits_total` | `rule` = the class (`sqli`, `xss`, `path_traversal`, `custom`); report and block both count | WAF pressure. Per-rule detail is only in the log. |
| `edgeguard_ratelimit_hits_total` | `scope` (`ip`, `route`, `key`) | Which limit is doing the work. |
| `edgeguard_forwarded_for_total` | `result` (`used`, `absent`, `short`, `invalid`) | With `trust_forwarded_for`: requests that fell back to the TCP peer. |
| `edgeguard_proxy_protocol_total` | `listener`, `result` (`proxied`, `local`, `missing`, `direct`, `untrusted`, `invalid`, `timeout`) | PROXY-protocol trust problems and probes. |
| `edgeguard_client_cert_header_total` | `result` (`accepted`, `untrusted_peer`, `invalid`, `unverified`) | Forged forwarded-certificate headers. |
| `edgeguard_tls_handshakes_total`, `edgeguard_tls_handshake_failures_total` | `listener`; failures by `reason` (`client_cert`, `timeout`, `other`) | Handshake refusals, which the access log never shows. |
| `edgeguard_tls_no_client_hello_total` | `listener` | Connections closed before a ClientHello (scans, TCP health checks). |
| `edgeguard_connections_open`, `edgeguard_connections_rejected_total`, `edgeguard_connections_max` | `listener` | Connection floods. |
| `edgeguard_tls_cert_not_after_seconds`, `edgeguard_tls_cert_not_before_seconds` | `source`, `cert` | Which certificate is live, and when it was issued: a new `not_before` you did not expect is a re-issuance. |
| `edgeguard_tls_cert_renewals_total`, `edgeguard_tls_cert_reloads_total` | `source`, `outcome` | Renewals and certificate swaps. |
| `edgeguard_upstream_requests_total` | `upstream`, `result` (`ok`, `http_5xx`, `connect_error`, `tls_error`, `timeout`, `reset`, `error`) | Upstream trouble per target. |
| `edgeguard_upstream_in_rotation`, `edgeguard_upstream_ejections_total` | `route`, `upstream` | Pool state. |
| `edgeguard_consumer_requests_total`, `edgeguard_consumer_bytes_total` | `consumer` (up to `metrics.consumer_series_max`) | Per-principal volume. |
| `edgeguard_logship_sent_total`, `edgeguard_logship_dropped_total` | `reason` (`queue_full`, `send_failed`) | Gaps in the shipped stream. |
| `edgeguard_csp_reports_total` | — | CSP violations (a sudden rise can be an injected script). |

### What eggrd does not record

- **Query values that look secret.** `log.query = "redact"` (the default) replaces the value of
  any parameter whose name contains `key`, `token`, `secret`, `password`, `passwd`, `pwd`, `auth`,
  `credential`, `session`, `sig`, `signature`, `code`, `state`, `nonce`, `assertion`, `email`,
  `phone` or `ssn` (case-insensitive, also percent-decoded), and any value shaped like a JWT or a
  24+ character token containing a digit, with `<redacted>`. Measured: OAuth
  `?code=…&state=…` → `?code=<redacted>&state=<redacted>&scope=email`, `?email=…` and
  `?%74%6f%6b%65%6e=…` redacted. Add names with `log.redact_params`; `query = "drop"` keeps only the
  path; `"full"` logs everything.
- **Path segments are not redacted.** `/reset/<token>` is logged whole (it cannot be told from
  `/users/<id>`). An app that puts secrets in paths needs `query = "drop"` *and* a different URL
  design.
- **Headers and bodies** are never logged, `Authorization` and `Cookie` included. Only the
  `User-Agent` (256 bytes) is.
- **API keys** appear only as `apikey:<16 hex>` (a hash), never the key. Basic passwords never.
- **Principals** can be hashed (`log.principal = "hash"`) or dropped (`"off"`); per-consumer metric
  series are capped by `metrics.consumer_series_max` (`0` turns them off).
- **CSP report bodies** are not logged above DEBUG.
- **Refused TLS handshakes, connections closed at accept, and admin-listener requests** leave no
  access record: the first two are DEBUG events and metrics, the third nothing.

Things to keep out of the logs yourself: credentials in upstream URLs (EG-HARD-165), secrets in
`edgeguard.toml` (a startup line does not print the file, but evidence bundles and ConfigMaps
copy it), and a `RUST_LOG=trace` left on in production.

---

## What to collect, and for how long

| Data | Source | Keep searchable | Keep archived | Why |
|---|---|---|---|---|
| eggrd stdout (access records **and** events) | container log via a node agent or logging driver | 30–90 days | 1 year (longer if a regulation says so) | The record of every request and every refusal. Breaches are often found months later. |
| `[log.ship]` stream | collector | as above | as above | A second, structured copy. Best-effort, access records only: never the only copy. |
| Metrics | Prometheus scrape of the admin port | 15–30 days at full resolution | 13 months downsampled | Baselines for "was this normal last month". Counters reset on restart. |
| Load balancer logs (ALB/NLB access logs, CDN logs) | the provider | 30–90 days | 1 year | What the edge never saw: handshakes refused upstream of it, requests a cloud WAF dropped, traffic that bypassed the edge. |
| Runtime events (Docker events, Kubernetes events and audit log) | the host / the API server | 90 days | 1 year | Restarts, image changes, ConfigMap edits, `kubectl exec`. Kubernetes keeps events for about an hour unless shipped. |
| Config history | version control | forever | — | What policy was live at a given moment. |
| Certificate history | `edgeguard_tls_cert_*`, the ACME directory, Certificate Transparency | — | 1 year | Unexpected issuance for your names. |
| App logs with `x-request-id` | the app | as the access log | as the access log | The other half of every request's story. |
| Evidence bundles | INCIDENT-RESPONSE.md | for the incident | per legal hold | Chain of custody. |

**Do not sample security data.** eggrd writes one record per request and has no sampling of its
own (`[tracing] sample_rate` affects spans only). Keep it that way through the pipeline: a sampled
access log cannot answer "did this address ever reach `/admin`". Watch for drops you did not
choose:

- `[log.ship]` drops when its queue is full (`edgeguard_logship_dropped_total`; alert
  `EggrdLogShipDropping` in [examples/prometheus-security-rules.yml](examples/prometheus-security-rules.yml)).
- journald rate-limits per service (`RateLimitBurst`); with Docker's journald driver, lines past
  the limit vanish before any agent reads them. Check `journalctl | grep -i suppressed`.
- Docker's `awslogs` driver with `mode: non-blocking` drops when `max-buffer-size` fills (the
  alternative, blocking, can stall the edge's stdout).
- json-file rotation (`max-size`, `max-file`) deletes the oldest lines on a busy host: ship before
  rotation takes them.

**Clocks.** Every host in the path (balancer, edge, app, database) synchronised (chrony,
systemd-timesyncd), alerting on offset. eggrd writes UTC with microseconds on stdout; keep UTC
everywhere in the pipeline.

**Integrity.** Logs that live only on the edge's host can be edited or deleted by whoever owns the
host.
- Ship off the host as lines are written (seconds, not a nightly copy).
- Archive to write-once storage: an S3 bucket with versioning and Object Lock in compliance mode
  (or a GCS bucket with a locked retention policy, Azure immutable blob storage), in an account the
  edge's credentials cannot administer. The edge's role may `PutObject`, never delete or change
  retention.
- CloudWatch Logs events cannot be edited, but a log group can be deleted: deny
  `logs:DeleteLogGroup`/`DeleteLogStream`/`PutRetentionPolicy` to the edge's role, and subscribe the
  group to a locked bucket for the archive.
- Per day (or per object), record the SHA-256 of what was archived somewhere the archive's writers
  cannot reach; it proves later that a file is the one written.

---

## Shipping

Tested combinations (see [README.md](README.md#what-was-tested)):

| Path | Carries | Example | Tested here |
|---|---|---|---|
| eggrd `[log.ship]` → Vector → Loki + S3 | access records (schema 2) | [examples/vector.yaml](examples/vector.yaml) | Yes: Vector 0.46, Loki 3.4, an S3 emulator |
| Container log → Vector → Loki + S3 | everything on stdout | [examples/vector.yaml](examples/vector.yaml) (`eggrd_stdout`) | Yes |
| Container log (CRI) → Fluent Bit → Loki | everything on stdout | [examples/fluent-bit.yaml](examples/fluent-bit.yaml) | Yes: Fluent Bit 3.2, a CRI-format file |
| Docker `awslogs` driver → CloudWatch Logs | everything on stdout | [compose.logging.yaml](../../deploy/reference/compose-single-vm/compose.logging.yaml) | No (needs AWS) |
| CloudWatch agent tailing pod logs → CloudWatch Logs | everything, with a CRI prefix | [examples/cloudwatch-agent.json](examples/cloudwatch-agent.json) | JSON validated only |
| OTLP (`[tracing]`, `[metrics.otlp]`) → a collector | spans and metrics, not logs | below | Config passes doctor; not run against a collector |

### `[log.ship]`

```toml
[log.ship]
enabled = true
url = "https://logs.example.com/eggrd"
headers = [["Authorization", "Bearer from-a-secret-store"]]
batch = 500
interval_secs = 5
queue_size = 10000
```
Startup-only. NDJSON POSTs; any receiver that takes them works (Vector's `http_server`, a Loki
push gateway, Splunk HEC, an S3 writer). The `[outbound]` defaults (proxy, extra CA, client
certificate) apply. A token in `headers` is in the config file, and 0.7 has no `_FILE` or environment form for
these headers, so it breaks EG-HARD-181 (a known gap). Prefer a receiver that needs no token: mutual
TLS (`[log.ship]` `client_cert_path` / `client_key_path` / `ca_path`, the receiver verifying the
client certificate), or a loopback sidecar; if you must use a token, keep the file as secret as the
token and give it to a receiver that accepts nothing else.

### Vector

[`examples/vector.yaml`](examples/vector.yaml) takes both the `[log.ship]` stream and the container
log (`file`; use `kubernetes_logs` or `docker_logs` in production), normalises both to the
schema-2 names with `kind = access|event`, and writes to Loki (labels `job`, `kind`, `level` only:
`client_ip`, `target` and `request_id` stay fields, or Loki's index explodes) and to an S3 bucket by
`kind` and date.

- **The receiver is evidence input, so it is locked down.** `http_server` binds `127.0.0.1:8687`
  (Vector as a sidecar in the edge's pod or on its host) and requires Basic credentials, which
  eggrd sends from `[log.ship] headers`. Across hosts, bind a private address and use the commented
  mutual-TLS block (eggrd's `[log.ship]` `client_cert_path`, `client_key_path`, `ca_path`).
  Measured: eggrd shipped through the sidecar (`edgeguard_logship_sent_total` rising, nothing
  dropped); an unauthenticated POST on loopback got `401`; another container could not connect.
- **Nothing is dropped silently.** A stdout line that does not parse (a panic, a truncated line, an
  unexpected prefix) is rerouted to `kind = "unparsed"` with its raw text, in Loki and in the
  archive. Measured with a panic line and a broken CRI line: both arrived as `unparsed`.

Tested end to end: the first run delivered 945 records to the bucket and to Loki, events
included, and the LogQL queries below ran on that stream; the locked-down receiver and the
dead letter were run again after the change.

### Fluent Bit

[`examples/fluent-bit.yaml`](examples/fluent-bit.yaml) tails `/var/log/containers`, strips the CRI or
Docker wrapper with the built-in multiline parsers, parses eggrd's JSON and ships to Loki. The
nesting is kept, so LogQL sees `fields_client_ip`, `fields_status`, … after `| json`. Tested with a
CRI-format copy of the synthetic log: the per-IP 429 counts matched the jq results exactly.

### Docker logging driver (one VM)

The reference's [`compose.logging.yaml`](../../deploy/reference/compose-single-vm/compose.logging.yaml)
sets the `awslogs` driver. Create the group with a retention first, and give the instance role
`logs:CreateLogStream` and `logs:PutLogEvents` on it only:
```sh
aws logs create-log-group --log-group-name /eggrd/edge
aws logs put-retention-policy --log-group-name /eggrd/edge --retention-in-days 90
```
CloudWatch then has eggrd's JSON line as the message and discovers `fields.client_ip`,
`fields.status`, … automatically; the Insights queries below use those names.

### CloudWatch agent (Kubernetes on VMs)

[`examples/cloudwatch-agent.json`](examples/cloudwatch-agent.json) tails
`/var/log/pods/eggrd-edge_eggrd-*/eggrd/*.log`. Those files carry the CRI prefix
(`<time> stdout F {json}`), so Insights cannot auto-discover the JSON fields; either `parse` with a
regex (shown below), or ship through Fluent Bit (its `cri` parser, then its `cloudwatch_logs`
output) to get clean JSON.

The example runs the agent as `root` because the kubelet writes `/var/log/pods` readable by root
only. To run it as a dedicated user instead, give that user read access to exactly those files (a
group that owns them, or a read-only ACL such as `setfacl -R -m u:cwagent:rX /var/log/pods` plus a
default ACL for new pods) and set `"run_as_user": "cwagent"`; the agent then also needs write
access to its own state directory. Either way, the agent holds every pod's log: treat the host user
as privileged.

### OTLP

eggrd exports spans and metrics over OTLP/HTTP; logs are stdout or `[log.ship]`. With an
OpenTelemetry collector, read the container log with its `filelog` receiver and a `json_parser`
operator, and point these at its OTLP/HTTP port:
```toml
[tracing]
enabled = true
endpoint = "http://otel-collector:4318/v1/traces"
sample_rate = 1.0

[metrics.otlp]
enabled = true
endpoint = "http://otel-collector:4318/v1/metrics"
interval_secs = 30
```
With `[tracing]` on, eggrd writes a `traceparent` for the upstream request (a sampled one); with
it off, a client's `traceparent` passes through to the app unchanged. eggrd always sends
`X-Request-Id`. So `x-request-id` is the join key between eggrd and the app in every setup, and
`traceparent` only when tracing is on.

---

## Alerts

The monitoring bundle ([`monitoring/prometheus/alerts.yml`](../../monitoring/prometheus/alerts.yml),
bundle 1.6.2), the reference's [`rules-0.7.yml`](../../deploy/reference/monitoring/prometheus/rules-0.7.yml)
and this corpus's [`prometheus-security-rules.yml`](examples/prometheus-security-rules.yml) (unit
tested with promtool). What each one means for security:

| Alert | Fires when | Security reading |
|---|---|---|
| `EdgeGuardWafBlockSpike` | WAF matches (report or block) > 1/s for 10 m | A scan or an exploit attempt. Read the WAF events by rule and address. |
| `EdgeGuardAuthFailureSpike` | `unauthorized` > 5/s for 10 m | Credential stuffing, a leaked key being tried, or a client broken by a rotation. |
| `EdgeGuardRateLimitSaturation` | rate-limit hits > 10/s for 10 m | A scanner flood or L7 DoS; also a misconfigured `forwarded_hops` (everyone in one bucket). |
| `EdgeGuardLimiterErrors` | `limiter_error` > 0 for 5 m | Redis down; fail-closed 503s. With fail-open, rate limiting is off. |
| `EdgeGuardHighUpstream5xx` | edge-made 502/504 > 5% for 5 m | Upstream down or unreachable. Not the app's own 5xx: see `EggrdAppServerErrors`. |
| `EdgeGuardUpstreamTimeouts`, `EdgeGuardUpstreamErrorRatio`, `EdgeGuardUpstreamNotAnswering` | upstream timeouts / non-ok results per target | A target under attack, overloaded, or changed (a compromised upstream answering differently). |
| `EdgeGuardUpstreamPoolDown`, `EdgeGuardUpstreamTargetOut`, `EdgeGuardUpstreamTargetFlapping` | pool targets out of rotation | Availability; a flapping target after a deploy you did not make. |
| `EdgeGuardHighLatencyP95`, `EdgeGuardRouteLatencyRegression` | p95 > 1 s; a route's p99 doubled since yesterday | Slow-path payloads, L7 DoS on an expensive route. |
| `EdgeGuardConnectionsNearCap` | open connections > 80% of `max_connections` | A connection flood (slowloris variants, many idle connections). |
| `EdgeGuardClientCertRejectSpike` | client-certificate handshake refusals > 0.2/s | Revoked or expired client certificates in use, or a scan of an mTLS port. |
| `EdgeGuardClientCertHeaderRefused` | forwarded-certificate headers refused | `untrusted_peer`: someone forging the header, or the balancer's addresses changed. |
| `EdgeGuardProxyProtocolRefused`, `…RefusedLowRate`, `…Missing` | PROXY headers refused or absent | Trust-list drift (an outage), or someone sending PROXY headers directly. |
| `EdgeGuardForwardedForFallback` | > 10% of requests fell back to the TCP peer | Clients bypass the balancer (EG-HARD-001), or `forwarded_hops` is too high. |
| `EdgeGuardTlsHandshakeFailureRatio` | > 20% of handshakes fail | Scanners, old clients, or a certificate / CA change. |
| `EdgeGuardCertExpiringSoon`, `…Critical`, `EdgeGuardCertRenewalFailing` | expiry in < 14 d / < 3 d; renewals failing 6 h | Availability; also a sign the ACME account or DNS was tampered with. |
| `EdgeGuardAcmeBudgetLow`, `…Exhausted` | issuance budget below 40% / at 0 | Unexpected issuance: someone re-ordering certificates with your account. |
| `EdgeGuardCrlStale` | a CRL past its `nextUpdate` | Revocations are not being applied. |
| `EggrdAppServerErrors` | the app's own 5xx > 5% of a route for 10 m | An exploited path often shows first as app errors after probes. |
| `EggrdLogShipDropping` | shipped records dropped | A gap in the evidence. |
| `EggrdForwardedForInvalid` | `X-Forwarded-For` entries that are not addresses | Header probing, or a proxy writing something odd. |
| `EggrdMostlyRateLimited` | > 50% of requests rate limited for 30 m | Sustained scanner pressure: build a deny list. |
| `EggrdEdgeRestarted` | the request counters reset | A restart: expected after a deploy, an incident signal otherwise. |

Two signals have no metric in 0.7 and need log alerts, as two rules with different weight:

- **Page** on `config reload failed` (ERROR): the edit did not apply and the old policy still runs.
- **Notify** on `config reloaded`: every reload, expected or not, so that one nobody made is seen.
  The query cannot tell a change window from an attack: keep this alert, and mute it during your
  change windows in Alertmanager (a time-based mute or an inhibit rule), not in the query.

In Loki:
```logql
sum(count_over_time({job="eggrd", kind="event"} |= "config reload failed" [5m])) > 0
sum(count_over_time({job="eggrd", kind="event"} |= "config reloaded" [5m])) > 0
```
In CloudWatch, metric filters on `{ $.fields.message = "config reload failed*" }` (an alarm that
pages) and `{ $.fields.message = "config reloaded" }` (one that notifies).

---

## Investigation queries

Field names: jq and the Vector-normalised Loki stream use the schema-2 names (`target`, `ts`);
CloudWatch (stdout lines) uses `fields.path`, `fields.client_ip`, …; Fluent Bit's Loki stream uses
`fields_path`, `fields_client_ip`, ….

### jq (any JSON log: `docker logs`, `kubectl logs`, json-file, `[log.ship]` files)

```sh
L=docs/security/examples          # where eggrd.jq lives
F=eggrd.log                       # docker logs eggrd > eggrd.log 2>&1 ; or kubectl logs …
```
All queries are `jq -nR -L "$L" '<query>' "$F"`; add `-c` for one line per result. Lines that are
not JSON are skipped; a CRI prefix is stripped first with `sed -E 's/^[^ ]+ [^ ]+ [^ ]+ //'`.

**Top offenders** (requests, statuses, probes, first and last seen):
```jq
include "eggrd";
[recs | access] | group_by(.client_ip)
| map({ip: .[0].client_ip, requests: length, statuses: count_by(.status),
       probes: (map(select(is_probe)) | length),
       first: (map(.ts) | min), last: (map(.ts) | max)})
| sort_by(-.requests) | .[:10][]
```

**Probe paths**, with how many addresses tried each and what they got:
```jq
include "eggrd";
[recs | access | select(is_probe)] | group_by(path_only)
| map({path: (.[0] | path_only), hits: length, ips: (map(.client_ip) | unique | length),
       statuses: count_by(.status)})
| sort_by(-.hits) | .[:20][]
```

**Soft-200s**: probes the app answered `200` (EG-HARD-146):
```jq
include "eggrd";
[recs | access | select(is_probe and .status == 200 and .upstream != null)] | count_by(path_only)
```

**Requests after the first 429**, per address (do scanners back off?):
```jq
include "eggrd";
[recs | access] | group_by(.client_ip)
| map((map(.status) | index(429)) as $i | select($i != null)
      | {ip: .[0].client_ip, before_first_429: $i, after_first_429: (length - $i - 1),
         of_which_429: (.[$i + 1:] | map(select(.status == 429)) | length)})
| sort_by(-.after_first_429) | .[:10][]
```
and the total: `… | map(… | length - $i - 1) | add`.

**WAF hits by rule, location and mode**, with the addresses:
```jq
include "eggrd";
[recs | events | select(.message | startswith("WAF "))]
| group_by([.rule, .location, (.message | test("blocked"))])
| map({rule: .[0].rule, class: .[0].class, location: .[0].location,
       mode: (if .[0].message | test("blocked") then "block" else "report" end),
       hits: length, ips: (map(.client_ip) | unique)})
| sort_by(-.hits)[]
```

**5xx by minute**, and **addresses that probed and then saw a 5xx**:
```jq
include "eggrd";
[recs | access | select(.status >= 500)] | group_by(.ts[0:16])
| map({minute: .[0].ts[0:16], n: length, outcomes: count_by(.outcome), routes: count_by(.route)})[]
```
```jq
include "eggrd";
[recs | access] | group_by(.client_ip)
| map(select(any(.[]; is_probe) and any(.[]; .status >= 500))
      | {ip: .[0].client_ip, probes: (map(select(is_probe)) | length),
         fivexx: (map(select(.status >= 500) | {ts, target, status, outcome}))})[]
```

**Principals**: who, from which addresses, when (a key used from a new address stands out):
```jq
include "eggrd";
[recs | access | select(.principal != null)] | group_by(.principal)
| map({principal: .[0].principal, requests: length, ips: (map(.client_ip) | unique),
       first: (map(.ts) | min), last: (map(.ts) | max), statuses: count_by(.status)})[]
```
**One principal's timeline** (`--arg p apikey:113179bb9bc261f2 -r`):
```jq
include "eggrd";
recs | access | select(.principal == $p)
| [.ts, .client_ip, .method, .target, .status, .outcome, (.user_agent // "-")] | @tsv
```

**One request end to end** (`--arg id <request id>`): its record, plus the events written in the
same second for the same address (WAF lines carry no request id) or the same target (upstream
errors). Then search the app's log for the same `x-request-id`:
```jq
include "eggrd";
[recs] | (map(select(.request_id == $id)) | first) as $r
| if $r == null then empty else .[] end
| select(.request_id == $id
     or (.message != "request" and .ts[0:19] == $r.ts[0:19]
         and (.client_ip == $r.client_ip
              or ($r.target != null and ((.upstream // "") | endswith($r.target))))))
| {ts, message, status, outcome, client_ip, target, upstream, error, rule}
```

**TLS and connection failures** (needs `edgeguard::serve=debug`):
```jq
include "eggrd";
[recs | events | select(.module == "edgeguard::serve" or (.module // "" | startswith("rustls")))]
| count_by(.message + (if .error then ": " + .error else "" end))
```

**`X-Forwarded-For` fallbacks**: with `trust_forwarded_for`, a request whose `client_ip` is a
private (balancer or pod) address fell back to the TCP peer (`absent`, `short` or `invalid`):
```jq
include "eggrd";
[recs | access | select(.client_ip | test("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|::1$|f[cd])"))]
| count_by(.client_ip)
```

**Lifecycle and config events** (starts, stops, reloads, certificates):
```jq
include "eggrd";
recs | events
| select(.message | test("reload|listening|shutdown|stopped|ACME|certificate|shipping"))
| [.ts, .level, .message, (.error // .path // .url // "" | tostring | .[0:60])] | @tsv
```

**Hit-and-run probers** (three requests or fewer, at least one a probe: no per-IP limit sees them):
```jq
include "eggrd";
[recs | access] | group_by(.client_ip)
| map(select(length <= 3 and any(.[]; is_probe)) | .[0].client_ip)
| {ips: length, sample: .[:10]}
```

**Refused methods and `[access]` denials**:
```jq
include "eggrd";
[recs | access | select(.outcome == "method_not_allowed" or .outcome == "ip_denied")]
| {methods: (map(select(.outcome == "method_not_allowed")) | count_by(.method)),
   ip_denied: (map(select(.outcome == "ip_denied")) | count_by(.client_ip))}
```

**Deny-list candidates**: addresses with 20+ probes, printed as an `[access]` line (`-r`):
```jq
include "eggrd";
[recs | access] | group_by(.client_ip)
| map(select((map(select(is_probe)) | length) >= 20) | .[0].client_ip)
| "deny = " + tojson
```

What these returned on the synthetic log (1,139 lines, 987 access records): the sweeping scanner sent
155 requests, 127 answered 429 and 133 sent after its first 429; 39 hit-and-run addresses; 13 WAF
rule/location/mode groups including the Host rule and two custom rules; the API-key principal seen
from three addresses, one of them new; the 502's request id joined to its `upstream unreachable`
event.

### Loki (LogQL)

On the Vector-normalised stream (`{job="eggrd", kind="access"|"event"}`). Range-vector queries are
best run as instant queries over the window you are investigating (`[6h]` here).

```logql
# Top offenders
topk(10, sum by (client_ip) (count_over_time({job="eggrd", kind="access"} | json client_ip [6h])))

# Probe paths
topk(20, sum by (target) (count_over_time({job="eggrd", kind="access"} | json target | target =~ "(?i).*(/\\.env|/\\.git|\\.php|/wp-|/cgi-bin|/actuator|\\.\\./).*" [6h])))

# Soft-200 probes
sum by (target) (count_over_time({job="eggrd", kind="access"} | json target, status, upstream | status = 200 and upstream != "" | target =~ "(?i).*(/\\.env|/\\.git|\\.php|/wp-).*" [6h]))

# 429s per address: each one is a request sent after being limited
topk(10, sum by (client_ip) (count_over_time({job="eggrd", kind="access"} | json client_ip, status | status = 429 [6h])))

# WAF hits by rule, location and address; blocks per minute
sum by (rule, location, client_ip) (count_over_time({job="eggrd", kind="event"} |= "WAF " | json rule, location, client_ip [6h]))
sum(count_over_time({job="eggrd", kind="event"} |= "WAF blocked" [1m]))

# 5xx per minute by route and outcome
sum by (route, outcome) (count_over_time({job="eggrd", kind="access"} | json route, outcome, status | status >= 500 [1m]))

# One principal's lines, and principals by address
{job="eggrd", kind="access"} | json principal | principal = "apikey:113179bb9bc261f2" | line_format "{{.ts}} {{.client_ip}} {{.method}} {{.target}} {{.status}}"
sum by (principal, client_ip) (count_over_time({job="eggrd", kind="access"} | json principal, client_ip | principal != "" [6h]))

# One request id, everywhere it appears
{job="eggrd"} |= "930c3bda-a5d4-4084-8083-b8bf19ff97d7"

# TLS and connection failures
sum by (message, reason) (count_over_time({job="eggrd", kind="event"} | json message, module, reason | module = "edgeguard::serve" or module =~ "rustls.*" [6h]))

# client_ip in private ranges (X-Forwarded-For fallbacks)
sum by (client_ip) (count_over_time({job="eggrd", kind="access"} | json client_ip | client_ip =~ "(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.).*" [6h]))

# Config and lifecycle events
{job="eggrd", kind="event"} | json message | message =~ "(?i).*(reload|listening|shutdown|stopped|acme|certificate).*"

# Method and IP refusals
sum by (outcome, method) (count_over_time({job="eggrd", kind="access"} | json outcome, method | outcome = "method_not_allowed" or outcome = "ip_denied" [6h]))
```
On Fluent Bit's stream (nested names), for example:
```logql
sum by (fields_client_ip) (count_over_time({job="eggrd"} | json | fields_message = "request" and fields_status = 429 [6h]))
sum by (fields_rule, fields_location) (count_over_time({job="eggrd"} | json | fields_message =~ "WAF.*" [6h]))
```
LogQL cannot compute "requests after the first 429" or "requests with ≤3 hits"; export the window
and use jq for those.

### CloudWatch Logs Insights

On a log group fed by Docker's `awslogs` driver (message = eggrd's JSON line). Written to the
Insights grammar, **not run here** (no AWS account was used).

```sql
-- Top offenders
filter `fields.message` = "request"
| stats count(*) as requests, count_distinct(`fields.path`) as paths by `fields.client_ip`
| sort requests desc
| limit 20

-- Probe paths
filter `fields.message` = "request" and `fields.path` like /(?i)(\/\.env|\/\.git|\.php|\/wp-|\/cgi-bin|\.\.\/)/
| stats count(*) as hits, count_distinct(`fields.client_ip`) as ips by `fields.path`, `fields.status`
| sort hits desc
| limit 50

-- 429s per address
filter `fields.message` = "request" and `fields.status` = 429
| stats count(*) as limited by `fields.client_ip`
| sort limited desc
| limit 20

-- WAF hits by rule, location, address
filter `fields.message` like /^WAF /
| stats count(*) as hits by `fields.rule`, `fields.location`, `fields.client_ip`, `fields.message`
| sort hits desc

-- 5xx by minute
filter `fields.message` = "request" and `fields.status` >= 500
| stats count(*) as errors by bin(1m), `fields.route`, `fields.outcome`

-- One principal's timeline
filter `fields.principal` = "apikey:113179bb9bc261f2"
| fields @timestamp, `fields.client_ip`, `fields.method`, `fields.path`, `fields.status`
| sort @timestamp asc

-- One request id
filter `fields.request_id` = "930c3bda-a5d4-4084-8083-b8bf19ff97d7"
| fields @timestamp, `fields.message`, `fields.status`, `fields.outcome`, `fields.path`

-- TLS and connection failures
filter target = "edgeguard::serve" or target like /rustls/
| stats count(*) by `fields.message`, `fields.reason`

-- X-Forwarded-For fallbacks: client_ip inside the VPC
filter `fields.message` = "request" and (isIpv4InSubnet(`fields.client_ip`, "10.0.0.0/8") or isIpv4InSubnet(`fields.client_ip`, "172.16.0.0/12") or isIpv4InSubnet(`fields.client_ip`, "192.168.0.0/16"))
| stats count(*) by `fields.client_ip`

-- Lifecycle and config events
filter `fields.message` like /reload|listening|shutdown|stopped|ACME|certificate/
| fields @timestamp, level, `fields.message`, `fields.error`
| sort @timestamp asc
```
For CRI-prefixed lines (the CloudWatch agent on Kubernetes), extract the fields you need first:
```sql
parse @message /"message":"(?<msg>[^"]+)".*"client_ip":"(?<client_ip>[^"]+)".*"status":(?<status>\d+)/
| filter msg = "request"
| stats count(*) as requests by client_ip
| sort requests desc
```
