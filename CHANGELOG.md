# Changelog

All notable changes to EdgeGuard are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0-rc.1] — 2026-11-02

A release candidate. 0.7.0 final will be cut from this same code after a soak, so it is published
as a prerelease: the crate as `0.7.0-rc.1`, and the image under the exact tag `0.7.0-rc.1` only,
with `latest` and `0.7` left where they are. Its themes are a hardening pass, mutual TLS on every
hop, API-usage monitoring, and hybrid connectivity (load-balanced upstream pools, PROXY protocol,
and client certificates forwarded by a TLS-terminating load balancer).

### Upgrading from 0.5

- **Connecting to an upstream now times out after 5 s** (`validation.upstream_connect_timeout`).
  An upstream that drops packets used to answer `504` after 30 s; it now answers `502` after 5 s.
  Set `"0"` to restore the old behaviour.
- **A client that sends its credential header twice now gets `401`.** This covers
  `Authorization` for `basic` and `jwt`, and the key header for `apikey`. A request like that used
  to be checked against one value and forwarded with another; see Security below. Under
  `auth.mode = "none"` or `"mtls"` duplicates are still forwarded.
- **A repeated header now reaches the app with every value, in order,** where it used to arrive
  with only its last value. An HTTP/2 client's several `Cookie` headers arrive as one, joined with
  `"; "`.
- **ACME requests time out:** 10 s to connect and 30 s per request. Before, they had no timeout.
- **A bad ACME client setting now fails at startup.** The client is built at startup even when a
  certificate is already on disk, so a directory that is not `https://`, an unreadable `ca_path` or
  a malformed proxy stops the edge then, rather than failing the renewal two months later.
- **Library users:** `UpstreamRoute` gained fields, and `ServeOpts` and `HealthCheckCfg` are new
  public structs that will keep growing. All three implement `Default`, so build them with
  `..Default::default()` rather than listing every field.
- **Every other new setting is off by default.** A 0.5 configuration loads and behaves as before.
  The exceptions are the changes listed above and the 30 s keep-alive idle limit described below.

### Security

- **A credential header sent twice could pass the edge with one value and reach the app
  with another.** The auth gate read the first `Authorization` (or API-key header), but the
  request was forwarded with the last, so an API key, Basic credentials or a JWT the edge checked
  could arrive at the app as a different token. An app that trusts the edge's check (decoding a
  JWT it does not verify again, telling tenants apart by key) would then act on a credential the
  edge never saw. Reproduced against the previous build: two `X-API-Key` headers, a valid one
  first, passed, and the upstream received only the second.
  - Whenever the edge authenticates with a header, a request carrying that header more than once
    is now refused with `401` and never reaches the app. The edge cannot know which copy the app
    will read, and RFC 9110 allows a client one.
  - Which header counts: `Authorization` for `basic` and `jwt`. For `apikey`, the configured
    header, and `Authorization` too when the key comes from it instead: the configured header
    absent, or holding bytes that are not text (found in review).
  - `mode = "none"` and `"mtls"` read no header, so they forward duplicates for the app to judge.
    An `apikey` request whose key is in its own header does the same for `Authorization`.

### Hardening (planned as 0.6.0)

0.6.0 was never released as a final version: only `0.6.0-beta.1` was cut, and it was never tagged.
Its hardening work ships here.

- **Connection limits on every listener** (`server.header_read_timeout`, `server.max_connections`).
  A connection that sent nothing, or sent its request a byte at a time, was held open forever on
  both the plain and the TLS listener: hyper's own 30 s header timeout needs a timer that was never
  installed, and its HTTP/1-or-2 check, which runs first, has no deadline at all. Every connection
  now has to deliver a complete request head within `header_read_timeout` (30 s), which also closes
  keep-alive connections left idle that long. The first bytes are read under that deadline before
  hyper sees them, so cleartext HTTP/2 with prior knowledge still works. `max_connections` (off by
  default) closes connections over the cap at accept. New series:
  `edgeguard_connections_open{listener}` and `edgeguard_connections_rejected_total{listener}`.
  The public, redirect and admin listeners now share one accept loop (`src/serve.rs`), so none of
  them can miss a protection the others have.
- **Last-known-good control-plane policy on disk** (`control_plane.cache_path`,
  `control_plane.boot_without_policy`). Managed mode's fail-static held only for the life of the
  process: an edge restarted while the control plane was unreachable came up on its local config
  file alone, typically looser than the pushed policy (no auth, WAF in report mode). Each applied
  policy is now also written to `cache_path` — `0600`, replaced atomically, never logged — and read
  back at startup before the listener binds. The first pull then sends its ETag, so an unchanged
  policy is a `304`. A cache for another control plane or tenant, from another format version, or
  that no longer builds is ignored and logged. `boot_without_policy = "refuse"` answers proxied
  requests and readiness with `503` until a policy arrives, health and metrics staying up (new
  outcome `no_policy`). `doctor` warns about managed mode without `cache_path` and a cache
  directory that does not exist. Proven with a stub control plane in `tests/policy_cache.rs`: the
  restart under an outage serves the pushed policy (and, without the cache, the local one).
- **Graceful drain** (`server.drain_delay`, `server.drain_timeout`). On `SIGTERM`,
  `/__edgeguard/ready` answers `503` at once while `/health` stays `200`. The public listener keeps
  accepting for `drain_delay` (default 0), then stops and lets in-flight requests finish for up to
  `drain_timeout` (25 s). Only then is a `--wrap`ped app stopped and the admin listener closed.
  `edgeguard doctor` warns when the drain is 30 s or longer, Kubernetes' default kill deadline, and
  when the header timeout is off.
- **Keep-alive connections idle for 30 s are closed** (by `server.header_read_timeout`). They
  used to be kept until the client closed them. Clients reconnect transparently; set a longer
  value, or `"0"` to restore the old behaviour.
- **HTTPS requests were cut on every restart.** The TLS listener returned as soon as shutdown was
  signalled, without waiting for its connections, and the process exited under them. It now
  drains like the plain listener did.
- **With `--wrap`, the app was stopped at the same moment as the listener**, so a request still in
  flight was answered `502`. Reproduced with the 0.6.0-beta.1 binary: a 2 s request in flight at
  `SIGTERM` got `502`, and `/ready` stopped answering instead of returning `503`. The app is now
  stopped after the drain, and the same request gets `200`.
- **In managed mode, editing the local config file dropped the pushed policy** until the control
  plane published a new one: the file reload rebuilt from the file alone, and the poller, holding
  the same ETag, kept getting `304`. The runtime is now built from both layers in one place, so a
  file edit keeps the pushed policy on top and a pushed policy keeps the file's edge-local sections.

### Added
- **A workload's identity as the LLM credential.** A `[[llm.keys]]` entry may name the `claims` of
  the request's verified JWT (`auth.mode = "jwt"`) in place of a `virtual_key`: a CI job presents
  its run's OIDC token, and the first entry whose every claim matches (by value, or by prefix with
  a trailing `*`) has its provider key injected upstream. The token never reaches the provider. A
  token whose claims match no entry is `401`. Such an entry needs `auth.jwt.issuer` and
  `auth.jwt.audience` set, and is refused at load without them.
- **A budget per claim** (`scope = "claim:<name>"`): `claim:run_id` holds each CI run to its own
  budget. Blocked requests count under `edgeguard_llm_budget_blocked_total{scope="claim"}`.
- **The access record says who called, where it went and how much moved** (schema 2). The line
  had request id, method, target, client IP, status, outcome and latency, so it could not answer
  "who made this request" or "was the edge or the app slow". Each record now also carries `route`,
  `principal`, `user_agent` (truncated to 256 bytes), `upstream` (`scheme://host:port`, no
  userinfo) and `upstream_ms`, `bytes_in`/`bytes_out`, `duration_ms`, and `tls_version` /
  `client_cert` when EdgeGuard terminates TLS. `log.principal = "full" | "hash" | "off"` decides
  how the caller is written. The shipped record gains `schema: 2` and keeps every key, `null` when
  it does not apply; a test pins the key set. Existing fields keep their names and meaning.
- **API usage by route and by consumer.** Request metrics had one dimension, `outcome`: there was no
  way to see which endpoint was slow or failing, or who was calling. New series:
  - `edgeguard_route_requests_total{route,method,status_class}`, with a latency histogram
    `edgeguard_route_request_duration_seconds{route}`. `route` is a configured label, never the
    request path: the longest matching `[[upstreams]]` or `[[ratelimit.routes]]` prefix, named
    by a new optional `name` or by the prefix, else `default`. Non-standard methods are `OTHER`.
    So the series count is set by the config. Proven by 1,000 random paths producing exactly the
    configured labels plus `default`.
  - `edgeguard_consumer_requests_total{consumer,status_class}` and
    `edgeguard_consumer_bytes_total{consumer,direction}`, keyed by the authenticated principal
    (`apikey:<id>`, never the key; the Basic user; the JWT `sub`; the client certificate's name),
    `_anon` without one. Capped by `metrics.consumer_series_max` (100), the rest sharing
    `_over_cap`; `0` turns them off. Bytes are counted on the buffered and the streamed response
    paths alike.

  Every request is counted on both, the edge's own `401`/`429` included, so the route, consumer
  and `edgeguard_requests_total` totals agree. Recording takes no lock: the counters are atomics
  reached through a read-mostly map. They sit outside the hot-swappable policy, so a reload does
  not reset them.
- **Balancing and failover across upstreams** (`[[upstreams]] targets`). A prefix could name one
  upstream, so spreading load over two servers, or an on-prem primary with a cloud standby, needed
  a load balancer in between.
  - **Pools:** `targets = [...]` instead of `target`. `path = "/"` puts the whole app behind a
    pool.
  - **Balance:** with `balance = "priority"` (the default), each request goes to the first target
    in rotation, in the order listed. With `"round_robin"`, requests take the targets in rotation
    in turn.
  - **Least connections:** `balance = "least_conn"` sends each request to the target in rotation
    with the fewest requests in flight for its weight, the least `(in flight + 1) / weight`.
    - Ties are taken in turn, so an idle pool still spreads requests.
    - A request is in flight until its response has been read, streamed bodies to their last
      byte. A WebSocket tunnel counts until it closes.
    - Only these pools count, so others pay nothing.
    - The count is `edgeguard_upstream_in_flight{route,upstream}`, and `in_flight` in the status.
  - **Weights:** an entry may be `{ url = "…", weight = 3 }` instead of a bare URL, giving that
    target three turns for each one a weight-1 target gets (round-robin), or three times the
    in-flight requests (least-connections).
    - Turns interleave: weights 3, 1, 2 go a, b, c, a, c, a.
    - Each cycle gives every target in rotation exactly its share, so a target out of rotation
      leaves the rest their ratio.
    - The pick is computed from the turn counter, with no lock.
    - A misspelled key in the table, a weight of 0, or a weight with `balance = "priority"` fails
      at load.
  - **Hashing:** `balance = "hash"` sends each request to the target its key ranks first, so the
    same key reaches the same target.
    - `hash_on` names the key: `"client_ip"` (default), `"path"`, `"header:<name>"`,
      `"cookie:<name>"` or `"query:<name>"`. A request without it is balanced in turn.
    - `"query:<name>"` hashes the first `<name>=` value as sent, not percent-decoded (HAProxy's
      `url_param`). An empty one counts as none, wherever the parameter sits in the query.
    - Ranking is rendezvous hashing with a fixed hash function, so every edge, of any version,
      ranks a key the same way with nothing shared, and a test pins the function.
    - A target leaving rotation moves only its own keys, each to its next-ranked target, which is
      also where a request goes when its target refuses the connection. Weights give a target its
      share of keys.
  - **Sticky sessions:** `sticky_cookie = "<name>"` keeps a client on the target that answered it.
    - The edge sets the cookie (`Path` set to the prefix, `HttpOnly`, `SameSite=Lax`, `Secure` as
      for every cookie) to a hash of the target's URL, shown as `sticky_cookie_value` in the
      status. Any edge reads another's.
    - A request carrying it goes to that target while it is in rotation, ahead of `balance`. One
      naming a target out of rotation is balanced as usual, and the cookie is replaced.
    - A backup target it names waits until no main target is in rotation. A WebSocket handshake
      follows the cookie but does not set it.
    - `sticky_cookie_max_age = "8h"` gives it a `Max-Age`, so a client stays across browser
      restarts. It counts from when the cookie was set and is not refreshed, so an active client
      is rebalanced when it runs out. Empty keeps a session cookie.
    - `sticky_cookie_strip = true` removes it from requests before the upstream sees them,
      WebSocket handshakes included, keeping the client's other cookies (HAProxy's `indirect`).
      What is left goes as one `Cookie` header, and a request without the cookie is untouched.
  - **Backup:** `backup = [...]` targets take requests only when no target in `targets` is in
    rotation, or when all of them refused the request.
  - **Failover:** a request that cannot connect to its target (refused, unreachable, past the new
    connect timeout, a failed TLS handshake) reached nothing, so it is sent to the next target,
    the backups last.
    That holds for a buffered body and for a WebSocket handshake, but not for a streamed body,
    which cannot be sent twice. A request that got an answer, even a `5xx`, is never retried.
  - **Ejection:** after `eject_after` (1) such failures in a row, a target is out of rotation for
    `eject_for` (30 s).
    - Repeat ejections grow: `eject_for` × the ejections in a row, up to `eject_for_max` (5 min,
      or `eject_for` if longer).
    - A target not ejected again for `eject_for_max` after its last ejection ends starts over.
    - The status shows `ejections_in_a_row` and each ejection's `length_s`.
  - **5xx ejection:** with `eject_after_5xx` (off by default), that many `5xx` answers in a row
    eject a target too: one that is up but broken. Any other answer resets the count. It never
    takes out the last target in rotation, since when every target answers `5xx` rotation can't
    help, and readiness would fail for the app's fault. Each `5xx` still reaches its client.
  - **Health checks:** `[upstreams.health_check]` `path` is fetched from each target every
    `interval` (5 s). A target is out after `unhealthy_after` (2) failures and back after
    `healthy_after` (2) passes. An answer in `expect_status` within `timeout` (2 s) passes.
    `expect_status` takes codes, ranges and classes (`"200,204"`, `"2xx"`; default `"200-399"`),
    and a failed check's reason names both.
    - `expect_body = '"status":"ok"'` also requires that text within the body's first 64 KiB,
      for an endpoint that answers `200` while saying it is degraded. The text may arrive split
      over several reads.
    - `expect_body_regex` matches a regular expression instead, in linear time whatever the
      pattern. It is matched once the body has ended or reached 64 KiB, never on part of it, so
      `^ok$` cannot pass on a body that only starts with `ok`.
    - `method` (default `GET`; `HEAD` for the status alone, never `CONNECT`) and `headers`
      (`[["Host", "app.internal"]]`, a token) shape the request. A `User-Agent` among them
      replaces the edge's, and headers about a body or a connection fail at load. The status
      endpoint shows header names, never values.
    - `port = 8081` checks each target on another port, for an app whose health lives on a
      separate management port. HTTP or TCP, with the target's host, scheme and path kept, and
      for an `https://` target the TLS settings its requests use (its `[[upstream_tls.targets]]`
      entry included). The target is still named and ejected by the port requests use.
    - `type = "tcp"` only connects to each target's host and port, for a target with no health
      endpoint. HTTP settings set with it fail at load, since they would do nothing.
    - A check's log line names the target by label, never by its configured URL.
  - **Nothing in rotation:** requests try every target in order anyway, and
    `/__edgeguard/ready` answers `503` for a pool at `"/"`.
  - **Reloads:** pools are reloadable, and a reload keeps each kept target's health, so it neither
    restores an ejected target nor restarts its checks.
  - **TLS:** each `https://` target takes its own `[[upstream_tls.targets]]` settings.
  - **Visibility:**
    - `edgeguard_upstream_in_rotation{route,upstream}`,
      `edgeguard_upstream_health_checks_total{route,upstream,result}` and
      `edgeguard_upstream_ejections_total{route,upstream,reason}`.
    - Alerts: `EdgeGuardUpstreamTargetOut` (warning), `EdgeGuardUpstreamPoolDown` (critical), and
      `EdgeGuardUpstreamTargetFlapping` (warning: ejected 3 times in 15m), with promtool tests. `EdgeGuardUpstreamNotAnswering` no longer fires for a pool's targets,
      whose requests fail over.
    - Three dashboard panels (bundle 1.6.0), and log lines when a target leaves or rejoins.
    - `doctor` warns on a pool that cannot tell a target is gone.
    - `GET /__edgeguard/upstreams`, an ops endpoint (admin port in split mode), shows every route:
      - each target, by `scheme://host:port` and never the configured URL with any credentials;
      - each target's request counts by result;
      - for a pool, its `balance` and `state` (`normal`, `backup`, `all_out`);
      - for each pool target, whether it is in rotation and, if not, why: its last health check
        (time, result), or what ejected it and how long it stays out.

      Reading it does not advance round-robin.
  - `UpstreamRoute` gains fields, so a struct literal needs `..Default::default()`.
- **The client's address from an L4 load balancer** (`server.proxy_protocol`). A balancer that
  passes TCP through without keeping the client's address cannot add `X-Forwarded-For`. Behind
  one (an AWS NLB with IP targets, HAProxy `mode tcp`, nginx `stream`, a GCP TCP proxy), every
  connection came from the balancer. Rate limits were shared by every client, `[access]` rules
  saw one address, and so did the logs.
  - **Reading:** with `proxy_protocol = true`, the public and redirect listeners read a PROXY
    protocol header (v1 or v2) first, before the TLS handshake on a TLS listener. They serve the
    connection as the client it names: rate limits, `[access]`, `X-Forwarded-For`, the access log
    and spans see it. v2 TLVs (an AWS VPC endpoint id) are skipped. Only the bytes needed to tell
    a header from a request are read, so a connection without one loses nothing and cleartext
    HTTP/2 still works.
  - **Trust:** a header is believed only from `proxy_protocol_trusted`, which is required; a `/0`
    is refused. From any other peer a connection that starts with one is closed, because it would
    be a client choosing its own address. One that does not is served as it is. A header that
    names no client (v2 `LOCAL`, v1 `UNKNOWN`: the balancer's health check) is served as the
    balancer, and so is a trusted peer without one. A header that does not parse, or nothing
    within `header_read_timeout`, closes the connection. The admin listener never reads one.
  - **Certificate header:** `[trusted_client_cert_header]` stays trusted by the connection's own
    peer, the hop that wrote it, not the client a PROXY header names. Requests carry that peer as
    the `TcpPeer` extension.
  - **Visibility:**
    - `edgeguard_proxy_protocol_total{listener,result}` (`proxied`, `local`, `missing`, `direct`,
      `untrusted`, `invalid`, `timeout`).
    - Alerts: `EdgeGuardProxyProtocolRefused` for the balancer being cut off, and
      `EdgeGuardProxyProtocolMissing` for a balancer sending no headers. Both have promtool tests.
    - A dashboard panel (bundle 1.4.0).
    - `doctor` reports settings that refuse startup. It warns on `trust_forwarded_for` alongside
      it, and on a certificate header trusted from the PROXY balancer.
  - `docs/DEPLOYMENT.md` gains where the client's address is behind each kind of balancer, and
    each balancer's setting.
  - `ServeOpts` gains a `proxy_protocol` field.
- **Client certificates from a TLS-terminating load balancer** (`[trusted_client_cert_header]`).
  Behind an L7 balancer the client's TLS ends at the balancer, so mutual TLS could not work: the
  certificate never reached the edge. Balancers that do the mTLS themselves forward it in a header.
  - **Formats:** `format = "pem"` (URL-encoded or not: ALB, nginx), `"der"` (base64, URL-escaped
    or not: HAProxy, Traefik) and `"xfcc"` (Envoy, Istio, with or without `Cert`).
  - **Trust:** the header is believed only from `trusted_proxies`, matched against the
    connection's own peer, never `X-Forwarded-For`; a `/0` is refused. It is removed before
    forwarding whoever sent it.
  - **Trust by name:** `trusted_proxy_names` trusts the balancer by the TLS client certificate it
    presents, verified by `[tls.client_auth]`, rather than by its address. That is the answer for
    a shared edge network, where everyone's traffic shares the balancer's ranges.
    - Exact names or prefixes ending in `*`, as `[auth.mtls] allowed`.
    - With `trusted_proxies` too, both must match.
    - Set without `[tls.client_auth]`, or set to a bare `*`, it fails at load.
    - `GET /__edgeguard/tls` and the startup log list them. The `untrusted_peer` metric help and
      the dashboard panel's description say what it now covers (bundle 1.6.1).
  - **Use:** from a trusted peer it is the request's client certificate. `auth.mode = "mtls"`,
    `[auth.mtls] allowed`, `forward_client_cert = "xfcc"`, the access log and the consumer series
    take it, and the first two no longer need `[tls.client_auth]`.
  - **The balancer's own certificate is never the client's:** from a trusted peer, a request
    without the header, or with one refused, has no client certificate, even when the balancer
    presented one in its TLS handshake.
  - **Verification:** `ca_path`/`crl_paths` re-verify it for a balancer that forwards unchecked.
    They are watched, and in the certificate series as `header-ca:<CN>`.
  - **Visibility:** `edgeguard_client_cert_header_total{result}` (`accepted`, `untrusted_peer`,
    `invalid`, `unverified`), the `EdgeGuardClientCertHeaderRefused` alert with a promtool test,
    and a dashboard panel (bundle 1.3.0). `GET /__edgeguard/tls` reports the settings. `doctor`
    flags settings that refuse startup, and a header nothing requires.
  - **Edge-local:** a pushed policy cannot change it.
  - **Docs:** `docs/DEPLOYMENT.md` gains the matrix of what in front of the edge allows what, with
    each balancer's header and format. It also explains why a shared edge network's addresses are
    not enough on their own.
  - **Proven** in `tests/client_cert_header.rs`, one case per format, from an untrusted peer,
    garbage and duplicates, with `ca_path` and a CRL. The tests caught that base64 starting with
    a DER byte was taken for a certificate; the header path now parses it fully, as the handshake
    does.
- **Visibility for the certificates the edge depends on beyond the one it serves.**
  - **The client certificates it presents.** Upstream, control plane, collectors, JWKS, alerts:
    each appears in the expiry series as `cert="client:<path>"`, so the existing
    `EdgeGuardCertExpiringSoon` alert fires for one with no rule change (a promtool test proves
    it). They are listed in `GET /__edgeguard/tls` under `client_certs`, with `used_by`, and
    `doctor` warns 21 days ahead. Reported only while something presents the certificate, so a
    pair a reload stopped using drops out rather than paging about a file nothing reads. They
    show even when the listener serves plain HTTP, and the endpoint answers then too.
  - **The CAs in `tls.client_auth.ca_path`.** `cert="client-ca:<CN>"`, listed in the endpoint's
    `client_auth.cas`, with a `doctor` warning before one expires.
  - **CRL staleness.** `edgeguard_tls_crl_next_update_seconds{crl}`, `client_auth.crls[].stale`,
    a `doctor` warning, and the `EdgeGuardCrlStale` alert. rustls goes on using a CRL past its
    `nextUpdate`, so revocations since it are not applied. Nothing said so before.
  - Monitoring bundle 1.2.0 adds that alert and a CRL panel, and labels the overview's days-left
    panel by `cert`. Proven in `tests/cert_visibility.rs`, and live against OpenSSL-made
    certificates and an overdue CRL.
- **Monitoring bundle 1.1.0: an API usage dashboard and five alerts.**
  - **The dashboard** (`monitoring/grafana/dashboards/edgeguard-api-usage.json`) shows per-route
    rate, 5xx ratio and p99, per-upstream error ratio, failures by result and time to headers,
    the edge's own overhead, connections against the cap, refused client certificates, and the
    top consumers by requests, bytes and errors.
  - **The alerts** (group `edgeguard-api`): `EdgeGuardUpstreamErrorRatio` (over 5% for 5m, with a
    traffic floor), `EdgeGuardUpstreamNotAnswering` (no answers for 5m, at any traffic level),
    `EdgeGuardRouteLatencyRegression` (p99 over 250ms and double the same hour yesterday; a
    recent baseline would absorb the regression within minutes), `EdgeGuardConnectionsNearCap`
    (over 80% of `server.max_connections`) and `EdgeGuardClientCertRejectSpike`.
  - **Unit tests** in `monitoring/prometheus/alerts.test.yml` cover a firing input and inputs
    that must stay quiet for each alert.
  - **The bundle check** now runs those tests and parses every dashboard query with promtool. It
    also fails when a rule or panel names a metric the crate does not export, when panels overlap
    or miss the datasource variable, and when an `edgeguard-api` alert has no test.
  - Two series the dashboard and alerts need: `edgeguard_connections_max{listener}`, set for
    listeners with a cap, and `edgeguard_edge_overhead_seconds`. The overhead is the time to
    response headers less the wait on the upstream (headers, and the body when buffered), with
    buckets from 100 µs.
- **Per-upstream health** (`edgeguard_upstream_requests_total{upstream,result}`,
  `edgeguard_upstream_duration_seconds{upstream}`). An upstream failure showed only as an edge
  `outcome` (`upstream_error`, `upstream_timeout`), with no way to tell which upstream or why.
  Each exchange is now counted by upstream (`scheme://host:port`, as the access log's
  `upstream`) and by result: `ok`, `http_5xx`, `connect_error`, `tls_error` (TLS errors are
  found anywhere in the error chain), `timeout`, `reset` (a body cut short included) and
  `error`. Every result is written from an upstream's first request, so an error ratio is defined
  from the start. The histogram is the time to the upstream's headers, from the same reading as the
  access log's `upstream_ms`. Requests the edge answers or cuts short itself are not counted, and
  a body over `max_response_body` counts as an answer. Proven in `tests/upstream_metrics.rs`: a
  stopped upstream, a hung one, one that closes without answering, one that cuts its body short
  (with and without a response cap), an untrusted TLS one, a `503`, a streamed response and a
  refused WebSocket handshake, plus agreement with the access log to within a millisecond.
- **The same private-CA, client-certificate and proxy settings on every outbound client.**
  `ca_path`, `client_cert_path`/`client_key_path` and `proxy` now work, with the same meaning, in
  `[log.ship]`, `[tracing]`, `[metrics.otlp]`, `[auth.jwt]` (the JWKS fetch), `[alerts]`,
  `[llm.telemetry]` and `[tls.acme.dns]`, as well as `[control_plane]`. Each of those clients
  previously trusted only the public roots and the process-wide `HTTPS_PROXY`, so a collector or
  an identity provider on a corporate CA was unreachable. A certificate file pair is loaded once
  per process, whichever client names it, and watched once. Clients a config reload rebuilds
  present the same watched store, so a rotation reaches them without a reload. The JWKS fetch
  settings are edge-local: a pushed policy can change `jwks_url` but not how it is reached.
  Settings that do not load fail at startup and are reported by `doctor`. The log shipper, span
  shipper and OTLP exporter used to start silently without a client in that case. Their failure
  logs now carry the TLS cause (`UnknownIssuer`, `CertificateRequired`). Proven against a TLS
  endpoint that requires client certificates, one test per client, in `tests/outbound_tls.rs`.
  - **Defaults, written once** (`[outbound]`): `proxy`, `client_cert_path`/`client_key_path` and
    `extra_ca_path` apply to every one of those sections that leaves its own key empty, so an
    egress proxy or the edge's identity is set in one place rather than eight. A section's own
    value always wins, key by key. A certificate is inherited only as a pair, never half from
    each. `proxy = "none"` in a section opts it out of the proxy.
  - **No replacing CA as a default.** `extra_ca_path` is trusted beside the public roots, not
    instead of them, so the default reaches a public endpoint (an alert webhook on a chat
    service, a SaaS JWKS) without breaking it. `[outbound] ca_path` is refused at startup with
    that reason, rather than ignored. A section that should trust only a private CA keeps its
    own `ca_path`.
  - **TLS defaults reach `https://` URLs only.** On a plain `http://` URL they are left out rather
    than refused, unlike a section's own. `doctor` warns when a section on plain `http://` to
    another machine would otherwise have taken them.
  - **Checked and visible.** `[outbound]` is checked at startup, on every reload and by `doctor`,
    whether or not anything uses it yet. An inherited setting that fails names both places
    (`outbound.client_cert_path (inherited by log.ship)`). `doctor` and the startup log say which
    sections take which keys. An inherited certificate is linted for expiry once, and
    `GET /__edgeguard/tls` lists every section that presents it.
  - **Edge-local:** a control-plane policy cannot change it, since a pushed proxy plus a pushed CA
    could read every connection the edge opens, its own included. Upstreams (`[upstream_tls]`)
    do not use it.
  - Tested from a config file through `Config::load`: the sections that set nothing reach a
    private-CA endpoint that requires a client certificate, through a `CONNECT` proxy. One with
    `proxy = "none"` goes direct, and one with its own `ca_path` trusts only that.
- **ACME through an egress proxy** (`[tls.acme]` `proxy`, `ca_path`,
  `client_cert_path`/`client_key_path`, and `[outbound]`). instant-acme's own HTTP client honoured
  no proxy at all, not even `HTTPS_PROXY`. An edge whose only way out is an egress proxy therefore
  could not obtain or renew a certificate. Every ACME request (directory, account, orders,
  challenges, certificate download, renewal information) now goes out on the same outbound client
  as everything else the edge calls.
  - **Proxy:** `[tls.acme] proxy`, the `[outbound]` default, or `HTTPS_PROXY`/`NO_PROXY`, through a
    `CONNECT` tunnel with TLS end to end.
  - **Trust is unchanged by default:** with no `ca_path`, the directory is still verified against
    the operating system's trust store, not the roots built into the binary, so a private ACME CA
    whose root is installed on the host keeps working. `[outbound] extra_ca_path` is added to that
    store. `[tls.acme] ca_path` replaces it with one CA bundle, which suits Pebble or step-ca
    without touching the host.
  - **Fails early:** the client is built at startup even when a certificate is on disk, so a bad
    `ca_path` or proxy, or a directory that is not `https://`, is caught now rather than at the
    renewal two months later. `doctor` checks it too. Each request times out after 30 s, where
    instant-acme's client had no timeout. Every URL the directory hands out must be `https://`,
    as before.
  - Tested against a stub ACME server on a private CA, through `obtain_certificate`: registration
    and the refused order go through a `CONNECT` proxy with the JWS intact. The inherited
    `[outbound]` CA and proxy work, as does `proxy = "none"`. With nothing set the CA is trusted
    only once it is in the system store (`SSL_CERT_FILE`), and a directory pointing at plain
    `http://` gets no request. Run live against a fake ACME server through a proxy, both from
    `[tls.acme]` and from `HTTPS_PROXY` + `SSL_CERT_FILE` alone, in `tests/acme_client.rs`.
- **A control plane behind a private CA, client-certificate identity, and an egress proxy**
  (`control_plane.ca_path`, `client_cert_path`/`client_key_path`, `proxy`). The managed-mode
  client trusted only the public web PKI, presented no certificate and could reach the control
  plane only through the process-wide `HTTPS_PROXY`, so a self-hosted control plane on a corporate
  CA was unreachable. `ca_path` replaces the public roots for this connection. The client
  certificate is presented to a control plane that requires one. The bearer token is still sent:
  the certificate identifies the edge and the token binds it to the tenant. The certificate is
  re-read when it changes on disk, and the next request presents the new one. A client that
  presents a certificate neither resumes TLS sessions nor keeps idle connections, because both
  would carry the old certificate past a rotation; the live run caught each in turn. It gets the
  same expiry warnings as the listener's. `proxy = "http://…"` routes this client alone through a `CONNECT`
  proxy, with TLS end to end through the tunnel. `proxy = "none"` ignores the environment. The
  private settings with an `http://` URL are a startup error. `doctor` warns about plain `http://`
  to a control plane on another machine. Proven against a TLS control-plane stub that requires
  client certificates, directly and through a `CONNECT` proxy stub, in `tests/cp_tls.rs`.
- **Client certificates on the TLS listener: mutual TLS** (`[tls.client_auth]`, `auth.mode =
  "mtls"`). The listener verified no client certificates. Now `mode = "required"` refuses any
  handshake without a certificate from a CA in `ca_path`. `"optional"` verifies one if presented.
  `crl_paths` refuses revoked certificates. The CA bundle and CRLs reload when they change on disk,
  so a revocation applies to the next connection with no restart. **TLS session resumption is off
  while this is on**: a resumed session is not verified again, so a certificate revoked after its
  first connection kept connecting — reproduced in the tests, which fail with resumption back on.
  `auth.mode = "mtls"` authenticates by the certificate: `[auth.mtls] allowed` narrows it to names
  (exact, or a `*` prefix such as `spiffe://prod.example/ns/web/*`), and the first allowed name —
  URI (SPIFFE ID), DNS, email, then CN — is the principal per-key limits and budgets key on.
  `forward_client_cert = "xfcc"` sends the app `X-Forwarded-Client-Cert` with the certificate's
  SHA-256 and names; a client's own copy of that header is always removed while client
  authentication is on. Refusals are counted in a new series,
  `edgeguard_tls_handshake_failures_total{listener,reason}` (`client_cert`, `timeout`, `other`),
  since a refused handshake never reaches the request log. `auth.mode = "mtls"` without
  `[tls.client_auth]` is refused at load, so a pushed policy cannot ask for it either, and
  `doctor` reports client authentication without TLS, a CA or CRL that will not load, and
  `"optional"` with nothing reading the certificate. Names are read by the existing DER walker; the
  verifier is rustls's own. The only new dependency edge is `ring`, the provider already in use, for
  the fingerprint.
- **TLS and mutual TLS to upstreams** (`[upstream_tls]`). The upstream client spoke plain HTTP
  only: an `https://` upstream loaded without complaint, then every request was answered `502`
  and the upstream never saw a connection. `https://` upstreams now work with no configuration,
  verified against the public web PKI (the Mozilla roots, compiled in, so a distroless image needs
  no CA bundle). `ca_path` trusts only a private CA instead. `cert_path`/`key_path` present a client
  certificate to upstreams that require one, reloaded when the files change and warned about as
  they near expiry. A connection that presents one never resumes a TLS session, because a resumed
  session carries the certificate of the handshake it resumes: an upstream that issues tickets
  went on seeing the replaced certificate after a rotation (reproduced in the tests). `server_name` verifies an upstream dialled by IP against the name on its
  certificate. `[[upstream_tls.targets]]` gives one upstream its own settings. There is no option
  to skip verification. Edge-local: a control-plane policy cannot change it. WebSocket tunnels use
  it too. Built on tokio-rustls, already a dependency; the only new edge is `webpki-roots`, which
  reqwest already compiled in. Proven against rustls upstreams in `tests/upstream_tls.rs`: private
  CA, refused public-roots and wrong-CA cases, required client certificates, a name mismatch by IP,
  two upstreams with different CAs, and a client certificate replaced on disk.

### Changed
- **Connecting to an upstream times out after 5 s** (`validation.upstream_connect_timeout`, new).
  It was bounded only by `upstream_timeout`, so an upstream whose packets are dropped (a
  partitioned network, a firewall) held each request for 30 s before a `504`. It now fails after
  5 s with `502` (`connect_error`), which is also what lets a pool move on in time. For an
  `https://` upstream it covers the TLS handshake too, so one that accepts the connection and
  never answers the handshake fails the same way. `"0"` restores the old behaviour.
- **A streamed response's access line is written when its last byte is sent**, rather than when
  its headers were, so its `bytes_out` and `duration_ms` are what was actually sent. `latency_ms`
  keeps its meaning, the time to the response headers. A long stream's line now appears when the
  stream ends.
- **An upstream URL that is not `http://` or `https://` fails at load** (`server.upstream`,
  `[[upstreams]] target`). It used to load and then answer every request with `502`.
- **Upstream connection errors are logged with their cause**: `client error (Connect): invalid peer
  certificate: UnknownIssuer` rather than hyper's bare `client error (Connect)`.

### Fixed
- **A header sent more than once reached the upstream with only its last value.** Headers were
  copied to the upstream request one value at a time with a replacing insert, so `Accept` sent
  twice, or any repeated field, lost all but its last value, on proxied requests and WebSocket
  handshakes alike. Every value is now forwarded, in the order sent.
  - Several `Cookie` headers become one, joined with `"; "`, as RFC 9113 §8.2.3 asks of a hop
    from HTTP/2 to HTTP/1.1. That is how HTTP/2 clients (the plain listener accepts h2c) send
    cookies, and until now an h2c client's request reached the app with one cookie.
  - Headers the edge sets itself (`X-Forwarded-For`, `X-Forwarded-Proto`, the request id,
    `traceparent`, a key-vault `Authorization`) still replace every value the client sent.
  - Tested over HTTP/1.1, HTTP/2 with prior knowledge and a WebSocket handshake, in
    `tests/header_forwarding.rs`.
- **A `[[upstreams]]` route at `path = "/"` delayed startup by 30 s.** With no `server.upstream`,
  startup waited for the local `app_port` to accept connections. A `/` route sends it no
  requests, so the wait was pointless, and the startup log named that unused upstream. Startup no
  longer waits unless `--wrap` started the app, and the log names the route's upstreams.

## [0.5.0] — 2026-10-02

### Added
- **ACME Renewal Information (ARI, RFC 9773)** (`tls.acme.ari`, on by default). Renewal still
  happens at two-thirds of a certificate's lifetime, and now also when the CA's suggested window
  opens earlier, which is how a CA asks for certificates to be replaced after an incident. The
  window can bring renewal forward but never push it later. The point inside the window is fixed
  per certificate, so hourly checks do not re-roll it. Renewal orders name the certificate they
  replace, which some CAs exempt from rate limits, and fall back to a plain order if the CA refuses.
  The ARI identifier is read by the existing DER walker, so no X.509 crate is added. `GET
  /__edgeguard/tls` shows `ari_renew_at`. Proven against Pebble in the `acme-pebble` job: window read
  for an issued certificate, then a renewal naming it.
- **Monitoring as a versioned bundle.** `monitoring/VERSION` (1.0.0) versions the alert rules and
  the Grafana dashboards together, with a SemVer policy in `monitoring/README.md` (rename or remove
  is major, a new alert or panel minor, a threshold or wording patch). The Enterprise control-plane
  Helm chart (0.5.0) can now install them as a `PrometheusRule` and a Grafana-sidecar dashboards
  ConfigMap, both off by default and stamped with the bundle version. CI validates the rules with
  promtool, checks the dashboards, fails if the chart's copy drifts from `monitoring/`, and packs
  `eggrd-monitoring-<version>.tar.gz`.
- **Streaming documented end to end.** A README "Streaming" section, and a table in
  `docs/CONFIG.md` of exactly which features keep a request or response buffered with streaming
  on. `docs/ROADMAP.md` marks the "the real fix is streaming" gap closed.
- **Streamed uploads inspected on a bounded window** (`[[validation.stream_inspect]]`, opt-in per
  route). With `stream_requests` on, a WAF body rule or inbound DLP still forced an upload to
  buffer. A listed route now streams anyway. The WAF and DLP inspect the first `window` bytes
  before anything reaches the upstream, so a match there is a clean `403`. Every later frame is
  then scanned as it passes, with `overlap` bytes carried between frames, and a blocking match cuts
  the upload with a `403`. Weaker than whole-body inspection, and documented as such: a match
  longer than the overlap across a frame boundary is missed, and a block in the tail comes after the
  upstream has seen the start of the upload. DLP `redact` and LLM routes keep buffering.
- **Community files.** A Code of Conduct (Contributor Covenant 2.1), issue forms for bugs and
  feature requests, and a pull request template. The issue chooser points security reports to
  private vulnerability reporting rather than a public issue.
- **Cloudflare Worker built and run in CI.** `scripts/worker-check.sh` builds the worker's
  deployable bundle with `worker-build --release`, from a newly committed `worker/Cargo.lock`, and
  serves it on workerd, the runtime Cloudflare runs. It checks that a request without credentials
  or with a wrong password gets `401` without reaching the origin, and that the right credentials
  get the origin's `200` with the hardening headers added and `Server` stripped. `worker-build`
  and `wrangler` are pinned. A Cloudflare deploy is still untested. `docs/ROADMAP.md` no longer
  says the build is broken: that failure was `strip = true`, fixed earlier.
- **Live-Redis tests in CI.** The Redis-backed rate limiter and LLM budget tests were `#[ignore]`d
  and ran nowhere. `scripts/redis-live-test.sh` starts a Redis, runs them, and fails if any of them
  skipped. It runs in CI here and in the public repository's `ci.yml`.
- **OTLP metrics export** (`[metrics.otlp]`, off by default). Metrics were Prometheus-scrape only,
  which leaves out a pipeline that collects with OpenTelemetry and does not scrape. Every metric
  `/__edgeguard/metrics` serves is now pushed as OTLP-JSON to a `/v1/metrics` endpoint on an
  interval, plus once on shutdown. It is converted from the Prometheus exposition itself rather than
  instrumented twice, so the two cannot disagree and a new metric needs no second change. Counters
  become cumulative monotonic Sums, gauges become Gauges, and the request-duration histogram becomes
  an OTLP Histogram (per-bucket counts with explicit bounds). Edge-local like `[tracing]`: a pushed
  policy cannot repoint it. Proven with the real binary pushing to a stub collector: 17 families, the
  request counter and histogram matching the traffic sent. `[tracing]` (one SERVER span per request,
  shipped earlier) is now documented in `docs/CONFIG.md` alongside it.
- **ACME over DNS-01, and wildcard certificates** (`tls.acme.challenge = "dns-01"`). HTTP-01 was the
  only challenge, so a wildcard could never be issued and a host the CA cannot reach on :80 could
  not be certified. A DNS-01 order publishes `_acme-challenge` TXT records through `[tls.acme.dns]`,
  waits `propagation_secs`, then answers. Its records are removed afterwards whatever the outcome,
  and nothing binds :80. The first provider is **Cloudflare** (zone id plus a token scoped to
  `Zone.DNS:Edit`, read from the environment variable `api_token_env` names, never from the config
  and never logged or included in errors). `challtestsrv` drives Pebble's test DNS server.
  Renewal uses the same challenge. A wildcard over HTTP-01, an unknown challenge, or a provider
  that cannot be built (no zone, unset token) fails before any order is sent or budget spent, and
  `edgeguard doctor` reports each. Proof: provider requests against recorded API shapes, and a
  DNS-01 wildcard order against Pebble in the `acme-pebble` CI job, which now also fails if that
  test skips.
- **Several certificates on one listener, chosen by hostname (SNI).** `[[tls.certs]]` entries
  (`cert_path`, `key_path`, `hosts`) add pairs to the TLS listener; the `[tls]` pair stays the
  default for any other name and for clients that send none, so self-signed and ACME keep working
  as before. Matching is exact name first, then a one-label wildcard (`*.example.com`), then the
  default, case-insensitively. Each extra pair is its own live store, so it is watched, reloaded
  and swapped on its own (proven over real handshakes: replacing one pair on disk changed only that
  hostname's certificate). Its expiry is checked hourly and warned about, but nothing here renews
  it. `GET /__edgeguard/tls` lists them under `sni`, and the certificate metrics gain one series
  per pair labelled `cert="<first host>"`. The default pair's series are unchanged, so existing
  alerts and dashboards keep working and the expiry alerts now cover the extra pairs too. Host
  patterns that cannot match as written (empty, wildcard not in the first label, a name claimed
  twice) fail startup, and `edgeguard doctor` reports them first.
- **Request bodies can stream** (`validation.stream_requests`, off by default). Every upload was
  read whole into memory before a byte went upstream, so `max_body` (2 MiB by default) capped
  uploads for everyone. With the switch on, a request body is forwarded as it arrives whenever
  nothing reads it first. A WAF rule targeting the body, inbound DLP and the LLM features (metering,
  key vault, budgets) still buffer, decided by `streams_request` with a test per reader.
  `max_body` still holds: a declared `Content-Length` over it gets `413` before the upstream is
  contacted; a body without one that grows past it is cut and the client gets `413` (not `502`),
  though the upstream has seen the start of it. Ingress bytes for usage are counted as the body
  flows. The upstream client now carries a boxed body, so one client serves both paths.
- **Responses of any content type can stream** (`validation.stream_responses`, off by default).
  Until now only `text/event-stream` could skip buffering; a download was held whole in memory,
  and `max_response_body` defaults to unbounded. With the switch on, a response streams as it
  arrives whenever nothing on the request needs the whole body. LLM metering, reversible DLP and
  outbound DLP scanning still buffer, decided in one place (`streams_any_response`) with a test per
  feature. `max_response_body` is still enforced, as the bytes flow: over it the connection is cut
  (the status was already sent) and the client sees a truncated body, never the bytes past the
  cap. The upstream's `Content-Length` is kept, since the body passes through unchanged. The first
  slice of 0.6's "streaming bodies end to end".
- **Certificates rotate on their own, and a running proxy picks up a new certificate without a
  restart.** Up to 0.4.0 the listener read its certificate once at boot and kept it for the life
  of the process: nothing renewed an ACME certificate, nothing regenerated a self-signed one, and a
  certificate replaced on disk by cert-manager, Vault Agent or certbot was ignored until someone
  restarted. Every one of those ends the same way — a running proxy serving an expired certificate
  it could have replaced. The 90-day self-signed certificates 0.4.0 generates would have started
  expiring in December.

  - **Hot swap.** The listener now serves from a live certificate store (a rustls
    `ResolvesServerCert` over an `ArcSwap`). New handshakes get the current certificate;
    established connections keep theirs. Proven against a live listener under concurrent traffic:
    zero failed requests across the swap.
  - **`[tls] watch`** (on by default) reloads `cert_path`/`key_path` when they change on disk. It
    watches the directories rather than the files, so atomic renames and a Kubernetes secret's
    `..data` symlink flip are both seen. A pair that does not load — including the moment between
    another tool writing the certificate and writing its key — is refused and the current pair keeps
    serving, the same contract as config hot-reload. An hourly re-read is the backstop for
    filesystems that deliver no change events.
  - **ACME renewal** (`[tls.acme] renew`, on by default) at two-thirds of the certificate's
    lifetime — day 60 of 90 — through the same issuance budget and control-plane lease as the first
    order. With `redirect_port = 80` the redirect listener now answers the renewal's HTTP-01
    challenge from a shared token map, rather than the order trying to bind a port the listener
    already holds; any other path under `/.well-known/acme-challenge/` is still `404`. Failed
    attempts keep serving the current certificate and retry from 5 minutes, doubling to 12 hours.
    Proven against Pebble: issue, then renew while the redirect listener holds `:80`, then serve
    the renewed certificate with no restart.
  - **Self-signed renewal** (`self_signed_renew`, on by default) at the same point, **signed with
    the existing key** so anything that trusted the certificate by public key keeps trusting it
    (`self_signed_rotate_key = true` to rotate). Only a certificate that is itself self-signed is
    ever replaced: a CA-issued certificate at `cert_path` is left alone and logged, not overwritten
    with an untrusted one.
  - **Visibility.** `GET /__edgeguard/tls` (an ops endpoint, so admin-port only in split mode)
    reports source, serial, validity, days left, whether renewal is due and the last renewal
    attempt with its error. New series: `edgeguard_tls_cert_not_after_seconds{source}`,
    `…_not_before_seconds`, `…_reloads_total{outcome}`, `…_renewals_total{source,outcome}`.
    `monitoring/` gains `EdgeGuardCertExpiringSoon` (14 days), `EdgeGuardCertExpiringCritical`
    (3 days), `EdgeGuardCertRenewalFailing`, and two dashboard panels. `doctor` now reads the
    certificate at `cert_path` and reports an expired or under-7-day certificate as an error, and
    under 21 days as a warning when nothing in the process renews it.

  **Build cost: no new crates.** Certificate validity is read by a ~100-line DER walker rather than
  `x509-parser`, which is not otherwise in the graph; `arc-swap` and `notify` were already
  dependencies for config hot-reload.

- **Managed mode reports the certificate this edge serves.** With `[control_plane]` enabled and TLS
  on, the usage report carries the served certificate's expiry and source (and, for ACME, the ordered
  domains), so the control plane can show which edges are about to serve an expired certificate and
  follow renewals of the certificates it manages. The fields are omitted when TLS is off, so an older
  control plane receives exactly the body it always did.

- **Editions, stated in the README.** What this repository is (the Community edition: the whole
  proxy, Apache-2.0, nothing withheld) and what eggrd Enterprise adds above a fleet of edges — a
  self-hosted control plane, licensed by annual agreement with a 30-day trial. Only shipped
  capabilities are listed; the hosted option is marked as not available yet.

### Changed
- **An idle edge in managed mode now reports every interval.** The usage report is also the edge's
  heartbeat, and it used to be skipped when no traffic had arrived — so a quiet edge went "stale" in
  the fleet view after three minutes, and its certificate was never reported, exactly when nobody was
  watching its traffic. Idle reports carry a zero delta, which the control plane does not record as
  usage.

### Fixed
- **The ACME challenge listener could still hold `:80` after an order returned.** It was torn down
  by aborting its task, and an aborted task only drops its listener when the runtime next polls it
  — so whatever bound `:80` immediately afterwards could fail with `AddrInUse`. That includes the
  redirect listener, which binds `:80` straight after first-boot issuance with `redirect_port = 80`.
  Found by the renewal test, which binds `:80` the same way. The order now waits for the listener
  to close before returning, on success and failure alike.
- **ACME wrote the certificate and key as two separate, non-atomic writes**, so a crash or I/O
  error between them could leave a new certificate on disk against the old key. It now goes through
  the same stage-both-then-rename writer self-signed generation uses: both files change, or neither.
- Windows CI: `clippy -D warnings` failed on `src/selfsigned.rs` (`unused variable: private`) —
  the parameter is only read inside the `#[cfg(unix)]` chmod-0600 blocks, so it was genuinely
  unused on the Windows build. No behavior change on any platform; the private-key file still
  gets no permission restriction on Windows, which remains a known best-effort-platform gap.

## [0.4.0] — 2026-09-14

Three new hardening defaults, so this is a minor release per `docs/RELEASE.md`'s versioning
policy, not a patch. Two ship new capability that stays off until configured (self-signed TLS,
the `:80` redirect listener) — the third changes what a running deployment already does:
**`[log] query` now defaults to `redact`.** A deployment that scrapes access logs expecting the
full query string — a dashboard keyed on a `?campaign=` value, a SIEM rule matching on
`?session=` — will see `<redacted>` there after upgrading. Set `[log] query = "full"` to keep the
previous verbatim behaviour; nothing else about the request, routing or the upstream changes.

### Added
- **HTTPS works without first obtaining a certificate, and plaintext traffic is upgraded rather
  than dropped.** These were the two remaining places where "secure by default" required the
  operator to already know something. `tls.enabled = true` used to be a promise you could not
  keep until you had a PEM pair in hand, and even once TLS was up, nothing listened on `:80` — so
  a visitor typing a bare hostname got a connection error, and an app still bound there answered
  in the clear. The proxy was hardening a door people were walking past.

  - `[tls] self_signed = true` generates a certificate at `cert_path`/`key_path` when none is
    there yet, then serves it. The key is written `0600` — a private key that lands
    world-readable is a worse outcome than the missing certificate it fixes. Generation is
    skipped once the files exist, so a restart does not hand every client a new identity, and
    ACME still wins when both are configured: `self_signed` is a floor ("never fail to start for
    want of a certificate"), not a ceiling. `self_signed_hosts` sets the SANs (empty means
    `localhost`/`127.0.0.1`/`::1`), with IP literals becoming IP SANs rather than DNS names,
    because that is what clients actually match an address against.

    **What it buys is stated plainly, in the docs and by `doctor`.** It encrypts the connection —
    which is what makes HSTS, `Secure` cookies and the hardening headers mean anything at all —
    and it proves no identity, so browsers warn and strict clients refuse. Right for localhost, a
    private network, a sidecar hop or staging; wrong for a public domain, where `[tls.acme]` is
    the answer. Selling it as more than that would be the same overstatement the Status table in
    the README exists to prevent.

  - `edgeguard cert [--host h]... [--days n] [--cert-out p] [--key-out p] [--force]` writes the
    same pair as a standalone utility — no config file, no listener — for a Docker build stage or
    a compose init step. It refuses to overwrite without `--force`: replacing a certificate is
    not recoverable, since the previous key is gone and anything that trusted it breaks.

  - `[tls] redirect_port` (also `REDIRECT_PORT`) runs a small plaintext listener that redirects to
    HTTPS. The default status is **308, not 301**, so a `POST` that lands on the plaintext port is
    replayed over TLS instead of being silently downgraded to a `GET`. The TLS port is carried
    into the `Location`, so a proxy on `:8443` redirects there rather than to a `:443` nothing is
    listening on.

    **It does not ship the hole it exists to close.** The `Host` header is attacker-controlled, and
    a redirect listener that reflects it unchecked is an open redirect wearing the site's own
    name. A malformed host — spaces, CR/LF, userinfo, an over-long name — is answered `400`
    rather than reflected, and `redirect_hosts` pins redirects to an allow-list.
    `/.well-known/acme-challenge/` is answered `404` and never redirected: a CA must read the
    HTTP-01 token in plaintext, and bouncing it to the port whose certificate is being issued
    would deadlock the order. With ACME enabled, issuance runs first and the redirect listener
    binds afterwards, so the two never contend for `:80`.

  - `doctor` gained the checks that make the above discoverable rather than documented: TLS on
    with no certificate source at all is an **error** (it will not start), `self_signed` warns
    that it is not publicly trusted, a `redirect_port` colliding with `server.port` or
    `admin_port` is an error, a non-3xx `redirect_status` is an error, and `redirect_port = 0`
    is called out because TLS that nothing redirects to is the most common way it gets bypassed.
    It also now flags **`headers.hsts = true` with `tls.enabled = false`** — the shipped default —
    which reads as protected and is not, since browsers ignore HSTS on a plain-HTTP response.

  **Review round.** Eight findings from the PR review bot, seven acted on. The one that
  mattered: the code did the *opposite* of its own comment. `self_signed` generation ran before
  ACME, wrote to the same `cert_path`, and the ACME branch skips issuance when a certificate is
  already there — so with both enabled on a public domain, the untrusted self-signed certificate
  silently won over the publicly trusted one the operator asked for. ACME now runs first, which
  is also what makes `self_signed` the floor it was documented to be. Alongside it: `Host` is now
  parsed as a whole authority rather than split on the first colon (`attacker.example:443@victim.example`
  was reduced to `attacker.example` and redirected instead of refused — the strictness the docs
  already claimed); `redirect_status` is validated before the listener binds, since failing inside
  the spawned task left the port closed while HTTPS carried on, turning a typo into "connection
  refused"; an out-of-range `--days` returns an error instead of panicking on `OffsetDateTime`
  overflow; identical `cert_path`/`key_path` is refused rather than writing the key over the
  certificate and reporting success; and both files are now staged and renamed into place, which
  also fixes a real permissions hole — `OpenOptions::mode` only applies when it *creates* a file,
  so regenerating over an existing `0644` key had been leaving new key material world-readable.
  Not taken: a cross-process lock around generation — with the reasoning stated more carefully
  than the first draft managed, because whether a lock helps depends on the storage. On **shared**
  storage one would work: the first replica generates, the rest find a complete pair and reuse it,
  and they converge on one identity. On **per-replica** storage it cannot — there is nothing to
  coordinate through, so each replica necessarily holds a different self-signed identity. The
  second case has no fix at this layer and the first is better solved by not generating at boot,
  so the documented answer for either is to generate once with `edgeguard cert` and mount it
  read-only, and `ensure` now says exactly that rather than dismissing locks outright.

  A second round found four more, all taken. `is_redirection()` accepts the whole 3xx class, so
  `redirect_status = 304` was allowed and would answer a cache validator with a `Location`,
  leaving the client on plaintext — the exact failure the feature exists to prevent, reached
  through a value we accepted; only 301/302/303/307/308 now pass. The ACME skip-issuance guard
  tested `cert_path` alone, so a certificate whose key was missing skipped the order and handed
  the half-pair to `ensure`, which regenerates both — the precedence bug again, through a
  different door; both files must now be present to skip. And `Path::exists()` follows symlinks,
  so a dangling one read as "absent" and let a no-force `edgeguard cert` replace the operator's
  symlink with a regular file; presence is now tested with `symlink_metadata`.

  A third round closed the pair-publication gap properly. The previous attempt staged and
  renamed one file at a time while its own comment claimed it staged both first — the third
  comment/code mismatch this change produced, and the reviewer was right that an ordinary I/O
  error on the key (not just a crash) could therefore leave a new certificate live against the
  old key. Both files are now staged before either live path moves, and the live certificate is
  set aside first and put back if the key never lands, so **any** failure leaves the operator's
  existing pair exactly as it was. Writing the test for that caught the remaining hole in the
  fix: a `rename` fails on its own too (a directory in the way, a read-only mount), so staging
  alone was not enough — hence the rollback.

  **Build cost: none measurable.** `rcgen` is declared directly for the first time since 0.3.0, but
  `instant-acme` already depends on it, so it was compiled on every build regardless: the graph
  stays at **218 crates**, cold release build time is unchanged, and the stripped binary grows
  **331 KiB (+1.9%)**, from 16.63 MiB to 16.96 MiB. Both features are always-on code paths with
  no feature flag, because a security default behind an opt-in flag is not a default.

- **Access logs no longer carry credentials.** The request line is the most useful field in an
  access log and the easiest place to leak a secret: password-reset links, OAuth `?code=`,
  presigned URLs and `?api_key=` all travel in the query string, and access logs are the
  most-copied artifact a service produces — scraped, shipped to a SIEM, retained for months, read
  by people who were never meant to hold the credential. EdgeGuard was logging
  `path_and_query()` verbatim, which for a proxy that advertises DLP is the wrong component to be
  writing them to disk.

  Query values are now redacted on two independent signals: **by name** (a built-in list covering
  `key`, `token`, `secret`, `password`, `auth`, `code`, `state`, `email`, … matched
  case-insensitively as substrings, plus whatever `[log] redact_params` adds) and **by shape** (a
  JWT, or a long high-entropy token — which catches `?t=eyJhbGciOi…` where the parameter name is
  innocuous and a name list never would). Ordinary values — page numbers, slugs, dates, search
  terms — stay readable, so the log keeps its debugging value. The replacement is a fixed
  `<redacted>`, so neither the value nor its length leaks.

  `[log] query` selects `redact` (default), `drop` (path only), or `full` (verbatim, opt-in).

  **Only the log is affected.** The upstream receives the client's target byte-for-byte, and the
  WAF, per-route rate limits, route-scoped DLP and upstream selection all still see the raw
  request — redacting those would break routing and blind the security pipeline. Both properties
  are covered by integration tests, including a WAF test whose SQLi payload sits in a parameter
  named `code`, which is on the redaction list.

  Path segments are *not* redacted: `/reset/<token>` cannot be distinguished from `/users/<id>`
  without knowing the application's routes, and guessing would mangle ordinary paths. Use `drop`
  where secrets ride in path segments.

  **Encoded parameters do not slip past it.** Classification runs on the decoded form as well as the
  raw text, so `?%74%6f%6b%65%6e=secret` (that is `?token=secret`) and a JWT whose dots are `%2E`
  are both caught — otherwise redaction would have covered exactly the credentials nobody bothered
  to obfuscate. Only classification decodes; the logged text keeps the original encoding, because
  rewriting it would change what the request actually said.

  **Upstream failure logs are covered too.** `upstream timed out` and `upstream unreachable` printed
  the forwarded URI, query and all — redacting the access line and then leaking the same `?api_key=`
  in a `warn!` would give it up on the path an operator is most likely to be reading. The forwarded
  URI is still verbatim; only the logged one is sanitised.

  The setting is deliberately **not** pushable from a control plane. A managed plane able to flip
  an edge to `query = "full"` could turn that edge's own logs into an exfiltration channel for
  every credential its users put in a URL, without touching the edge's config file.
- **A documentation site at `eggrd.dev/docs`, so the reference is not the source.** The landing
  page's "Documentation" link pointed at the GitHub README, which meant every question about a
  configuration key ended in `config.rs`. There are now four pages: an overview, the CLI and
  environment variables, the full configuration reference, and operations (endpoints, every
  Prometheus series, and what fails closed).

  **The configuration page is generated** from `src/config.rs` by
  `scripts/build-config-reference.py` — 151 keys across 21 tables, with the doc comment as the
  description and the `Default` impl as the stated default. It cannot describe a binary that
  does not exist, and a field added without a doc comment fails the generator rather than
  producing a blank row: a reference with silent holes looks complete and is not.

  Writing it found **21 public config fields with no doc comment at all**, including
  `auth.realm`, all six `[headers]` policy values and every `enabled` flag. Those are now
  documented in `config.rs`, which improves the source as much as the page.

### Added
- **The LLM gateway's ordering guarantee is now enforced by tests, not asserted in comments.**
  The landing page claims the budget reserve, model allowlist and DLP gates run *before the
  provider is called* — the whole economic argument, since a request that reaches the provider has
  been paid for whatever the client eventually sees. Every denial test checked the client's status
  and the metric and said "never reaches the upstream" in a comment; none of them observed the
  upstream. A gate that forwarded first and denied afterwards would have passed all of them.

  Five tests now use a counting stub provider and assert it saw **exactly zero** requests: over
  budget, DLP block, off-allowlist model, and a budget-store outage (fail-closed, the default).
  A control test asserts an admitted request registers exactly one hit — without it, a counter
  that never incremented would make the rest pass vacuously.

  Confirmed to have teeth by mutation: making the denial path call the provider before returning
  makes `over_budget_request_never_reaches_the_provider` fail with `left: 1, right: 0`, while the
  client still receives the same `429` the old test accepted.
- **The same guarantee is now covered for the gates in front of an ordinary app**, not just the
  LLM path: unauthenticated (`401`), WAF block (`403`), IP-denied (`403`), oversized body (`413`),
  rate-limited (`429`), and a rate-limiter store outage (`503`, fail-closed). Each asserts the
  upstream saw zero requests, with a control asserting an allowed request reaches it exactly once.
  Mutating the auth path to forward before rejecting makes
  `unauthenticated_request_never_reaches_the_upstream` fail the same way.

### Changed
- **`aws-lc-sys` is gone from the dependency graph.** It was the single most expensive crate in
  the build — 54.8s of a 139s cold `cargo build --release --bin edgeguard` on 4 cores, 17.4% of
  total unit-time — and nothing used it. `src/tls.rs` has always pinned `ring`: `init_crypto()`
  installs the ring provider and `load_server_config()` builds the `ServerConfig` with an
  explicit one. The aws-lc stack was in the graph purely by feature unification, because
  `rustls = { features = ["ring"] }` adds `ring` *on top of* rustls's defaults rather than
  replacing them, leaving `aws_lc_rs` on — and `tokio-rustls` and `instant-acme` each turned it
  back on through their own defaults, so fixing only `rustls` was not enough.

  All three now take an explicit ring path (`default-features = false` plus the features the
  crate actually uses). `reqwest` and `redis` needed no change and are annotated as such in
  `Cargo.toml`, so the next person does not re-derive it: reqwest's `rustls-tls` already implies
  `__rustls-ring`, and redis declares rustls with `default-features = false`.

  Measured on the same 4-core box, cold target and warm registry: **139s → 111s wall**, total
  unit-time **314.7s → 255.7s**, 285 → 271 compilation units, and `cargo tree -i aws-lc-rs`
  reports nothing under default, `--all-features` and `--features ner`. The stripped release
  binary goes from **16.6 MiB to 7.5 MiB** — 54.7% smaller, since the whole of libcrypto was
  being linked in unused. It also removes the build's only cmake/bindgen C dependency, which was
  the piece most likely to break on a new toolchain or a musl/cross target — the thing the
  single-static-binary and distroless claims rest on.

  Nothing changes on the wire. rustls's `prefer-post-quantum` default is dropped along with the
  rest (it is an `aws_lc_rs` alias), but it was already inert: the listener builds with an
  explicit ring provider and ring has no ML-KEM. Before and after both negotiate
  `TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519 / RSASSA-PSS`.

- **The single-provider rule is now enforced, not just documented.**
  `scripts/check-crypto-provider.sh` fails the build if `aws-lc-rs` or `aws-lc-sys` reappears
  anywhere in the resolved graph, and names what pulled it in. It runs in CI and as `make deps`
  (part of `make test-all`).

  It has to be a graph check rather than a test, because neither consequence surfaces as a test
  failure: the C build is a build-time and binary-size cost, and the provider ambiguity only
  bites the `rediss://` path at runtime. A lockfile does not remove the need for it: a
  `cargo update`, a new dependency, or a point release that flips a default feature anywhere
  across rustls / tokio-rustls / instant-acme / hyper-rustls / rcgen can put aws-lc back, and in
  a ~26k-line workspace lock diff the handful of changed edges is not something a reviewer
  spots. The crate also ships without a lock of its own, so the OSS cut resolves fresh every
  time.

  The check reads `cargo tree`, not `Cargo.lock`, because the lock keeps entries for optional
  dependencies that no enabled feature activates — `aws-lc-rs` is still listed there under
  `rustls-webpki` — so grepping the lock would report a regression that is not one. Both package
  names are matched: `rcgen` can pull `aws-lc-rs` without touching rustls's features, so neither
  name implies the other.

### Fixed
- **`ratelimit.store = "redis"` over `rediss://` aborted the process when TLS termination was
  off.** Linking two rustls crypto providers makes `rustls::ClientConfig::builder()` panic —
  *"Could not automatically determine the process-level CryptoProvider"* — unless a default has
  been installed first. `tls::init_crypto()` installs one, but only runs under `[tls] enabled`,
  and the `redis` crate calls that builder when it opens a `rediss://` connection. So an operator
  terminating TLS at a load balancer (the documented deployment) and pointing the distributed
  limiter at a TLS Redis lost the process on the first rate-limited request, with a panic
  message about crate features rather than anything resembling their config.

  With `ring` now the only provider linked, the lookup resolves from crate features and the path
  behaves like every other store failure: the connection is attempted, and an unreachable store
  fails closed with `503` and a `rate-limit store error` warning.

- **`dead_addr()` in the integration tests was racy.** It bound an ephemeral port and dropped it,
  assuming nothing would claim it — but the OS is free to hand that port to the next listener, and
  with more concurrent tests it does. The "down" upstream then answered `200` and
  `bad_gateway_when_upstream_down` failed pointing at the proxy, when the fault was in the
  fixture. Now returns `127.0.0.1:1`, which is privileged, unallocated, and refuses immediately.

### Fixed (release tooling, no crate change)
- **The crate is published to crates.io again.** The mirror's release workflow had a `crates`
  job that published `edgeguard-ner` and then `eggrd`; rewriting that workflow upstream dropped
  it, and nothing noticed because the images kept publishing. crates.io stopped at **0.2.1**
  (2026-07-14) while 0.2.2, 0.3.0 and 0.3.1 shipped as containers — so `cargo install eggrd`,
  which the site and this README both recommend, was installing the version whose ACME issuance
  is broken.

  Restored, and deliberately independent of the image jobs so a Docker Hub outage cannot block
  the crate. It keeps the ordering the original had, which a dry run confirms is still required:
  `eggrd` declares `edgeguard-ner = "^0.1.1"`, only `0.1.0` is on the index, and packaging
  `eggrd` fails outright until the new `edgeguard-ner` is published *and* indexed. Both steps
  treat an already-published version as success, and the retry loop waits only on index
  propagation — any other failure exits immediately rather than burning four minutes to report
  the wrong cause.

  A `workflow_dispatch` with `push: false` now skips the crate publish as well as the image
  push. A crates.io release cannot be withdrawn, only yanked, so a "dry run" that publishes one
  is not a dry run.

## [0.3.1] — 2026-08-24

A patch release, but read the argument-parsing note before upgrading: it changes what happens to
a command line the proxy previously accepted.

Both fixes came from the same habit as 0.3.0 — running the thing rather than reading it. Both
turned out to be the project being wrong about itself: one flag that silently did nothing, and
one build failure blamed on the wrong component for weeks.

### Added
- **`edgeguard --version` / `-V`.** There was previously no way to ask a binary or a published
  image what version it was — the flag fell through the parser's catch-all and started a proxy
  instead. Works for the subcommands too (`edgeguard doctor --version`).

### Fixed
- **The WASM edge worker builds and runs — the toolchain was never the problem.** `worker-build`
  failed with `externref table required for catch wrappers`, which was recorded as a pinned-
  toolchain incompatibility and left the worker as the one unproven capability. It was actually
  `strip = true` in the worker's own `[profile.release]`: `worker-build` invokes wasm-bindgen with
  `--force-enable-abort-handler`, whose catch wrappers need the externref table, and stripping
  removes the symbols used to find it. The error names neither `strip` nor the manifest.

  Bisected by holding everything else constant — `lto = true` + no strip builds; `lto = false` +
  strip fails. LTO, the usual suspect, was never involved.

  With `strip` removed, `worker-build --release` emits the bundle (`index.js` +
  a 415 KB `index_bg.wasm`), and it was **run on workerd**, the runtime Cloudflare runs in
  production: `401` unauthenticated, `401` on a wrong password, `200` fetched from a live origin
  carrying all six hardening headers with `Server` and `X-Powered-By` stripped. Deployment to a
  Cloudflare account — routes, custom domains, secret bindings — remains untested.
- **Unknown arguments are rejected instead of silently discarded.** The serve path and
  `generate` ended in `_ => {}`, so any token the parser did not recognise was dropped without
  a word. A typo such as `--wrpa "npm start"` started an unwrapped, unconfigured proxy that
  looked healthy, and `generate --targt vercel` emitted the default `_headers` target and
  reported success. Both now fail with the offending argument named, matching what `doctor` and
  `init` already did. A front door that ignores its instructions is worse than one that refuses
  to open.

  This is a **behaviour change**: a deployment currently passing an argument that was being
  ignored will now fail at startup rather than run with settings it did not ask for.

### Fixed (release tooling, no crate change)
- **The 0.3.0 manifest assertion could never pass.** It grepped the raw manifest for
  `"architecture":"amd64"`, but `docker buildx imagetools inspect --raw` returns
  pretty-printed JSON — `"architecture": "amd64"`, with a space. The 0.3.0 release therefore
  reported `amd64 missing` and failed while all three tags were in fact correctly
  multi-arch. It now parses the index with `jq` and prints what it found, so a real failure
  is diagnosable and a false one cannot recur. An assertion that cannot pass is worse than
  no assertion: it teaches people to re-run through red.
- **Two release pipelines could run concurrently.** `gh release create` creates the tag,
  raising a push event alongside the release event, so 0.3.0 ran the whole pipeline twice
  against the same tags. Serialized with a concurrency group keyed on the ref, deliberately
  *without* `cancel-in-progress` — cancelling mid-push is what leaves half-written tags.
- **The Docker Hub overview stopped updating.** `dockerhub-readme.yml` existed only on the
  public mirror, hand-placed and untracked upstream, so the first sync that owned
  `.github/workflows/` deleted it. The overview kept advertising 0.2.1 after 0.3.0 shipped.
  Restored upstream and added to the sync manifest, which is the only place it survives.

## [0.3.0] — 2026-08-24

Three capabilities this crate shipped were compiled but had never been run against real
infrastructure. Running them found one of the three genuinely broken, and that fix is the
reason this is a minor bump rather than a patch.

### Fixed
- **ACME certificate issuance was broken in the field, and is now proven working.**
  The pinned `instant-acme` 0.7.2 (October 2024) could no longer parse Let's Encrypt's
  current authorization payload, so every issuance attempt failed at the first
  authorization with:

      Error: ACME certificate provisioning
      Caused by:
        0: fetching authorizations
        1: missing field `token`

  This affected anyone relying on `[tls] acme = true` for automatic certificates — the
  proxy started, then failed to obtain a certificate. Bumped to `instant-acme` 0.8 and
  reworked the order flow around its API: the HTTP-01 challenge responder is now started
  **before** the authorizations are walked (the previous order raced the CA's validation),
  challenges are marked ready explicitly, and both the order and the certificate are polled
  with a retry policy instead of a hand-rolled sleep loop.

  Verified end to end twice: against a local Pebble CA, and against Let's Encrypt's staging
  environment, which issued a real certificate in about five seconds
  (`CN=acme-test.eggrd.dev`, issuer `(STAGING) Artificial Amaranth YE1`).
  `docs/ACME_TESTING.md` carries both recipes and every trap that stopped them working.

### Removed
- **The `rcgen` dependency.** `instant-acme` 0.8 generates the key pair and CSR inside
  `finalize()` and returns the private key, so nothing in this crate constructed a
  certificate itself any more. `rcgen` had been left behind as an unused dependency — in a
  proxy that terminates TLS, an unused crypto dependency is supply-chain surface with no
  compensating benefit.

### Added
- **Native `linux/arm64` images.** Releases now build each architecture on its own native
  runner (`ubuntu-24.04` and `ubuntu-24.04-arm`), push by digest, and merge the two into one
  multi-arch manifest. The release fails if the merged manifest does not contain both
  architectures, so a half-published image cannot pass as a green release. Previous images
  were amd64 only. The release also now asserts that `Cargo.toml` matches the tag being
  released — the image tag came from the git tag while `--version` came from the manifest,
  and nothing compared them, so a forgotten bump could have published an image labelled
  `0.3.0` containing a binary reporting `0.2.2`.
- **`examples/tls-termination.toml`** — a TLS configuration that has actually been run,
  with the reproduce recipe in its header. Explicitly marked as a demonstration rather than
  a production template.
- **`docs/ACME_TESTING.md`** — how to test ACME locally against Pebble and against Let's
  Encrypt staging, plus each failure encountered on the way and the misleading symptom it
  presented.

### Changed
- **CI now runs on the public repository.** The crate's `ci.yml` travelled with the source
  but was never registered, so the public repository had no CI at all after 2026-07-28. It
  and the new `release.yml` are now shipped by the release pipeline and run on every push
  there.

### Proven, not changed
No code change, but previously undemonstrated and now exercised:
- **TLS termination with a supplied certificate** — TLS 1.3 negotiated, certificate
  verified, the upstream response proxied back through it, plaintext refused on the TLS
  port, and all six hardening headers present on the response.
- **The shared-store rate limiter** — two replicas against one Redis, thirty requests from
  a single client alternating between them: **5 allowed** against one shared key. The same
  run with the per-replica store allowed **10**, exactly twice, which is the reason the
  shared store exists.

The **WASM edge worker remains unproven.** The crate compiles to
`wasm32-unknown-unknown`, but `worker-build` — the step that produces the deployable
bundle — fails on the pinned toolchain, so there is no artifact to run.

## [0.2.2] — 2026-07-28

### Changed
- **Documentation comments describe failure modes rather than attributing them.** A number of
  doc comments across the LLM metering, DLP and alerting paths justified a design choice by
  pointing at a specific defect in another vendor's issue tracker. The engineering rationale is
  unchanged and still stated — an unmask that can restore another caller's value is still the
  thing reversible masking is built to avoid, and an unknown model is still never served at a
  silent `$0` — but the reasoning now stands on its own rather than on a third-party bug report
  that this project does not re-check and cannot keep current.

## [0.2.1] — 2026-07-15

### Fixed
- **Cookie hardening no longer forces `HttpOnly` on cookies that must stay JS-readable.**
  EdgeGuard's `[headers]` hardening added `HttpOnly` to every `Set-Cookie` unconditionally,
  which silently broke apps behind the proxy that use a **double-submit CSRF cookie** the
  frontend reads from `document.cookie` (the cookie became unreadable → the app saw no
  session). Two new `[headers]` keys make it configurable:
  - `httponly_cookies` (bool, default `true`) — global toggle for adding `HttpOnly`.
  - `httponly_cookie_exempt` (string list, default `[]`) — cookie **names** to never add
    `HttpOnly` to, e.g. `["doneyet_csrf"]`. The surgical fix.

  `Secure` and the `SameSite=Lax` default are unchanged. Existing configs keep the previous
  behaviour (HttpOnly on by default); opt out only for cookies you intend JS to read.

## [0.2.0] — 2026-06-28

### Hardened (pre-release review follow-ups)
- **CORS on error responses**: EdgeGuard-generated `401`/`403`/`429` are now CORS-decorated too
  (centralized in `proxy::handle`), so an allowed browser origin sees the real status instead of a
  generic CORS failure.
- **WebSocket upgrade path**: forwards under the same `upstream_timeout`, caps a rejected
  (non-`101`) body by `max_response_body`, and strips hop-by-hop headers before forwarding (so a
  client can't smuggle connection-scoped headers upstream).
- **`[[upstreams]]` validation**: a `path` without a leading `/` (e.g. `api/`) is now rejected at
  startup instead of silently never matching.
- **`edgeguard doctor`**: also validates the managed-mode control-plane path (`CpClient::from_cfg`),
  no longer prints "no issues found" when info-level findings were emitted, and no longer warns
  about secrets "in the config file" when they were actually sourced from the env / `*_FILE`.
- **CLI**: `doctor` / `init` now reject unknown flags (a typo like `--confg` no longer silently
  validates the default config).

### Added
- **Request IDs** (`X-Request-Id`): for every request EdgeGuard reuses a well-formed inbound id (a
  short, printable-ASCII token — validated so it can't inject control characters into the log) or
  mints a UUID v4, forwards it upstream, echoes it on every response (including errors), and adds it
  to the JSON access log — one id correlates the client, EdgeGuard, and the app. Always on. See
  `src/proxy.rs`.
- **Per-path upstreams** (`[[upstreams]]`, single upstream by default): a static path-prefix →
  upstream map (longest prefix wins; unmatched falls back to the default upstream), for the common
  "static frontend + `/api` backend" shape. Deliberately not a gateway — no service discovery, load
  balancing, or request rewriting. Edge-local (not pushed by the control plane). See `src/config.rs`.
- **Response compression** (`validation.compress_responses`, off by default): gzip for clients that
  send `Accept-Encoding: gzip`, via `tower-http`, skipping small/already-compressed responses and
  (always) `text/event-stream` so SSE streaming is never buffered by the compressor. Listener-level
  (restart to toggle). See `src/lib.rs`.
- **Prometheus alert rules** (`monitoring/prometheus/alerts.yml`): reusable alerts on upstream-5xx
  ratio, p95 latency, auth-failure / WAF / rate-limit spikes, and limiter-store errors, wired into
  the bundled monitoring stack and droppable into any Prometheus.
- **WebSocket / `Upgrade` passthrough** (`[validation] websocket_passthrough`, **off by default**):
  tunnel WebSocket connections through to the upstream. The normal path strips the hop-by-hop
  `Upgrade`/`Connection` headers (so a handshake would fail); when enabled, an authenticated,
  rate-limited upgrade request is forwarded intact and, on the upstream's `101 Switching
  Protocols`, EdgeGuard splices the client and upstream connections into a raw bidirectional tunnel
  (`tokio::io::copy_bidirectional` over `hyper::upgrade`). A non-`101` reply is passed back
  unchanged. Response hardening / WAF body inspection don't apply to a tunneled connection. See
  `src/proxy.rs`.
- **IP access control** (`[access]`, allow-all by default): CIDR `allow`/`deny` lists (IPv4 + IPv6)
  evaluated by client IP **before auth and rate limiting** — lock the app to an office/VPN range or
  drop an abusive subnet. `deny` wins over `allow`; a non-empty `allow` is a whitelist. Matching is
  implemented directly (no new dependency); a bad CIDR fails at startup/reload. Keys on the same
  resolved client IP rate limiting uses. See `src/access.rs`.
- **`*_FILE` secret loading**: every secret env var now also accepts a `*_FILE` variant
  (`EDGEGUARD_JWT_SECRET_FILE`, `EDGEGUARD_API_KEYS_FILE`, `EDGEGUARD_REDIS_URL_FILE`,
  `EDGEGUARD_CP_EDGE_TOKEN_FILE`) pointing at a file whose contents are the value — the Docker /
  Kubernetes / systemd-`LoadCredential` secret-mount convention, so secrets stay out of the config
  file and the process environment. The direct variable wins when both are set; an unreadable
  `*_FILE` is a hard startup error. See `src/config.rs`.
- **Deploy examples**: a hardened systemd unit (`examples/edgeguard.service` — sandboxed, binds
  80/443 via `CAP_NET_BIND_SERVICE`, secrets via `LoadCredential` + `*_FILE`) and a
  `docker compose` front-door layout (`examples/docker-compose.yml` — app reachable only through
  EdgeGuard, file-mounted secret).
- **CORS** (`[cors]`, **off by default**): a small, explicit Cross-Origin Resource Sharing policy
  so a separate-origin browser frontend (a static host, a preview URL, `localhost:5173` in dev) can
  call the app EdgeGuard fronts. EdgeGuard answers browser **preflight** `OPTIONS` requests itself —
  *before* auth, since preflights carry no credentials — and **decorates** actual responses with the
  matching `Access-Control-*` headers (echoing the request `Origin` + `Vary: Origin` for an explicit
  allow-list, or the cacheable `*` for a wildcard). A credentialed wildcard
  (`allow_credentials = true` with `allow_origins = ["*"]`) is rejected at startup/reload, since the
  Fetch spec forbids it. Configure `allow_origins`/`allow_methods`/`allow_headers`/`expose_headers`/
  `allow_credentials`/`max_age`. Compiled into a `crate::cors::CorsPolicy` on the hot-swappable
  runtime. See `src/cors.rs`.
- **`edgeguard init`**: scaffold a starter `edgeguard.toml` (the annotated, secure-by-default
  reference, embedded so it can't drift) plus a `Dockerfile.edgeguard` that wraps your app behind
  EdgeGuard — tailored to the runtime detected from the working directory (Node / Python / Go /
  Rust). Refuses to clobber existing files unless `--force`. Turns adoption from "read the README and
  hand-write a config + Dockerfile" into one command. See `src/scaffold.rs`.
- **`edgeguard doctor`**: load + validate a config (the same `Config::load` + `build_runtime` paths
  the proxy uses) and report the common deployment foot-guns — the shipped **placeholder credential**
  still in place (a malformed argon2 hash that can never authenticate), `auth.mode = "none"`, secrets
  committed to the file, an over-permissive or credentialed-wildcard CORS policy, a `redis` store with
  no URL, `enforce_quota` without managed mode, and more. Exits non-zero on a hard error, so it can
  gate a deploy in CI. See `src/doctor.rs`.

## [0.1.5] — 2026-06-21

### Added
- **Streaming / LLM-proxy passthrough** (`[validation] stream_passthrough`, **off by default**):
  forward `text/event-stream` (Server-Sent Events) responses **unbuffered, frame-by-frame** instead
  of buffering the whole body first. This makes EdgeGuard a viable front door for **streaming LLM
  backends** (OpenAI-compatible token streams) and any SSE app — time-to-first-byte is preserved
  rather than collapsing to time-to-completion. A small `CountingBody` wrapper tallies egress bytes
  as frames flow, so managed-mode usage stays correct without buffering. On a streamed response the
  `max_response_body` cap and the body-read deadline don't apply (the connect/first-byte
  `upstream_timeout` still does). Non-SSE responses are unchanged. See `src/proxy.rs`.

### Docs
- Grafana dashboard for the load-test harness (`loadtest/grafana/`): an auto-provisioned
  **"EdgeGuard — proxy overview"** dashboard (request rate by outcome, p50/p95/p99 latency from the
  histogram, rate-limit hits by scope, WAF hits by rule) wired to the harness Prometheus, plus a
  pinned datasource uid so it binds deterministically.

## [0.1.4] — 2026-06-20

### Added
- **Managed mode** (`[control_plane]`, **off by default**): an optional client that pulls this
  edge's policy from a remote control plane and hot-reloads it (conditional `GET` with an ETag →
  `304`, applied through the same `build_runtime` + arc-swap path as a local file edit), reports
  usage deltas (requests + ingress/egress bytes), and forwards received CSP reports. The pushed
  policy is the *policy subset* (auth/ratelimit/validation/headers/waf) — the edge keeps its own
  local `[server]`/`[tls]`. The edge token comes from `EDGEGUARD_CP_EDGE_TOKEN`. With no
  `[control_plane]` configured the proxy is byte-for-byte unchanged. See `src/cp.rs`.
- **Live-dependency proof tests** (`#[ignore]`d — no effect on the default suite): two against a
  live **Redis** exercising the real GCRA Lua script (global per-IP + per-key limits;
  `cargo test --lib redis_ -- --ignored`), and one **ACME HTTP-01** end-to-end against
  [Pebble](https://github.com/letsencrypt/pebble) (`src/acme.rs`), plus a
  `loadtest/pebble.compose.yaml` starting point.

### Docs
- Expanded the **distributed rate-limiting** README section: *why* a shared store (a per-replica
  limit multiplies under autoscale — Redis keeps one global cap) and *how to run it* (a local
  one-Redis snippet and a 3-replica compose).

## [0.1.3] — 2026-06-19

### Added
- README **"Where it fits"** section: high-level architecture diagrams (front-door + wider-stack
  placement), a "what it does *not* replace" list, and migration examples for moving an existing
  app behind EdgeGuard (from no-proxy / plain nginx / a hosted gate / a static host).
- **Multi-arch release image** `mancube/eggrd` (Docker Hub) — `linux/amd64` + `linux/arm64`, a
  static musl binary on `distroless/static`; see `Dockerfile`.

### Changed
- Deploy templates and docs point the container image at `mancube/eggrd` (Docker Hub) and the
  build-from-source step at `cargo install eggrd`; repository links use `lucheeseng827/eggrd`.

## [0.1.2] — 2026-06-18

### Changed
- Crate `repository` metadata now points at the public mirror `lucheeseng827/eggrd` (was the
  development monorepo, whose link 404s for the public). Metadata-only; no code change.

## [0.1.1] — 2026-06-18

### Changed
- README rewritten to a neutral, data-plane-only, user-facing tone. No code change.

## [0.1.0] — 2026-06-18

First public release on crates.io, published as the **`eggrd`** package — the name `edgeguard`
was already taken, so the crate is `eggrd` while the binary and library keep the name
`edgeguard` (the CLI, the `EDGEGUARD_*` env vars, and the `/__edgeguard/*` namespace are
unchanged). Ships the v0–v2.5 feature set below.

> **Note:** 0.1.0 and 0.1.1 are **yanked** — they carried, respectively, a `repository` link that
> 404s for the public and an interim README. Use **0.1.2+**.

### Changed
- **License consolidated to Apache-2.0** (was MIT OR Apache-2.0), pre-release.

### Added
- **Phase 5 / v2.5 (static/edge surface):**
  - **Static-host / edge config generator** (`edgeguard generate --target <t>`): renders the
    `[headers]` policy into a `_headers` file (Netlify / Cloudflare Pages), a `vercel.json` headers
    block, a Vercel Edge Middleware (`middleware.ts`), or a Netlify Edge Function. `--out <path>`
    writes to a file (otherwise stdout). Every target renders from a new shared
    `proxy::security_headers` — the **same** source of truth the live proxy injects — so generated
    config can't drift from runtime; an integration test cross-checks the generated `_headers`
    against a real proxied response. (A static `_headers` file can only *add* headers, so cookie
    hardening / leaky-header stripping / auth are documented as worker-only.) See `src/generate.rs`.
  - **Rust→WASM Cloudflare Worker** (`worker/`): a detached-workspace crate that compiles to
    `wasm32-unknown-unknown` via `worker-build`. It authenticates at the edge (HTTP Basic / static
    API key, constant-time), forwards to the configured origin, and hardens the response (security
    headers + cookie hardening + leaky-header stripping) — mirroring `src/proxy.rs` / `src/auth.rs`.
    The pure logic (header set, auth decision, cookie hardening, env parsing, origin-URL joining)
    is unit-tested on the native target and the wasm entrypoint compiles clean under
    `cargo clippy --target wasm32-unknown-unknown -D warnings`; the `fetch` runtime is *proven only
    against a live Cloudflare deploy* (like ACME / Redis). Rate limiting and JWT are out of scope
    for the edge subset. See `worker/README.md`.
  - Refactor: extracted `proxy::security_headers` + `proxy::HSTS_VALUE` as the single source of
    truth for the injected security-header set, now shared by the live proxy and the generator.
- **Phase 4 / v2 (WAF-lite), in progress:**
  - **WAF-lite input inspection** (`[waf]`, **off by default**): built-in heuristic **SQLi**,
    **XSS**, and **path-traversal** rulesets screen the request path/query (matched both raw and
    percent-decoded) and, opt-in (`inspect_headers` / `inspect_body`), header values and the
    size-capped request body. `mode = "report"` logs + counts matches without blocking;
    `mode = "block"` returns `403 Forbidden`. Each built-in ruleset is individually toggleable.
    Runs after auth and the size/method checks; the internal `/__edgeguard/*` endpoints are
    never inspected. See `src/waf.rs`.
  - **Custom deny patterns / pluggable rule sets** (`[[waf.rules]]`): operator-defined RE2 regex
    rules with a per-rule `target` (`path` / `headers` / `body` / `all`), evaluated alongside the
    built-ins. RE2 matching is linear-time and rejects backreferences/lookaround, so an operator
    pattern can't cause catastrophic backtracking (ReDoS); a pattern that fails to compile (or an
    unknown `target`) is rejected at startup/reload like any other config error.
  - `edgeguard_waf_hits_total{rule="sqli|xss|path_traversal|custom"}` metric, counting both
    report-only and blocked matches; blocked requests are additionally counted under the existing
    `forbidden` request outcome. The startup log line now also reports the active `waf` mode.
  - **Distributed (shared-store) rate limiter** (`ratelimit.store`): in addition to the default
    in-process `governor` limiter (`"local"`), a **Redis**-backed shared store (`"redis"`) so
    multiple replicas enforce one global GCRA limit (`redis_url` / `redis_prefix`, or the
    `EDGEGUARD_REDIS_URL` env var; `rediss://` TLS supported). The GCRA check-and-update runs
    atomically as a Redis Lua script. `ratelimit.fail_open` controls behavior when the store is
    unreachable: fail-closed `503` (default) or fail-open allow — this is the failure path the
    removed `fail_mode` knob was meant for. A `"memory"` store exercises the same shared-store
    code path in-process. *The Redis transport is compiled but, like ACME, is not covered by the
    in-process test suite (the GCRA core and the in-memory store are); see `src/limiter.rs`.*
  - **Public/private service split** (`server.admin_port` / `server.admin_addr`, or the
    `ADMIN_PORT` env var): when set, the internal ops endpoints (`/__edgeguard/health`, `/ready`,
    `/metrics`) are served on a separate, plain-HTTP **private listener**, keeping them off the
    public port; the public port serves only the proxy plus the browser-facing CSP report sink.
    The `/__edgeguard/*` namespace is now **reserved** — unknown internal paths return `404`
    rather than being forwarded upstream (`not_found` outcome). New `build_public_router` /
    `build_admin_router`, and a `limiter_error` outcome for fail-closed store errors.
- **Phase 3 / v1 (self-hostable & production-usable):**
  - **JWT auth** (`auth.mode = "jwt"`): HS/RS/ES/PS/EdDSA verification with either a static
    secret/PEM key or a fetched, **cached JWKS** (keys selected by `kid`, refreshed on miss or
    TTL expiry). The configured algorithm is pinned, so a token can't substitute its own `alg`
    (`alg=none`/HS-vs-RS confusion). Optional `issuer`/`audience`/leeway checks.
  - **Static API-key / bearer-token gate** (`auth.mode = "apikey"`): constant-time match of
    `Authorization: Bearer <key>` or a configurable header (default `X-API-Key`); keys may come
    from `EDGEGUARD_API_KEYS`.
  - **Per-route and per-key rate limits**: per-route overrides matched by longest path prefix
    (`[[ratelimit.routes]]`) and an optional per-principal limit (`[ratelimit.per_key]`) keyed
    by API-key id / JWT subject.
  - **TLS termination** (`[tls]`) via `rustls` + `tokio-rustls`, loading a PEM cert/key, with
    **ACME / Let's Encrypt** automatic certificates over HTTP-01 (`[tls.acme]`, via
    `instant-acme` + `rcgen`; staging by default). *ACME is compiled/CI-checked but provable
    only against a live CA — it binds port 80 and needs a public domain.*
  - **Prometheus metrics** at `/__edgeguard/metrics`: requests by outcome, rate-limit hits by
    scope, a request-latency histogram, and CSP report count (hand-rolled text exposition, no
    new metrics dependency).
  - **Config hot-reload** via `notify`: the config file is watched and policy is rebuilt and
    swapped atomically (`arc-swap`) with no dropped connections; an invalid edit is logged and
    the previous policy retained. The connection pool and metric counters survive a reload.
  - **CSP report-only mode + violation sink**: `headers.csp_report_only` emits
    `Content-Security-Policy-Report-Only`; `headers.csp_report_uri` appends a `report-uri`
    directive, and `POST /__edgeguard/csp-report` logs + counts received reports.
  - **Max-header-size limit** (`validation.max_header_bytes`): requests whose total header
    bytes exceed the cap get `431` (completes the Phase 3 timeout/header-size item).
- OSS launch scaffolding: dual `LICENSE-MIT` / `LICENSE-APACHE`, `CONTRIBUTING.md`, this
  changelog, and the `docs/` set (`REQUIREMENTS.md`, `DEPLOYMENT.md`, `ROADMAP.md`).
- `examples/` directory holding the deploy templates (`Dockerfile.node`,
  `Dockerfile.python`, `render.yaml`, `fly.toml`).
- Test suite (Phase 0): unit tests for `parse_size`, `parse_rate`, `client_ip` (XFF
  parsing), `harden_cookie`, and `check_basic_auth` (plaintext + argon2 + bad-creds paths);
  and in-process integration tests that drive the real pipeline against a stub upstream —
  401 without auth, 200 with auth, 429 over the limit, 413 on oversized body, 405 on a
  disallowed method, security headers injected, leaky headers stripped, cookie hardened, 502
  when the upstream is down, plus the health/readiness endpoints.
- `edgeguard --hash`: reads a password on stdin and prints an Argon2id PHC hash for
  `auth.users`, so operators don't need a separate argon2 tool.
- Configurable upstream timeout (`validation.upstream_timeout`, default `30s`; `0` disables):
  the proxy bounds the upstream request + body read with a single deadline and returns
  `504 Gateway Timeout` if the upstream stalls, instead of pinning the handler task.
- Library target (`src/lib.rs`) exposing `build_state` / `build_router`, so the binary and
  the tests share one code path rather than a reimplementation.

### Changed
- Restructured the repository into `src/` + `docs/` + `examples/` and rewrote the README as
  a clean, user-facing document (the product/requirements prose moved to `docs/`).
- `/__edgeguard/ready` now probes the upstream — it returns `200` only when the upstream
  accepts a connection, `503` otherwise — instead of always returning `200`.
  `/__edgeguard/health` remains unconditional liveness.
- Made the co-process supervisor cross-platform: Unix keeps full process-group signaling;
  Windows uses a `cmd /C` launch with a best-effort child kill on shutdown.
- `libc` is now a Unix-only dependency (`[target.'cfg(unix)'.dependencies]`).
- `argon2` now enables its `std` feature (provides the getrandom-backed `OsRng` the `--hash`
  helper uses to generate a salt).

### Removed
- `server.fail_mode` config field. It was parsed but never honored, and v0 has no failure
  path for it to govern (the in-memory limiter cannot fail; an unreachable upstream stays a
  `502`). EdgeGuard remains fail-closed; a configurable fail-open returns with the
  distributed limiter (see `docs/ROADMAP.md`, Phase 4). Configs that still set `fail_mode`
  are ignored, not rejected.

### Security
- `X-Forwarded-For` is no longer trusted by default — client identity uses the real peer
  address unless `server.trust_forwarded_for` is enabled (behind a trusted proxy). Prevents
  spoofed per-IP rate limiting and forged access logs.
- Cookie hardening now parses cookie attributes by token instead of substring matching, so
  a value like `session=securetoken` can no longer skip the `Secure` flag.
- The default `auth.users` value is a non-working placeholder rather than a plaintext
  password, so the shipped config can't be copied straight to production.

### Fixed
- The crate now compiles on Windows (previously failed with 7 errors from Unix-only
  `setsid`/`pre_exec`/`libc::kill` usage in the supervisor).
- `parse_size` is now overflow-checked (returns an error instead of silently wrapping).
- The startup readiness wait is skipped when pointing at an external `UPSTREAM`, avoiding a
  needless cold-start stall.
- Added an optional `validation.max_response_body` cap so a huge upstream response can't
  OOM the proxy.

[Unreleased]: https://github.com/lucheeseng827/eggrd/compare/v0.7.0-rc.1...HEAD
[0.7.0-rc.1]: https://github.com/lucheeseng827/eggrd/compare/v0.5.0...v0.7.0-rc.1
[0.5.0]: https://github.com/lucheeseng827/eggrd/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/lucheeseng827/eggrd/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/lucheeseng827/eggrd/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/lucheeseng827/eggrd/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/lucheeseng827/eggrd/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/lucheeseng827/eggrd/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/lucheeseng827/eggrd/compare/v0.1.5...v0.2.0
[0.1.3]: https://github.com/lucheeseng827/eggrd/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/lucheeseng827/eggrd/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/lucheeseng827/eggrd/releases/tag/v0.1.1
[0.1.0]: https://crates.io/crates/eggrd/0.1.0
