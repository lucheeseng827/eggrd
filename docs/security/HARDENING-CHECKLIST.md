# eggrd hardening checklist

For eggrd **0.7.0** and 0.7.1 (run 0.7.1: EG-HARD-241). Every key below was checked against
`src/config.rs` at 0.7.0, every TOML block loads and passes `edgeguard doctor` with 0 errors on the released
image, and every metric and alert name was checked against `src/` and `monitoring/`. What was
run, and what was only written, is in [README.md](README.md#what-was-tested).

Each item has a stable ID (`EG-HARD-NNN`), so a ticket, an audit or a runbook can cite it. IDs
are grouped by layer in blocks of twenty, and an ID is never reused. The machine-readable copy is
[`checklist.yaml`](checklist.yaml).

- **Severity**: *Critical* (exploitable from the internet, or silently disables another control),
  *High*, *Medium*, *Low*.
- **[App]**: the edge cannot finish this alone; the application must change too.
- **[0.8]**: a workaround until a planned 0.8 setting. **[Gap]**: no 0.7 setting exists and none
  is planned yet; the item says what to do instead.
- **Reference**: the tested setup under [`deploy/reference/`](../../deploy/reference/) that
  implements it. A complete hardened file for a single VM is
  [`examples/edgeguard.hardened.toml`](examples/edgeguard.hardened.toml).

Commands use `app.example.com` for the public name, `EDGE` for the edge's address and
`ADMIN=http://127.0.0.1:9090` for the admin listener. The configuration reference is
[eggrd.dev/docs/config.html](https://eggrd.dev/docs/config.html).

## Contents

| Layer | IDs | Items |
|---|---|---|
| [Network and placement](#network-and-placement) | 001–019 | 7 |
| [TLS and mTLS](#tls-and-mtls) | 020–039 | 8 |
| [Client identity and IP](#client-identity-and-ip) | 040–059 | 6 |
| [Request validation](#request-validation) | 060–079 | 5 |
| [WAF](#waf) | 080–099 | 4 |
| [Authentication](#authentication) | 100–119 | 6 |
| [Rate limiting](#rate-limiting) | 120–139 | 5 |
| [Response headers](#response-headers) | 140–159 | 7 |
| [Upstream](#upstream) | 160–179 | 6 |
| [Secrets and files](#secrets-and-files) | 180–199 | 5 |
| [Container and pod runtime](#container-and-pod-runtime) | 200–219 | 7 |
| [Supply chain](#supply-chain) | 220–239 | 3 |
| [Operations](#operations) | 240–259 | 8 |

**Where to start:** 001, 002, 040/041 (or 044 behind an L4 balancer), 080, 082, 120, 200–203,
220, 241, 243.

---

## Network and placement

### EG-HARD-001 · Only the load balancer reaches the traffic port

**Severity:** Critical · **Reference:** [kubernetes](../../deploy/reference/kubernetes/) (`networkpolicies.yaml`), [aws-nlb](../../deploy/reference/aws-nlb/), [aws-alb](../../deploy/reference/aws-alb/)

**Why.** Behind a balancer, eggrd believes `X-Forwarded-For` (with `trust_forwarded_for`) or the
PROXY header (from `proxy_protocol_trusted`). Whatever reaches the traffic port directly (another
pod, a host in the VPC, the internet through a forgotten security-group rule) writes the whole
header and chooses its own client address: a fresh rate-limit bucket per request, a way past
`[access]` deny lists, and forged addresses in your logs. It also walks around whatever the
balancer enforces (a cloud WAF, its own TLS policy). 0.7 believes the header from every peer; 0.8
plans `server.trusted_forwarders` to name the peers in eggrd itself.

**Config.** Network, not eggrd: the edge's security group admits 80/443 from the balancer's
security group (or its subnets) only; on Kubernetes a NetworkPolicy admits the traffic port from
the balancer's source ranges only. When eggrd *is* the edge (no balancer), 80/443 from anywhere is
correct, and `trust_forwarded_for` stays `false` (EG-HARD-040).

**Verify.**
```sh
# From a host that is not the balancer (another pod, a VM in the VPC): must time out or be refused.
curl -sk --connect-timeout 3 -o /dev/null -w '%{http_code}\n' https://EDGE/
# Behind an L7 balancer, requests that arrive without the balancer's header:
#   PromQL  sum(rate(edgeguard_forwarded_for_total{result="absent"}[1h]))   ~ 0
```
The reference alert `EdgeGuardForwardedForFallback`
([rules-0.7.yml](../../deploy/reference/monitoring/prometheus/rules-0.7.yml)) fires when more than
10% of requests fall back to the TCP peer.

### EG-HARD-002 · The admin listener is off the public port, on loopback or a private network

**Severity:** High · **Reference:** every setup (`admin_port = 9090`)

**Why.** `/__edgeguard/*` (health, ready, metrics, tls, upstreams) is exempt from auth, rate
limiting, the WAF and `[access]` by design. On the public port it tells anyone your route names,
upstream addresses, certificate details and, with authentication on, your consumers' names. With
`admin_port` set, the public port answers every `/__edgeguard/*` path except the CSP sink with
`404` (outcome `not_found`).

**Config.**
```toml
[server]
admin_port = 9090
admin_addr = "127.0.0.1"   # same host; "0.0.0.0" inside a container published to 127.0.0.1 only
```

**Verify.**
```sh
curl -sk -o /dev/null -w '%{http_code}\n' https://app.example.com/__edgeguard/metrics   # 404
curl -s -o /dev/null -w '%{http_code}\n' "$ADMIN/__edgeguard/ready"                     # 200, from the host only
```

### EG-HARD-003 · No app-internal endpoint is routed to the internet

**Severity:** High · **[App]** · **Reference:** —

**Why.** A real deployment routed the app's own `/metrics` to the backend through a
`[[upstreams]]` prefix, and two unknown addresses scraped about thirty internal metric families
from it. eggrd forwards whatever a route matches. Debug, actuator, metrics, admin and health
endpoints of the *app* need their own network path (the app's port on a private network, scraped
there), not a public prefix.

**Config.** Remove such `[[upstreams]]` prefixes. Refuse the paths at the edge as a backstop:
```toml
[waf]
mode = "block"
inspect_path = true

[[waf.rules]]
id      = "app-internal-paths"
target  = "path"
pattern = '(?i)^/+(\./+)*(metrics|debug|actuator|admin/internal)([/;?]|$)'
```

**Verify.**
```sh
curl -s https://app.example.com/metrics | grep -c '^# HELP'    # 0 (a soft-200 HTML page can still come back: EG-HARD-146)
```

### EG-HARD-004 · The host exposes 80/443 and nothing else

**Severity:** Medium · **Reference:** [compose-single-vm](../../deploy/reference/compose-single-vm/)

**Why.** The edge's host often runs more listeners than the edge: sshd, a Kubernetes API server
(6443), the kubelet (10250), NodePorts (30000–32767), the container runtime's API. A cloud
security group is one layer; a mistake there exposes all of them.

**Config.** Security group: 80/443 only (from the balancer, EG-HARD-001). Host firewall that drops
new connections to everything else on the public interface. Prefer a session manager to an open
sshd. On single-node k3s, do not use ufw's default `FORWARD DROP` (it breaks pod networking); drop
on the public interface in the `raw` table instead, or bind the services to a private address.

**Verify.**
```sh
ss -tlnp                      # every listener and its process
nc -vz -w 5 EDGE 22 6443 10250 30080   # from outside: all time out
```

### EG-HARD-005 · Kubernetes: default-deny NetworkPolicies around the edge and the app

**Severity:** High · **Reference:** [kubernetes](../../deploy/reference/kubernetes/) (`base/networkpolicies.yaml`)

**Why.** A compromised edge should reach the app's port and nothing else: not the database, not
the API server, not the cloud metadata service. And the app should accept traffic only from the
edge, so nothing bypasses the WAF and the rate limits.

**Config.** Default deny in both namespaces. Edge ingress: 80/443 from the balancer's ranges, the
admin port from the monitoring namespace. Edge egress: the app's pod port (policies apply after
the Service's DNAT, so name the *pod* port), DNS, and TCP 443 to the internet minus the pod and
service CIDRs and `169.254.169.254/32` (for ACME and a JWKS). App ingress: from the edge only.
On EKS's VPC CNI, an egress rule to a multi-port Service also needs an `ipBlock` for the service
CIDR.

**Verify.**
```sh
# A pod with the edge's labels must not reach the database or the API server. The override makes
# it pass Pod Security "restricted"; without it, a restricted namespace refuses the pod.
kubectl -n eggrd-edge run np-check --rm -i --restart=Never --labels=app=eggrd \
  --image=docker.io/curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"np-check","image":"docker.io/curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69","command":["sh","-c","sleep 5; curl -sk -m 3 -o /dev/null -w \"%{http_code}\\n\" https://kubernetes.default.svc"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},"readinessProbe":{"exec":{"command":["false"]},"periodSeconds":1}}]}}'
# expect "000" (a timeout); the same pod pointed at the app's Service must answer.
# The label puts the pod under the edge's NetworkPolicy, but it also matches the edge Service's
# selector. The readinessProbe of `false` keeps it never-Ready, so it is never a serving endpoint.
# Measured on k3s v1.31.14: with a Service whose targetPort is a number, the pod WITHOUT the probe
# was a ready endpoint for its whole life (client traffic would reach a container listening on
# nothing); WITH it, it stayed in notReadyAddresses only. (The reference Services target the named
# ports https/http, which this pod lacks, so it was never their endpoint either way.)
# The sleep matters: a policy controller can take a second or two to apply to a new pod, and a probe
# sent at once gets through (measured on k3s v1.31: 401 from the API server at once, 000 after 5 s;
# the app's Service 200 either way). The override was also checked: without it, a restricted
# namespace refuses the pod.
```

### EG-HARD-006 · No Service exposure the setup does not use

**Severity:** Medium · **Reference:** [kubernetes](../../deploy/reference/kubernetes/) (ClusterIP `eggrd`, `eggrd-admin`)

**Why.** A `NodePort` left beside a `hostPort` or a LoadBalancer opens the edge on every node's
high port, often outside the security group's intent. The admin port as a LoadBalancer Service is
EG-HARD-002 in another form.

**Config.** The public Service is the balancer (`LoadBalancer`, `externalTrafficPolicy: Local`) or
`hostPort`; everything else is `ClusterIP`. The admin Service is `ClusterIP`, reached by Prometheus
through the NetworkPolicy.

**Verify.**
```sh
kubectl -n eggrd-edge get svc -o custom-columns=NAME:.metadata.name,TYPE:.spec.type,PORTS:.spec.ports[*].nodePort
```

### EG-HARD-007 · The edge cannot read the cloud metadata service

**Severity:** Medium · **Reference:** [kubernetes](../../deploy/reference/kubernetes/) (egress `except`)

**Why.** An SSRF in the app, or code execution in the edge's container, turns the metadata
service into instance credentials. eggrd itself never calls it.

**Config.** On EC2: IMDSv2 required (`HttpTokens=required`) and a hop limit of 1 for containers. On
Kubernetes: the edge's egress policy excepts `169.254.169.254/32`.

**Verify.**
```sh
curl -s -m 3 http://169.254.169.254/latest/meta-data/   # from the edge's network namespace: 401 (IMDSv2) or a timeout
```

---

## TLS and mTLS

### EG-HARD-020 · A publicly trusted certificate, from the ACME production directory you named

**Severity:** High · **Reference:** [compose-single-vm](../../deploy/reference/compose-single-vm/) (`config-acme/`), [kubernetes](../../deploy/reference/kubernetes/) (hostPort overlay)

**Why.** `[tls.acme] directory_url` defaults to Let's Encrypt **staging**, whose certificates no
browser trusts; a staging certificate in production trains users to click through warnings.
`self_signed = true` proves no identity (doctor warns). Behind a balancer that terminates TLS, the
balancer's certificate is the one that matters, and the edge-to-balancer hop is covered by
EG-HARD-160 in the other direction.

**Config.**
```toml
[tls]
enabled = true
cert_path = "/var/lib/edgeguard/cert.pem"
key_path = "/var/lib/edgeguard/key.pem"

[tls.acme]
enabled = true
domains = ["app.example.com"]
email = "security@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
cache_dir = "/var/lib/edgeguard/acme"
accept_tos = true
```

**Verify.**
```sh
openssl s_client -connect EDGE:443 -servername app.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -dates
curl -s "$ADMIN/__edgeguard/tls"     # "source":"acme", "self_issued":false, days_left
```

### EG-HARD-021 · The plaintext redirect listener only reflects your own names

**Severity:** Medium · **[0.8]** · **Reference:** [compose-single-vm](../../deploy/reference/compose-single-vm/), [kubernetes](../../deploy/reference/kubernetes/)

**Why.** A browser given a bare name tries port 80 first; without a redirect that first request is
plaintext. The redirect builds `Location` from the `Host` header, which the client writes: with
`redirect_hosts` empty it reflects any syntactically valid host, an open redirect under your IP's
reputation. In 0.7 the `Location` carries `server.port`, so an edge listening on 8443 behind a 443
Service sends visitors to `:8443`; listen on 443 inside the pod (0.8 plans `tls.redirect_to_port`).

**Config.**
```toml
[tls]
redirect_port = 80
redirect_status = 308
redirect_hosts = ["app.example.com"]
```

**Verify.**
```sh
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://app.example.com/x       # 308 https://app.example.com/x
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' -H 'Host: evil.example' http://EDGE/   # no redirect to evil.example
```

### EG-HARD-022 · Certificates renew in process, and you are told when they do not

**Severity:** High · **Reference:** [compose-single-vm](../../deploy/reference/compose-single-vm/), [monitoring](../../deploy/reference/monitoring/)

**Why.** An expired certificate is an outage, and a renewal that fails quietly for weeks is one
waiting to happen. ACME renewal runs at two-thirds of the lifetime, earlier when the CA's ARI
window says so (a CA that must revoke after an incident uses ARI to hurry renewals).

**Config.**
```toml
[tls.acme]
renew = true
ari = true
budget_enabled = true
```
and the bundle alerts `EdgeGuardCertExpiringSoon` (14 days), `EdgeGuardCertExpiringCritical`
(3 days), `EdgeGuardCertRenewalFailing` (6 h of failures), `EdgeGuardAcmeBudgetLow` /
`EdgeGuardAcmeBudgetExhausted`.

**Verify.**
```sh
curl -s "$ADMIN/__edgeguard/metrics" | grep -E '^edgeguard_tls_cert_(not_after_seconds|renewals_total)'
edgeguard doctor --config edgeguard.toml    # warns on tls.acme.renew = false and on a certificate past two-thirds
```

### EG-HARD-023 · Certificates you bring are watched for expiry

**Severity:** Medium · **Reference:** [hybrid-pools](../../deploy/reference/hybrid-pools/)

**Why.** `[[tls.certs]]` pairs, a certificate written by cert-manager or certbot, client
certificates for upstreams and the CAs in `client_auth.ca_path` are reloaded when they change but
renewed by nothing in eggrd. They appear in `edgeguard_tls_cert_not_after_seconds`, so the same
expiry alerts cover them.

**Config.** `tls.watch = true` (the default) so a renewed pair is picked up without a restart; the
expiry alerts of EG-HARD-022 routed to someone.

**Verify.**
```sh
curl -s "$ADMIN/__edgeguard/tls"    # every certificate, CA and CRL with days_left
```

### EG-HARD-024 · Machine clients use mutual TLS, narrowed to the names you expect

**Severity:** High (where machine clients exist) · **Reference:** [aws-nlb](../../deploy/reference/aws-nlb/) (mTLS passthrough), [aws-alb](../../deploy/reference/aws-alb/) (`mtls-passthrough/`)

**Why.** A bearer API key is replayable by anyone who copies it; a client certificate's key does
not leave the client. `auth.mode = "mtls"` with an empty `[auth.mtls] allowed` admits every
certificate the CA ever issued, including ones issued for other purposes.

**Config.** eggrd must terminate TLS itself (or the balancer forwards the certificate:
EG-HARD-045).
```toml
[tls]
enabled = true
cert_path = "/var/lib/edgeguard/cert.pem"
key_path = "/var/lib/edgeguard/key.pem"

[tls.client_auth]
mode = "required"
ca_path = "/etc/edgeguard/pki/clients-ca.pem"
crl_paths = ["/etc/edgeguard/pki/clients-ca.crl.pem"]
forward_client_cert = "xfcc"

[auth]
mode = "mtls"

[auth.mtls]
allowed = ["spiffe://example.com/ns/payments-worker/*", "reporting.internal.example.com"]
```

**Verify.**
```sh
curl -sk -o /dev/null -w '%{http_code}\n' https://EDGE/                           # handshake refused without a certificate
curl -sk --cert c.pem --key c.key -o /dev/null -w '%{http_code}\n' https://EDGE/   # 200
# PromQL  rate(edgeguard_tls_handshake_failures_total{reason="client_cert"}[5m]); alert EdgeGuardClientCertRejectSpike
```

### EG-HARD-025 · Revocation lists are fresh

**Severity:** Medium · **Reference:** [aws-nlb](../../deploy/reference/aws-nlb/)

**Why.** A CRL past its `nextUpdate` is still used, so a certificate revoked since keeps working.
With `crl_paths` set, a certificate whose issuer has no CRL there is refused, so a missing CRL
fails closed but a stale one fails open.

**Config.** A job that fetches each CRL into the same file before its `nextUpdate`; it is reloaded
without a restart. Alert `EdgeGuardCrlStale`.

**Verify.**
```sh
curl -s "$ADMIN/__edgeguard/tls"    # client_auth.crls[].stale must be false
```

### EG-HARD-026 · Old protocol versions are refused (built in: verify only)

**Severity:** Low · **Reference:** every TLS setup

**Why.** eggrd uses rustls: TLS 1.2 and 1.3 with modern AEAD suites only, nothing to configure.
Scanners still try TLS 1.0/1.1 and CBC suites; they fail the handshake and count as
`edgeguard_tls_handshake_failures_total{reason="other"}`.

**Verify.**
```sh
openssl s_client -connect EDGE:443 -tls1_1 </dev/null    # "no protocols available" / alert
openssl s_client -connect EDGE:443 -tls1_2 -cipher AES128-SHA </dev/null   # handshake failure
```

### EG-HARD-027 · Raw-IP and wrong-name connections are expected noise, refused by the Host rule

**Severity:** Low · **Reference:** every setup with the Host rule (EG-HARD-082)

**Why.** Scanners connect by IP address. A client that sends an IP literal as its SNI makes rustls
log `Illegal SNI extension: ignoring IP address presented as hostname` (WARN): in one six-week log
that line was 14% of all lines. It is not an attack on eggrd. The certificate is still served (the
default pair), and the request is answered by the Host rule (403) or the app.

**Config.** Do not alert on that warning; keep the Host rule (EG-HARD-082). Filter the line out of
dashboards rather than out of the archive.

**Verify.**
```sh
curl -sk -o /dev/null -w '%{http_code}\n' https://EDGE_IP/     # 403 with the Host rule in block mode
```

---

## Client identity and IP

### EG-HARD-040 · `trust_forwarded_for` only behind an L7 proxy you control

**Severity:** Critical · **Reference:** [aws-alb](../../deploy/reference/aws-alb/) (`true`), [compose-single-vm](../../deploy/reference/compose-single-vm/) (`false`)

**Why.** With `trust_forwarded_for = true` and nothing in front, every client writes its own
address: per-IP limits, `[access]`, the access log, pool hashing on `client_ip`, spans and the
app's `X-Forwarded-For` all take the client's word. With `false` (the default) the TCP peer is the
client, which is right when eggrd is the edge and wrong behind a proxy (every request looks like
the proxy: one bucket, a site-wide 429).

**Config.**
```toml
[server]
trust_forwarded_for = false   # eggrd is the edge; true only behind an L7 balancer (EG-HARD-041)
```

**Verify.**
```sh
edgeguard doctor --config edgeguard.toml   # notes trust_forwarded_for and forwarded_hops; warns on hops without trust
# With trust on: a client that reaches eggrd directly must not be able to (EG-HARD-001).
```

### EG-HARD-041 · `forwarded_hops` matches what the proxies in front append

**Severity:** Critical · **Reference:** [aws-alb](../../deploy/reference/aws-alb/) (`configs/`)

**Why.** 0.7.0 takes the entry `forwarded_hops` from the **right** of `X-Forwarded-For`: the one
the trusted proxy appended. Before 0.7.0 the leftmost entry was used, which the client writes, so
any client could pick its address through the balancer; upgrade (EG-HARD-241). Too low a count
takes the balancer's address for every client (one bucket for everyone, `[access]` allowlists lock
everyone out); too high lets the client choose.

| In front of eggrd | `forwarded_hops` | Source |
|---|---|---|
| AWS ALB, `routing.http.xff_header_processing.mode = append` (default) | 1 | AWS documentation; behaviour run with an nginx stand-in in [aws-alb](../../deploy/reference/aws-alb/) |
| GCP external Application Load Balancer | **2** | Google documentation; stand-in in aws-alb (`configs/gcp-alb.toml`) |
| CloudFront → ALB | 2 | AWS documentation; stand-in in aws-alb (`configs/cloudfront-alb.toml`) |
| Cloudflare | 1 | Cloudflare documentation only |
| Azure Application Gateway (v2 writes `ip:port` entries) | 1 | Microsoft documentation; the `ip:port` form **measured** on 0.7.0 with an nginx stand-in: `198.51.100.5:43210` and `[2001:db8::7]:51234` resolve to the address, port stripped (`result="used"`) |
| nginx `$proxy_add_x_forwarded_for`, nginx replacing the header | 1 | **Measured** with nginx stand-ins (append, replace) |
| Traefik | 1 | Traefik documentation only |
| Anything else (Cloud Run and other Google Front End services included) | measure first | — |

None of these balancers was run here; a row "from documentation" is the vendor's statement, not a
test. **Measure your own chain whatever the table says** (the verify step below).

**Config.**
```toml
[server]
trust_forwarded_for = true
forwarded_hops = 2          # GCP external Application LB, or CloudFront -> ALB
```

**Verify.** Send a spoofed entry through the balancer and read what eggrd resolved:
```sh
curl -s -o /dev/null -H 'X-Forwarded-For: 192.0.2.1' https://app.example.com/
# the access record's client_ip must be your own public address, not 192.0.2.1 and not the balancer's.
# PromQL  sum by (result) (rate(edgeguard_forwarded_for_total[15m]))   short/invalid ~ 0
```
`result="used"` does not prove the count is right; only the comparison with a known client does.

### EG-HARD-042 · In a chain, every inner proxy accepts only the one in front of it

**Severity:** High · **Reference:** [aws-alb](../../deploy/reference/aws-alb/) (`cloudfront-lock/main.tf`)

**Why.** With CloudFront → ALB → eggrd and `forwarded_hops = 2`, a client that reaches the ALB
directly sends `X-Forwarded-For: 192.0.2.9`, the ALB appends the client's real address, and eggrd
resolves `192.0.2.9`. eggrd only sees its own peer (the ALB), so no eggrd setting closes this,
0.8's included.

**Config.** The ALB's security group admits only CloudFront's origin-facing managed prefix list,
and an ALB listener rule requires a secret header that CloudFront adds (the prefix list admits
every CloudFront distribution, not only yours).

**Verify.**
```sh
curl -sk -o /dev/null -w '%{http_code}\n' https://ALB_DNS_NAME/    # times out, or the ALB's fixed 403
```

### EG-HARD-043 · An ALB appends; it never preserves

**Severity:** High · **Reference:** [aws-alb](../../deploy/reference/aws-alb/)

**Why.** In `preserve` mode the ALB appends nothing, so the rightmost entry is the client's own
writing; in `remove` mode there is no header and every client is the ALB (`absent`).

**Config.** ALB attribute `routing.http.xff_header_processing.mode = append` (the default), with
`forwarded_hops = 1`.

**Verify.**
```sh
aws elbv2 describe-load-balancer-attributes --load-balancer-arn "$ALB_ARN" \
  --query "Attributes[?Key=='routing.http.xff_header_processing.mode']"
```

### EG-HARD-044 · PROXY protocol is believed from the L4 balancer only

**Severity:** High · **Reference:** [aws-nlb](../../deploy/reference/aws-nlb/)

**Why.** Behind an L4 balancer (NLB, a TCP proxy, HAProxy) the client's address arrives in a PROXY
header. From any peer outside `proxy_protocol_trusted` a connection that starts with one is closed,
so a wrong list is an outage, and a `/0` (refused at load) would let anyone choose an address.
Combining it with `trust_forwarded_for` lets a client behind the L4 balancer write a header that is
believed (doctor warns).

**Config.**
```toml
[server]
proxy_protocol = true
proxy_protocol_trusted = ["10.0.0.0/24", "10.0.1.0/24"]   # the NLB's subnets
trust_forwarded_for = false
```
NLB: client IP preservation **off** (with it on, the peer is the client and every connection is
`untrusted`); health check over HTTP on the admin port (`/__edgeguard/ready`, which reads the NLB's
`LOCAL` header in 0.7.0). Alerts: `EdgeGuardProxyProtocolRefused`,
`EdgeGuardProxyProtocolRefusedLowRate`, `EdgeGuardProxyProtocolMissing`.

**Verify.**
```sh
curl -s "$ADMIN/__edgeguard/metrics" | grep '^edgeguard_proxy_protocol_total'
# proxied rising, untrusted and invalid flat. A TCP health check stays green even when every
# connection is refused, so do not rely on it.
```

### EG-HARD-045 · A forwarded client certificate is trusted from the balancer only

**Severity:** High · **Reference:** [aws-alb](../../deploy/reference/aws-alb/) (`mtls-passthrough/`, `configs/trusted-proxy-names.toml`)

**Why.** With `[trusted_client_cert_header]`, the header becomes the request's client certificate
and `auth.mode = "mtls"` authenticates by it. Anyone who can write that header from a trusted
address chooses an identity. An ALB in passthrough mode forwards certificates it did not verify.

**Config.**
```toml
[trusted_client_cert_header]
name = "X-Amzn-Mtls-Clientcert"
format = "pem"
trusted_proxies = ["10.0.0.0/24", "10.0.1.0/24"]   # the ALB's subnets; /0 is refused
ca_path = "/etc/edgeguard/pki/clients-ca.pem"       # passthrough: eggrd verifies the chain itself
```
With `trusted_proxy_names`, give the balancers a CA of their own: with `auth.mode = "mtls"` and an
empty `[auth.mtls] allowed`, any certificate from the balancer's CA authenticates as itself
(doctor warns).

**Verify.**
```sh
curl -sk -H 'X-Amzn-Mtls-Clientcert: forged' -o /dev/null -w '%{http_code}\n' https://EDGE/   # direct: 401, counted untrusted_peer
# PromQL  rate(edgeguard_client_cert_header_total{result!="accepted"}[5m]); alert EdgeGuardClientCertHeaderRefused
```

---

## Request validation

### EG-HARD-060 · Only the methods the app uses

**Severity:** Medium · **Reference:** every setup

**Why.** `allow_methods` is empty by default (all methods). Scanners send `CONNECT`, `PROPFIND`,
`TRACE`, `SSTP_DUPLEX_POST` (an SSL-VPN probe) and random four-letter verbs to find proxies, WebDAV
and appliances behind you. Refusing them at the edge costs nothing.

**Config.**
```toml
[validation]
allow_methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
```

**Verify.**
```sh
curl -sk -X PROPFIND -o /dev/null -w '%{http_code}\n' https://app.example.com/   # 405, outcome method_not_allowed
```

### EG-HARD-061 · Request bodies are capped at what the app accepts

**Severity:** Medium · **Reference:** every setup

**Why.** The default `max_body` is 2 MiB. A cap at what the app really takes stops memory
exhaustion through the edge and makes WAF body inspection cheaper. With `stream_requests` on, a
body over the cap is cut after the upstream has seen its start.

**Config.**
```toml
[validation]
max_body = "5MiB"
```

**Verify.**
```sh
head -c 6000000 /dev/zero | curl -sk -X POST --data-binary @- -o /dev/null -w '%{http_code}\n' https://app.example.com/api/upload   # 413
```

### EG-HARD-062 · Request headers are capped

**Severity:** Medium · **Reference:** [examples/edgeguard.hardened.toml](examples/edgeguard.hardened.toml)

**Why.** `max_header_bytes` is `0` (off) by default, leaving only hyper's transport limit. Oversized
headers are a cheap way to exhaust memory and to smuggle payloads past inspection limits.

**Config.**
```toml
[validation]
max_header_bytes = "32KiB"
```

**Verify.**
```sh
curl -sk -H "X-Pad: $(head -c 40000 /dev/zero | tr '\0' a)" -o /dev/null -w '%{http_code}\n' https://app.example.com/   # 431
```

### EG-HARD-063 · Slow clients are cut off

**Severity:** High · **Reference:** every setup

**Why.** `header_read_timeout` (30 s by default) runs before auth and rate limiting: without it a
handful of clients sending a header a byte at a time hold sockets forever (slowloris). It also
closes keep-alive connections idle that long. With PROXY protocol, the PROXY header and the first
request head share the one deadline in 0.7.0. `"0"` disables it, and doctor warns.

**Config.**
```toml
[server]
header_read_timeout = "30s"
```
Startup-only: a change needs a restart.

**Verify.** Measured on 0.7.0: a client that sent half a request head was closed after the
configured timeout and logged `connection ended with an error: read header from client timeout`
(DEBUG, `edgeguard::serve`).
```sh
(printf 'GET / HTTP/1.1\r\nHost: app.example.com\r\n'; sleep 40) | openssl s_client -quiet -connect EDGE:443   # closed at ~30 s
```

### EG-HARD-064 · Connections are capped, and you see the cap approach

**Severity:** Medium · **Reference:** every setup (`max_connections = 1024`/`2048`)

**Why.** `max_connections` is `0` (unlimited) by default. A cap keeps a connection flood from
taking the process's memory and file descriptors; the admin listener has no cap, so health checks
and scrapes still answer when the public port is full.

**Config.**
```toml
[server]
max_connections = 1024
```
Alert `EdgeGuardConnectionsNearCap` (above 80% for 5 m). Startup-only.

**Verify.**
```sh
curl -s "$ADMIN/__edgeguard/metrics" | grep -E '^edgeguard_connections_(open|max|rejected_total)'
```

---

## WAF

### EG-HARD-080 · The WAF blocks, after a report-mode review

**Severity:** High · **Reference:** every setup (`mode = "block"`)

**Why.** `[waf] mode` is `off` by default. In report mode a match is logged and counted but the
request is forwarded: in one deployment a `' OR '1'='1` probe was refused by an edge in block mode
and reached the app through another left in report mode with header and body inspection off.
Roll out in report mode, read the matches, then block. In a real review, 54 matches in 13 hours of
report mode were all scanners, with no false positive from body inspection on an ingest API; the
switch to block then cost nothing.

**Config.**
```toml
[waf]
mode = "block"
sqli = true
xss = true
path_traversal = true
inspect_path = true
inspect_headers = true
inspect_body = true
```
The switch is a hot reload: measured at 0.21 s on 0.7.0 with a directory-mounted config
([INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md#containment-levers)).

**Verify.**
```sh
curl -sk -o /dev/null -w '%{http_code}\n' "https://app.example.com/api/x?id=1%27%20OR%20%271%27=%271"   # 403
# during the report phase: the "WAF hits by rule" query in LOGGING-AND-EVIDENCE.md; alert EdgeGuardWafBlockSpike
```

### EG-HARD-081 · Inspection covers the locations attacks use, and you know what streaming skips

**Severity:** Medium · **Reference:** [examples/edgeguard.hardened.toml](examples/edgeguard.hardened.toml)

**Why.** `inspect_headers` and `inspect_body` are off by default; a custom rule on a location whose
`inspect_*` flag is off never runs (and a misspelt flag is silently ignored: EG-HARD-240). A
request body that streams (`stream_requests`) is not inspected unless its route is listed in
`[[validation.stream_inspect]]`, and then only within a window. WebSocket frames are never
inspected. The WAF matches the path raw and percent-decoded, which caught every path-mangling
variant seen in the wild (`%2e%2e`, `..;/`, `%2f`, doubled slashes, changed case).

**Config.** `inspect_path = true` and `inspect_headers = true` always; `inspect_body = true` once
the report run shows your legitimate bodies (JSON with SQL-ish words, diffs with `../`) do not
match, or per route through `[[validation.stream_inspect]]` for streamed uploads.

**Verify.**
```sh
curl -sk -H 'Referer: <script>alert(1)</script>' -o /dev/null -w '%{http_code}\n' https://app.example.com/   # 403 needs inspect_headers
```

### EG-HARD-082 · Every Host but yours is refused (the Host rule)

**Severity:** High · **[0.8]** · **Reference:** every setup ([`tools/host-rule.sh`](../../deploy/reference/tools/host-rule.sh))

**Affected:** 0.7.0 and earlier. **Fixed:** 0.7.1 (#1748; CHANGELOG.md, 0.7.1, Security). **Upgrade** to 0.7.1; the two bypasses below are fixed there; the Host
rule itself is still the 0.7.x way to refuse other names.

**Why.** 0.7 has no allowed-hosts setting (0.8 plans `allowed_hosts`). Without one, eggrd serves
any `Host`: raw-IP requests from scanners, forged names that poison password-reset links built
from `Host` or `X-Forwarded-Host` (eggrd sets `X-Forwarded-Host` to the `Host` it received, which
the client chose), and cache keys keyed on the host.

**Config.** The WAF in block mode with header inspection, plus a rule generated for your name (the
regex engine has no lookahead, so the script spells out the complement):
```sh
deploy/reference/tools/host-rule.sh app.example.com >> edgeguard.toml
```
One rule per name. Pair it with app-side Host validation (EG-HARD-161).

**The rule has two holes in 0.7.0** (measured; it matches a `host:` line, so it cannot act when
there is none). Both are fixed in 0.7.1 (#1748): the WAF sees one effective host per request, the h2
authority included, and a request with no host is refused or matched as an empty `host:` line. On
0.7.0 ("the plain listener" below is the **proxy** listener serving plain HTTP: `server.port` with
`[tls]` off, typically `:8080` behind a TLS-terminating balancer. The `:80` redirect listener only
redirects and is not what the h2c rows describe. An edge that terminates TLS itself, as in
`examples/edgeguard.hardened.toml`, has no plain proxy listener and is exposed only to the no-Host
row):

| Request | Result |
|---|---|
| HTTP/1.1 or HTTP/2 over TLS with `Host: evil.example` (the TLS listener offers only `http/1.1` in ALPN, so `--http2` falls back) | 403 |
| HTTP/1.1 on the plain listener with `Host: evil.example` | 403 |
| **Cleartext HTTP/2 with prior knowledge** (`curl --http2-prior-knowledge`) on the plain listener, `:authority` = `evil.example`, no `Host` header | **200**, and the app received `X-Forwarded-Host: evil.example` |
| h2c by `Upgrade: h2c` | 403 (served as HTTP/1.1) |
| **No `Host` header at all** (HTTP/1.0, or HTTP/1.1 without one), plain or TLS | **200** (no `X-Forwarded-Host` reaches the app) |

Mitigations until eggrd checks the authority itself: terminate TLS in eggrd, or let only the
balancer reach the plain listener (EG-HARD-001), and do not put a proxy configured for h2c to
targets (Envoy, gRPC proxies) in front of it; validate the host in the app before building any link from `Host` or
`X-Forwarded-Host`, and refuse requests that carry neither (EG-HARD-161).

**Verify.** Measured on 0.7.0: raw IP and `evil.example` → 403, `app.example.com` and
`app.example.com:443` → 200. Pin the protocol, and include h2c if the edge has a plain proxy listener:
```sh
curl -sk --http1.1 -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' https://EDGE/   # 403
curl -sk --http2   -o /dev/null -w '%{http_code} %{http_version}\n' -H 'Host: evil.example' https://EDGE/   # 403 1.1
curl -sk -o /dev/null -w '%{http_code}\n' https://EDGE_IP/                                   # 403
curl -s --http2-prior-knowledge -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' http://EDGE:8080/   # the plain proxy listener (server.port, [tls] off): 200 on 0.7.0, 403 on 0.7.1
```
It counts in `edgeguard_waf_hits_total{rule="custom"}` and logs `rule":"host-allowlist"`.

### EG-HARD-083 · Paths that are never valid are refused at the edge

**Severity:** Medium · **Reference:** [examples/edgeguard.hardened.toml](examples/edgeguard.hardened.toml)

**Why.** Probes for `/.env`, `/.git/config`, `/.aws/credentials`, `phpinfo`, WordPress, SAP, VPN
appliances and `cgi-bin` made up most of the attack traffic in the logs reviewed, and one in seven
`.env` probes was answered `200` by the app's catch-all route. Refusing them at the edge keeps
them out of the app, makes the probe obvious in the log (`forbidden`, with the rule id), and
answers scanners with a 403 rather than a page their tooling flags as a hit. It does not replace
EG-HARD-146. Add rules for exploits specific to your stack, for example a header an
authentication-bypass CVE relies on.

**Config.**
```toml
[[waf.rules]]
id      = "never-valid-paths"
target  = "path"
pattern = '(?i)(^|/)(\.env|\.git/|\.aws/|\.svn/|\.ds_store)|^/+(\./+)*(wp-admin|wp-login\.php|xmlrpc\.php|phpinfo|vendor/phpunit|cgi-bin/|server-status)'

[[waf.rules]]
id      = "framework-middleware-bypass"
target  = "headers"
pattern = '(?mi)^x-middleware-subrequest:'
```
Two halves, case-insensitive. The dotfiles (`.env`, `.git/`, `.aws/`, `.svn/`, `.DS_Store`) are
refused **at any depth** (`/app/.env`, `/blog/.git/config`), since no app should serve them
anywhere. The rest is anchored at the root, tolerating repeated slashes and `./` segments, because
apps normalise paths and the WAF does not (it matches the path raw and percent-decoded): a plain
`^/(…)` misses `//wp-login.php` and `/./phpinfo`. A deeper `/test/phpinfo.php` or
`/blog/wp-admin/` is **not** refused by the root-anchored half: if your app has no such paths at
all, drop the `^/+(\./+)*` anchor for them too. The rule matches the path and query, so a query
value containing `/.env` (`?next=/.env`) is refused as well. Rule ids appear in the WAF log line;
the metric only has the class (`rule="custom"`).

**Verify.** Measured on 0.7.0 with the rule above:
- 403: `/.env`, `//.env`, `/./.env`, `/.ENV`, `/.env.local`, `/%2eenv`, `/app/.env`,
  `/api/v1/.env`, `/.git/config`, `//.git/config`, `/blog/.git/config`, `/x/.aws/credentials`,
  `/static/.DS_Store`, `/wp-login.php`, `//WP-LOGIN.PHP`, `/cgi-bin/x`, `/?next=/.env`.
- Not refused, as described: `/test/phpinfo.php`, `/blog/wp-admin/`, `/environment`, `/envelope`.
```sh
for p in /.env //.env /./.env /.ENV /%2eenv /app/.env /blog/.git/config //WP-LOGIN.PHP; do
  curl -sk --path-as-is -o /dev/null -w "$p %{http_code}\n" "https://app.example.com$p"   # 403 each
done
curl -sk -o /dev/null -w '%{http_code}\n' -H 'x-middleware-subrequest: x' https://app.example.com/admin  # 403
```

---

## Authentication

### EG-HARD-100 · Anything not meant to be public has a gate

**Severity:** High · **[App]** · **Reference:** every setup (`mode = "none"`, with an app that authenticates)

**Why.** `auth.mode = "none"` (the default) forwards every request unauthenticated; doctor warns.
That is right only when the app authenticates every route itself, and checking that is the app
team's job: probe `/api/*` without a session. The gate is per deployment, not per route: in 0.7
there is no per-path auth.

**Config.** For an API: `apikey`, `jwt` or `mtls`. For a site whose app has its own login:
`none`, with the app's auth checked.

**Verify.**
```sh
curl -sk -o /dev/null -w '%{http_code}\n' https://app.example.com/api/private   # 401 from the edge, or from the app
```

### EG-HARD-101 · A credential header sent twice is refused (0.7.0), and the app reads the same one

**Severity:** High · **[App]** · **Reference:** —

**Why.** Before 0.7.0 the edge checked the first `Authorization`/API-key header and forwarded the
last, so a valid key first and a forged token second passed the edge and reached the app as the
forged one. 0.7.0 answers `401` when the header it authenticates by appears more than once
(`basic`, `jwt`, `apikey`); `none` and `mtls` forward duplicates for the app to judge. An app that
reads a *different* credential than the edge checked (a query parameter, a second header, a
cookie) reopens the hole.

**Config.** eggrd ≥ 0.7.0. The app authorises with the credential the edge verified (for JWT, the
same token, verified again or trusted only from the edge).

**Verify.** Measured on 0.7.0: two `X-API-Key` headers → 401.
```sh
curl -sk -H 'X-API-Key: valid' -H 'X-API-Key: forged' -o /dev/null -w '%{http_code}\n' https://app.example.com/api/x   # 401
```

### EG-HARD-102 · Basic passwords are argon2 hashes

**Severity:** High · **Reference:** —

**Why.** A plaintext `auth.users` value is a dev convenience; the config file is copied into
backups, tickets and evidence bundles. doctor warns on plaintext and on a value that is not a valid
argon2 PHC string.

**Config.**
```sh
edgeguard --hash          # reads the password from stdin, prints the $argon2id$… value
```
```toml
[auth]
mode = "basic"

[auth.users]
ops = "$argon2id$REPLACE-ME-with-the-output-of-edgeguard---hash"
```
The value is a placeholder with no hash in it: measured on 0.7.0, every login against it is 401
(empty, arbitrary, and the placeholder text itself as the password). Note that `doctor` does not
flag it (it parses as a PHC string), so search for `REPLACE-ME` before deploying, and paste your
own `edgeguard --hash` output.

**Verify.**
```sh
edgeguard doctor --config edgeguard.toml   # no "plaintext password" warning
```

### EG-HARD-103 · JWTs are pinned to one algorithm, issuer and audience

**Severity:** High · **Reference:** [hybrid-pools](../../deploy/reference/hybrid-pools/) (JWKS through the egress proxy)

**Why.** eggrd never lets the token choose its algorithm (`alg` must equal `auth.jwt.algorithm`),
which closes `alg=none` and RS/HS confusion. `issuer` and `audience` are optional: without them, a
token your IdP minted for another application is accepted here.

**Config.**
```toml
[auth]
mode = "jwt"

[auth.jwt]
algorithm = "RS256"
jwks_url = "https://idp.example.com/.well-known/jwks.json"
issuer = "https://idp.example.com/"
audience = "app.example.com"
leeway_secs = 60
```
An HS256 secret belongs in `EDGEGUARD_JWT_SECRET_FILE` (EG-HARD-181).

**Verify.**
```sh
curl -sk -H "Authorization: Bearer $TOKEN_FOR_ANOTHER_AUDIENCE" -o /dev/null -w '%{http_code}\n' https://app.example.com/api/x   # 401
```

### EG-HARD-104 · API keys are random, many, and named in logs only by hash

**Severity:** Medium · **Reference:** —

**Why.** Keys are compared in constant time and logged as `apikey:<16 hex>` (a hash prefix, never
the key), so a leak investigation can follow one key across the log without anyone holding it. One
key per client is what makes revoking one leaked key possible without an outage for all. The id is
Rust's default 64-bit hasher over the key. Measured: identical for the same key on 0.7.0-rc.1,
0.7.0 and a rebuild of main with rustc 1.99.1; 0.5 and earlier log no principal. The standard
library does not promise that hasher is stable across Rust versions, so after an upgrade, confirm
with one known test key that ids still match before joining logs across the upgrade.

**Config.** One key per consumer, 32+ random bytes, from `EDGEGUARD_API_KEYS_FILE`
(comma-separated). Add `ratelimit.per_key` (EG-HARD-122).
```sh
openssl rand -base64 32
```

**Verify.** The access record's `principal` is `apikey:…` for each consumer; one consumer's activity
is the "principal timeline" query in LOGGING-AND-EVIDENCE.md.

### EG-HARD-105 · Paths that need a stronger gate than the rest are split out

**Severity:** Medium · **[Gap]** · **Reference:** —

**Why.** `auth.mode` applies to every proxied request; 0.7 cannot require a key or a client
certificate on `/admin` only. Measured on 0.7.0: switching the mode to `apikey` turned `/` into a
401 as well as `/api/`.

**Config.** One of: a second eggrd deployment (its own hostname) for the admin surface with its own
`[auth]` and `[access] allow`; the app enforcing auth on those paths; or refusing the paths
publicly with a WAF path rule and reaching them over a private network:
```toml
[[waf.rules]]
id      = "offline-admin"
target  = "path"
pattern = '(?i)^/+(\./+)*admin([/;?]|$)'
```
Case-insensitive, tolerant of repeated slashes and `./` segments, and ending at `/`, `;`, `?` or the
end, so the app's own path normalisation cannot turn a variant into `/admin` behind the edge's back.
Measured on 0.7.0 (a path rule applies in 0.25 s): `/admin`, `/admin/`, `/admin/users`, `/ADMIN`,
`/Admin`, `//admin`, `///admin`, `/./admin`, `/.//admin`, `/admin;x`, `/admin;jsessionid=1`,
`/admin?x=1`, `/%61dmin`, `/%2fadmin`, `/%2e/admin`, `/admin%2f` → 403, and `/x/../admin` → 403
(the built-in traversal rules). Not matched, as intended: `/administrator`, `/adminx`,
`/admin.php` (200), `/api/admin` (other routes). If your app maps other spellings onto `/admin`
(a trailing `.json`, a locale prefix), extend the pattern and test them.

**Verify.**
```sh
for p in /admin //admin /ADMIN /./admin '/admin;x' /%61dmin; do
  curl -sk --path-as-is -o /dev/null -w "$p %{http_code}\n" "https://app.example.com$p"   # 403 each, or 401
done
```

---

## Rate limiting

### EG-HARD-120 · A global per-IP limit is on

**Severity:** High · **Reference:** every setup (`120/min`, burst 20–30)

**Why.** Rate limiting is on by default at 60/min, burst 20. In the logs reviewed, a third of all
requests were answered `429`, almost all to scanners, and clients sent thirteen thousand requests
after their first 429: scanners do not back off. The limit does not stop them sending; it stops
them reaching the app. Limits key on the resolved client address, so EG-HARD-040/041/044 must be
right first.

**Config.**
```toml
[ratelimit]
enabled = true
rate = "120/min"
burst = 30
```
A reload resets local limiter state (measured: a changed limit applied in 0.29 s, from a fresh
bucket).

**Verify.**
```sh
for i in $(seq 1 60); do curl -sk -o /dev/null -w '%{http_code} ' https://app.example.com/; done   # 429s after the burst
# PromQL  sum by (scope) (rate(edgeguard_ratelimit_hits_total[5m])); alert EdgeGuardRateLimitSaturation
```

### EG-HARD-121 · Credential endpoints have a strict route limit

**Severity:** High · **[App]** · **Reference:** [compose-single-vm](../../deploy/reference/compose-single-vm/) (`/login`, 5/min)

**Why.** Login, token, password-reset and sign-up endpoints are where credential stuffing and
enumeration land. A route limit is still per IP, so it slows a single source; a distributed
stuffing run needs the app's own per-account lockout and breached-password checks too.

**Config.**
```toml
[[ratelimit.routes]]
path = "/api/login"
rate = "5/min"
burst = 3
name = "login"
```

**Verify.** Measured on 0.7.0: the fourth login attempt within the burst got 429, other paths
kept the global limit.
```sh
# PromQL  rate(edgeguard_ratelimit_hits_total{scope="route"}[5m]); edgeguard_route_requests_total{route="login"}
```

### EG-HARD-122 · Authenticated clients have a per-principal limit

**Severity:** Medium · **Reference:** —

**Why.** One API key spread over many addresses gets a per-IP bucket on each. A per-key limit
bounds what a leaked key can do before you revoke it.

**Config.**
```toml
[ratelimit.per_key]
enabled = true
rate = "1000/hour"
burst = 100
```

**Verify.**
```sh
# PromQL  rate(edgeguard_ratelimit_hits_total{scope="key"}[5m])
```

### EG-HARD-123 · Several replicas share one limit, and a store outage fails closed

**Severity:** Medium · **Reference:** —

**Why.** `store = "local"` is per process: N replicas allow N times the limit. With `store =
"redis"`, `fail_open = false` (the default) answers `503` when Redis is unreachable rather than
silently dropping rate limiting.

**Config.**
```toml
[ratelimit]
store = "redis"
redis_prefix = "eggrd-prod"
fail_open = false
```
The URL from `EDGEGUARD_REDIS_URL_FILE` (`rediss://` for TLS). Alert `EdgeGuardLimiterErrors`.

**Verify.**
```sh
# PromQL  sum(rate(edgeguard_requests_total{outcome="limiter_error"}[5m]))   0
```

### EG-HARD-124 · Distributed and repeat scanners are handled beyond the per-IP limit

**Severity:** Medium · **[Gap]** · **Reference:** —

**Why.** In six weeks of one deployment's log, 192 probing addresses sent three requests or fewer
each: no per-IP limit ever sees them. Repeat offenders keep coming back after their 429s. 0.7 has
no automatic ban or jail.

**Config.** Layers, cheapest first: the never-valid-paths rule (EG-HARD-083) and the Host rule,
which refuse a probe on its first request; real 404s from the app (EG-HARD-146); a deny list built
from the log (the "deny-list candidates" query), applied with `[access] deny` (a hot reload,
0.25 s); for automatic bans, fail2ban-style tooling on the access log that rewrites that list, or
a cloud WAF / IP-reputation feed in front of the balancer.

**Verify.**
```sh
# the "hit-and-run probers" and "requests after the first 429" queries in LOGGING-AND-EVIDENCE.md
```

---

## Response headers

### EG-HARD-140 · The CSP is enforced, after a report-only phase

**Severity:** High · **[App]** · **Reference:** [compose-single-vm](../../deploy/reference/compose-single-vm/)

**Why.** The default CSP (`default-src 'self'`) blocks inline scripts, which breaks frameworks that
hydrate with inline scripts. The common response is `csp_report_only = true` forever, which
protects nothing. Roll out with reports, then enforce. A policy without `'unsafe-inline'` in
`script-src` needs a per-request nonce, which only the app can mint.

**Config.** Phase 1, a week of reports:
```toml
[headers]
csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
csp_report_only = true
csp_report_uri = "/__edgeguard/csp-report"
```
Phase 2: `csp_report_only = false` once `edgeguard_csp_reports_total` stays flat under real use.
Phase 3 (strict, app change): the app's middleware mints a nonce and sends its own
`script-src 'self' 'nonce-…' 'strict-dynamic'` policy, and eggrd sends none (`csp = ""`) or keeps
its policy as report-only beside it.

**Verify.**
```sh
curl -sk -D - -o /dev/null https://app.example.com/ | grep -i '^content-security-policy'   # not -report-only
```

### EG-HARD-141 · HSTS is on

**Severity:** Medium · **Reference:** every TLS setup

**Why.** `hsts = true` (the default) sends `max-age=63072000; includeSubDomains`; the value is fixed
in 0.7 (no `preload` token). Once browsers have seen it they refuse plaintext for two years, so turn
it on only when every subdomain is HTTPS.

**Config.**
```toml
[headers]
hsts = true
```

**Verify.**
```sh
curl -sk -D - -o /dev/null https://app.example.com/ | grep -i strict-transport-security
```

### EG-HARD-142 · Framing, referrer and feature headers stay at their defaults

**Severity:** Low · **Reference:** every setup

**Why.** The defaults are `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Permissions-Policy: geolocation=(), microphone=(), camera=()` and `X-Content-Type-Options:
nosniff` (always). Loosening them is a decision to record, not a default to drift into.

**Config.**
```toml
[headers]
frame_options = "DENY"
referrer_policy = "no-referrer"
permissions_policy = "geolocation=(), microphone=(), camera=()"
```

**Verify.**
```sh
curl -sk -D - -o /dev/null https://app.example.com/ | grep -iE '^(x-frame-options|referrer-policy|permissions-policy|x-content-type-options)'
```

### EG-HARD-143 · Server banners are removed

**Severity:** Low · **Reference:** every setup

**Why.** `Server` and `X-Powered-By` tell a scanner which exploit to try. `strip` removes them by
default (measured: the upstream's `Server` header did not reach the client).

**Config.**
```toml
[headers]
strip = ["Server", "X-Powered-By", "X-AspNet-Version"]
```

**Verify.**
```sh
curl -sk -D - -o /dev/null https://app.example.com/ | grep -iE '^(server|x-powered-by):'   # nothing
```

### EG-HARD-144 · Cookies are Secure and HttpOnly unless one is named as an exception

**Severity:** Medium · **Reference:** —

**Why.** `force_secure_cookies` and `httponly_cookies` (both on by default) add `Secure`,
`HttpOnly` and `SameSite=Lax` to `Set-Cookie` values that lack them. A double-submit CSRF cookie
the frontend must read is the one legitimate exception: exempt it by exact name, never by turning
`httponly_cookies` off.

**Config.**
```toml
[headers]
force_secure_cookies = true
httponly_cookies = true
httponly_cookie_exempt = ["csrf_token"]
```

**Verify.**
```sh
curl -sk -D - -o /dev/null https://app.example.com/login | grep -i '^set-cookie'
```

### EG-HARD-145 · CORS is off, or lists exact origins

**Severity:** Medium · **Reference:** —

**Why.** `[cors]` is off by default. `allow_origins = ["*"]` lets any site read responses with the
user's network position; with `allow_credentials` it is refused at load.

**Config.**
```toml
[cors]
enabled = true
allow_origins = ["https://app.example.com"]
allow_credentials = true
max_age = "600s"
```

**Verify.**
```sh
curl -sk -H 'Origin: https://evil.example' -D - -o /dev/null https://app.example.com/api/x | grep -i access-control-allow-origin   # absent
```

### EG-HARD-146 · The app answers unknown paths with 404

**Severity:** Medium · **[App]** · **Reference:** —

**Why.** A single-page app's catch-all route answers every unknown path `200` with its HTML shell.
In the logs reviewed, about one in seven `/.env` probes, and hundreds of PHP and config-file
probes, got a `200`: no secret leaked, but every scanner records the site as "has `.env`", and
your own log can no longer tell a hit from a miss. The edge cannot know which paths your app
serves.

**Config.** In the app: an explicit route table and a real 404 for the rest. At the edge, the
never-valid-paths rule (EG-HARD-083) as a backstop.

**Verify.**
```sh
curl -sk -o /dev/null -w '%{http_code}\n' https://app.example.com/this-does-not-exist.php   # 404 (or 403 from the edge rule)
```

---

## Upstream

### EG-HARD-160 · Upstreams across an untrusted network are reached over TLS, with a client certificate

**Severity:** High · **Reference:** [hybrid-pools](../../deploy/reference/hybrid-pools/)

**Why.** The edge-to-app hop carries every credential and session the edge saw. Inside one host or
one cluster network that may be acceptable; across a VPN, a peering link or the internet it is not.
A wrong-CA upstream certificate fails with `502` (`UnknownIssuer`).

**Config.**
```toml
[upstream_tls]
ca_path = "/etc/edgeguard/pki/upstream-ca.pem"
cert_path = "/etc/edgeguard/pki/edge-client.pem"
key_path = "/etc/edgeguard/pki/edge-client.key"
```
with `https://` targets. The client pair is reloaded when it changes.

**Verify.**
```sh
curl -s "$ADMIN/__edgeguard/upstreams"   # targets by scheme://host:port, ok counts rising
# PromQL  rate(edgeguard_upstream_requests_total{result="tls_error"}[5m])   0
```

### EG-HARD-161 · The app trusts the edge's client headers only, and validates Host itself

**Severity:** High · **[App]** · **Reference:** [aws-alb](../../deploy/reference/aws-alb/) (scrub checks)

**Why.** 0.7.0 replaces `X-Forwarded-For`, `X-Real-IP` and `Forwarded` with the resolved client,
sets `X-Forwarded-Host` to the `Host` it received, and removes `True-Client-IP` (measured: spoofed
values of all five never reached the app). Two things remain the app's: accept these headers only
from the edge (the app's port reachable from the edge only, EG-HARD-005), and validate `Host`
before building links from it, since the client still chooses `Host` and eggrd 0.7 has no
allowed-hosts list (the Host rule, EG-HARD-082, is the interim edge control).

**Config.** In the app: Django `ALLOWED_HOSTS`, Rails `config.hosts`, or the public URL in the app's
own config for links in emails.

**Verify.** An endpoint that echoes request headers (in staging) shows `x-forwarded-for`,
`x-real-ip` and `forwarded` with your own address, `x-forwarded-host` equal to the host you asked
for, and no `true-client-ip`.

### EG-HARD-162 · Upstream timeouts are bounded

**Severity:** Medium · **Reference:** every setup

**Why.** `upstream_connect_timeout` (5 s, new in 0.7) and `upstream_timeout` (30 s) bound how long
a stalled or blackholed upstream holds a request and a connection; without them a slow upstream
becomes an edge-wide resource exhaustion.

**Config.**
```toml
[validation]
upstream_timeout = "30s"
upstream_connect_timeout = "5s"
```
`upstream_connect_timeout` is startup-only. Alert `EdgeGuardUpstreamTimeouts`.

**Verify.**
```sh
# PromQL  sum(rate(edgeguard_requests_total{outcome="upstream_timeout"}[5m]))
```

### EG-HARD-163 · Pools are health-checked and eject failing targets

**Severity:** Medium · **Reference:** [hybrid-pools](../../deploy/reference/hybrid-pools/)

**Why.** A compromised or broken target keeps receiving traffic until something takes it out.
doctor warns on a pool with neither a health check nor `eject_after`.

**Config.**
```toml
[[upstreams]]
path = "/api/"
targets = ["http://10.0.1.5:8080", "http://10.0.2.5:8080"]
eject_after = 3
eject_for = "30s"
health_check = { path = "/healthz", interval = "5s", timeout = "2s" }
```
Alerts `EdgeGuardUpstreamPoolDown`, `EdgeGuardUpstreamTargetOut`, `EdgeGuardUpstreamTargetFlapping`.

**Verify.**
```sh
curl -s "$ADMIN/__edgeguard/upstreams"    # in_rotation, ejected, health_check.passing per target
```

### EG-HARD-164 · Buffered responses are capped

**Severity:** Low · **Reference:** [examples/edgeguard.hardened.toml](examples/edgeguard.hardened.toml)

**Why.** `max_response_body` is `0` (unbounded) by default: a misbehaving or compromised upstream
can make the edge buffer an arbitrarily large body.

**Config.**
```toml
[validation]
max_response_body = "64MiB"
```

**Verify.**
```sh
# PromQL  rate(edgeguard_requests_total{outcome="upstream_body_too_large"}[1h])
```

### EG-HARD-165 · No credentials in upstream URLs

**Severity:** Medium · **Reference:** —

**Affected:** 0.7.0 and earlier. **Fixed:** 0.7.1 (#1748; CHANGELOG.md, 0.7.1, Security). **Upgrade** to 0.7.1; keeping credentials out of URLs stays good
practice on every version.

**Why.** The access record strips userinfo from the upstream (`scheme://host:port`), but in 0.7.0
the `upstream unreachable` and `upstream timed out` WARN lines print the configured base URL whole:
measured, `http://svc-user:<password>@host` appeared in the log. Fixed in 0.7.1 (#1748), which redacts
userinfo everywhere a URL is logged; on 0.7.0, and as a rule, keep credentials out of URLs. Logs are
the most-copied artefact you have.

**Config.** Authenticate to upstreams with `[upstream_tls]` client certificates, or with a header
the app checks, never `user:pass@` in `target`/`targets`/`server.upstream`.

**Verify.**
```sh
grep -nE '://[^/@" ]+:[^/@" ]+@' edgeguard.toml   # nothing
```

---

## Secrets and files

### EG-HARD-180 · The ACME account and the TLS key are readable by the edge only

**Severity:** High · **[0.8]** · **Reference:** [compose-single-vm](../../deploy/reference/compose-single-vm/) (`edge-health` sidecar)

**Why.** 0.7 writes `acme/account.json` (it holds the ACME account's private key) and the
issuance ledger `0644`. With the account key, anyone on the host can revoke your certificates or
order new ones for your names. 0.8 plans to write them `0600`.

**Config.** Directory `0700`, files `0600`, owned by 65532, re-applied after every start (the
reference's sidecar does it every five minutes):
```sh
chmod 700 /var/lib/edgeguard /var/lib/edgeguard/acme
chmod 600 /var/lib/edgeguard/key.pem /var/lib/edgeguard/acme/*.json
```

**Verify.**
```sh
ls -la /var/lib/edgeguard /var/lib/edgeguard/acme   # no group or world bits on key.pem and *.json
```

### EG-HARD-181 · Secrets come from the environment or a mounted file, not the config

**Severity:** High · **Reference:** [examples](../../examples/) (`edgeguard.service` with `LoadCredential`)

**Why.** The config file goes into version control, ConfigMaps (readable by anyone with `get` on
the namespace), backups and evidence bundles. doctor warns when `auth.jwt.secret`, `auth.api_keys`
or `control_plane.edge_token` are in the file.

**Config.** `EDGEGUARD_JWT_SECRET_FILE`, `EDGEGUARD_API_KEYS_FILE`, `EDGEGUARD_REDIS_URL_FILE`,
`EDGEGUARD_CP_EDGE_TOKEN_FILE` (or the variables without `_FILE`), pointing at a Kubernetes Secret
volume, a Docker secret or a systemd credential. A `_FILE` that cannot be read stops startup.
Rotation: the file is re-read on every config reload, and only a change to `edgeguard.toml`
triggers one (measured: a new key file applied 0.21 s after the config was touched, and not at all
before).

**Verify.**
```sh
edgeguard doctor --config edgeguard.toml   # no "prefer the … env var" warnings
```

### EG-HARD-182 · The ACME contact is a role address

**Severity:** Low · **Reference:** —

**Why.** The CA sends expiry and revocation notices there; a personal mailbox leaves with its
owner.

**Config.**
```toml
[tls.acme]
email = "security@example.com"
```

### EG-HARD-183 · Nothing sensitive is left beside the config

**Severity:** Medium · **Reference:** —

**Why.** Hosts collect `edgeguard.toml.bak-*`, configs of the proxy eggrd replaced, old `.env`
copies and expired key backups. They outlive the rotation of what they hold.

**Config.** One config directory under version control (rendered from a template if secrets are
injected), nothing else in it; old keys destroyed after rotation, not archived beside the new.

**Verify.**
```sh
ls -la /etc/edgeguard /var/lib/edgeguard    # the config, cert.pem, key.pem, acme/ and nothing else
```

### EG-HARD-184 · Backups and evidence of the state volume are handled as secrets

**Severity:** Medium · **Reference:** —

**Why.** A tarball of `/var/lib/edgeguard` is the TLS key and the ACME account key. So is the
evidence bundle of INCIDENT-RESPONSE.md.

**Config.** Encrypt at rest (`age -r`, `gpg -e`, a KMS-encrypted bucket), restrict who can read,
expire them.

---

## Container and pod runtime

### EG-HARD-200 · Runs as a non-root user

**Severity:** High · **Reference:** every setup (`65532:65532`)

**Why.** The image is distroless and runs as 65532 by default; an explicit `--user` (or
`runAsUser`, `runAsNonRoot`) keeps an override from silently making it root.

**Config.** Docker `--user 65532:65532`; Kubernetes `runAsNonRoot: true`, `runAsUser: 65532`,
`runAsGroup: 65532`.

**Verify.**
```sh
docker inspect --format '{{.Config.User}}' eggrd    # 65532:65532
```

### EG-HARD-201 · Read-only root filesystem

**Severity:** High · **Reference:** every setup

**Why.** An attacker with code execution cannot drop a binary or alter the image's files. eggrd
writes only its state directory (certificate, key, ACME) and `/tmp`.

**Config.** Docker `--read-only --tmpfs /tmp`; Kubernetes `readOnlyRootFilesystem: true` with an
`emptyDir` on `/tmp`.

**Verify.**
```sh
docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' eggrd   # true
```

### EG-HARD-202 · All capabilities dropped but the one to bind low ports

**Severity:** High · **Reference:** every setup

**Why.** The default capability set includes `NET_RAW`, `CHOWN`, `SETUID` and others an edge never
needs. `NET_BIND_SERVICE` is needed only to bind 80/443 as a non-root user.

**Config.** Docker `--cap-drop ALL --cap-add NET_BIND_SERVICE`; Kubernetes `capabilities: { drop:
["ALL"] }` with the `net.ipv4.ip_unprivileged_port_start` sysctl, or ports above 1024 behind the
Service.

**Verify.**
```sh
docker inspect --format '{{.HostConfig.CapDrop}} {{.HostConfig.CapAdd}}' eggrd   # [ALL] [NET_BIND_SERVICE]
```

### EG-HARD-203 · No privilege escalation, default seccomp

**Severity:** High · **Reference:** every setup

**Why.** A setuid binary or a file capability cannot raise an attacker's privileges in a process
that may not gain any, and the runtime's default seccomp profile removes the system calls
(`mount`, `ptrace`, kernel keyrings, `unshare`…) most container escapes start with. eggrd needs
none of them.

**Config.** Docker `--security-opt no-new-privileges` (the default seccomp profile stays on);
Kubernetes `allowPrivilegeEscalation: false`, `seccompProfile: { type: RuntimeDefault }`.

**Verify.**
```sh
docker inspect --format '{{.HostConfig.SecurityOpt}}' eggrd   # [no-new-privileges]
```

### EG-HARD-204 · Memory, CPU and process limits

**Severity:** Medium · **Reference:** every setup (`192m`, 0.5 CPU, 256 pids)

**Why.** A flood or a bug should cost the edge its own container, not the host it shares with the
app.

**Config.** Docker `--memory 192m --cpus 0.5 --pids-limit 256` (size from load tests); Kubernetes
requests and limits.

**Verify.**
```sh
docker inspect --format '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.HostConfig.PidsLimit}}' eggrd
```

### EG-HARD-205 · The edge comes back by itself, and something outside checks it

**Severity:** Medium · **Reference:** [compose-single-vm](../../deploy/reference/compose-single-vm/) (`edge-health`)

**Why.** `docker run` without a restart policy stays down after a crash or a reboot. The image has
no shell, so it cannot carry a `HEALTHCHECK`: probe `/__edgeguard/ready` from outside (kubelet,
a sidecar, a host check). Measured on 0.7.0: a container restart refused connections for 0.4 s.

**Config.** Docker `--restart unless-stopped` (or systemd `Restart=always`, not both); Kubernetes
probes on the admin port.

**Verify.**
```sh
docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' eggrd    # unless-stopped
# On a staging edge, never production (it takes the edge down): restart the daemon, as a reboot
# would, and the edge must come back. (`docker stop` would not test this: unless-stopped then
# deliberately stays down; a crash or a daemon restart is what the policy is for.)
sudo systemctl restart docker; sleep 10; docker ps --filter name=eggrd   # Up
```

### EG-HARD-206 · Kubernetes: Pod Security `restricted`, no service-account token

**Severity:** High · **Reference:** [kubernetes](../../deploy/reference/kubernetes/) (`base/namespaces.yaml`)

**Why.** `restricted` enforces most of 200–203 at admission. The edge needs no Kubernetes API, so
a mounted token is only something to steal. A `hostPort` edge needs `privileged` in its own
namespace; keep every other namespace `restricted`.

**Config.** Namespace labels `pod-security.kubernetes.io/enforce: restricted` (edge on hostPort:
`privileged`, with `warn`/`audit: restricted`); `automountServiceAccountToken: false`.

**Verify.**
```sh
kubectl label --dry-run=server --overwrite ns eggrd-app pod-security.kubernetes.io/enforce=restricted   # no violations
```

---

## Supply chain

### EG-HARD-220 · The image is pinned by its multi-arch index digest

**Severity:** High · **Reference:** every setup

**Why.** A tag is a pointer that can move. After three releases an amd64-only image overwrote the
`X.Y.Z` tag about 22 minutes after the release (0.7.0 was re-pointed; the release now asserts and
watches its tags). A digest is what you tested.

**Config.** The image this corpus was measured on is below. For 0.7.1, take its index digest
from the 0.7.1 release notes (do not copy a digest from anywhere else) and pin that.
```text
docker.io/mancube/eggrd:0.7.0@sha256:b19278b379a457e626954e148effffa2fe559613d55ff497fdaa862c8c4096f6
```

**Verify.**
```sh
docker buildx imagetools inspect docker.io/mancube/eggrd:0.7.0   # an OCI index with linux/amd64 and linux/arm64
docker inspect --format '{{.Image}}' eggrd                       # the running image
```
On Kubernetes `status.containerStatuses[].imageID` is what the node pulled; an image imported
locally shows its platform manifest's digest, not the index's.

### EG-HARD-221 · You check what the release publishes, and generate what it does not

**Severity:** Medium · **[Gap]** · **Reference:** —

**Why.** 0.7.0 publishes the image (by digest, two architectures) and the crate on crates.io. The
image build turns provenance and SBOM attestations off, and there is no image signature yet.

**Config.** Record the digest from the release notes and compare it with what you pull. Generate
an SBOM and a vulnerability scan for the pinned digest in your own pipeline (for example
`syft <image>@<digest>`, `trivy image <image>@<digest>`). Or build from source:
`cargo install eggrd --version 0.7.0 --locked` (the crate ships its `Cargo.lock`).

### EG-HARD-222 · Dependencies are re-checked between releases

**Severity:** Low · **Reference:** —

**Why.** A vulnerability in a dependency (rustls, hyper, tokio) is fixed by a new eggrd release,
not by your rebuild of the old one.

**Config.** Watch the repository's releases and security advisories; run `cargo audit` against the
crate's `Cargo.lock` if you build from source.

---

## Operations

### EG-HARD-240 · `doctor` runs in CI with 0 errors, and keys are checked against the reference

**Severity:** High · **[0.8]** · **Reference:** every setup (each passes doctor)

**Why.** `edgeguard doctor` catches bad values, missing files, risky combinations and secrets in
the file. It does **not** see unknown keys: a misspelt key (`inspect_header`), a key from another
version, or a key that does not exist (`allowed_hosts`, `[log] level`) loads silently and does
nothing. Measured: with `inspect_headers` misspelt, the Host rule stopped matching and a forged
Host got `200`, with doctor clean. 0.8 plans a warning.

**Config.**
```sh
docker run --rm -v "$PWD/config:/etc/edgeguard:ro" \
  docker.io/mancube/eggrd:0.7.0@sha256:b19278b379a457e626954e148effffa2fe559613d55ff497fdaa862c8c4096f6 \
  doctor --config /etc/edgeguard/edgeguard.toml
```
fails the pipeline on a non-zero exit. Diff every key against
[eggrd.dev/docs/config.html](https://eggrd.dev/docs/config.html) by review, and test the behaviour
a key is for (the verify step of its item), not only that the file loads.

### EG-HARD-241 · You run a release with the current security fixes

**Severity:** Critical (every release before 0.7.0) · **Reference:** [CHANGELOG.md](../../CHANGELOG.md)

**Why.** 0.7.0 fixed three security bugs: a duplicated credential header passing the edge with one
value and reaching the app with another; `trust_forwarded_for` taking the client-written
`X-Forwarded-For` entry; and client-written `X-Real-IP`, `True-Client-IP`, `Forwarded`,
`X-Forwarded-Host` reaching the app. Affected: every release up to and including 0.5.0 has all
three (0.6.0 was never released; only a `0.6.0-beta.1` was cut), and the published 0.7.0-rc.1 has
all three as well; 0.7.0 is the first fixed release. On 0.7.0 itself, the WAF Host rule
bypasses of EG-HARD-082 and the upstream-credential logging of EG-HARD-165 are fixed in 0.7.1 (#1748):
run 0.7.1.

**Config.** Read every release's Security and Upgrading sections; test the upgrade on a staging
edge with the same config; upgrade within days for a Security entry. 0.5 → 0.7: set
`forwarded_hops` first (EG-HARD-041), and expect the 5 s connect timeout and the 30 s keep-alive
idle limit.

**Verify.**
```sh
docker run --rm "docker.io/mancube/eggrd:0.7.1@$DIGEST_FROM_THE_0_7_1_RELEASE_NOTES" --version   # edgeguard 0.7.1
docker inspect --format '{{.Image}}' eggrd    # the running edge: compare with the digest you pinned
```

### EG-HARD-242 · Config changes reach the running edge the way you think they do

**Severity:** Medium · **[0.8]** · **Reference:** every setup ("Lessons that apply to every setup")

**Why.** eggrd watches the config file's directory (not recursively) and reloads on a change it
attributes to the config file. A bind mount of the directory delivers that; a single-file bind mount
does not. On a ConfigMap volume the kubelet updates the files by writing a new timestamped
directory and renaming a `..data_tmp` symlink over `..data` (recorded with inotify on k3s v1.31.14:
`CREATE ..<timestamp>`, `CREATE ..data_tmp`, `MOVED_FROM ..data_tmp`, `MOVED_TO ..data`,
`DELETE` of the old directory; no event names `edgeguard.toml`), and eggrd 0.7.0 did reload after
that swap. Which event it matches is not yet pinned down in `src/reload.rs`, so treat the ConfigMap
result as an observation of these versions, not a guarantee. What delivered a reload, on 0.7.0:

| Delivery | Reloads? |
|---|---|
| Directory bind mount, any edit | Yes, in 0.2–0.35 s |
| Single-file bind mount | No (and an editor that replaces the file leaves the container on the old inode) |
| Host folder bind-mounted into Docker Desktop's or Podman's VM (Windows, macOS) | No |
| `subPath` mount of a ConfigMap | No (never updated) |
| ConfigMap volume, in-place edit | k3s v1.31.14 (containerd): yes, 27–62 s after the edit (the kubelet's sync), four times out of four. k3s v1.33.4 with the Docker runtime (a build of 2026-10-27): no reload within 90 s, one run. Untested elsewhere. Do not depend on it |
| Kubernetes, new ConfigMap name + pod roll | Yes: the roll is the reload (13–14 s for a one-replica `Recreate` hostPort edge, about 2 s of it refusing) |

The single-file and VM-folder rows come from the reference deployments' tests; the others were
measured for this corpus. A reload that does not parse keeps the previous config and logs `config reload failed; keeping
previous config` (ERROR). Listener settings (`port`, `admin_*`, `header_read_timeout`,
`max_connections`, `drain_*`, `proxy_protocol*`, `upstream_connect_timeout`, all of `[tls]`,
`[log.ship]`, `[tracing]`) need a restart whatever the delivery.

**Config.** Mount the directory. On Kubernetes, a kustomize `configMapGenerator` (or a checksum
annotation checked to be a hash, not a placeholder) so every change rolls the pods.

**Verify.** After every change, look for `config reloaded` (or the new pod) and test the behaviour:
```sh
docker logs --since 1m eggrd 2>&1 | grep -E 'config reload'
```

### EG-HARD-243 · Logs leave the host as they are written, and are kept

**Severity:** High · **Reference:** [compose-single-vm](../../deploy/reference/compose-single-vm/) (`compose.logging.yaml`)

**Why.** A container's log lives as long as the container (on Kubernetes, the current and the
previous one). An incident found a week later, or an attacker with the host, leaves nothing to
investigate. Retention, integrity and queries are in
[LOGGING-AND-EVIDENCE.md](LOGGING-AND-EVIDENCE.md).

**Config.** Docker's `awslogs` (or journald/fluentd) driver, a node agent (Fluent Bit, Vector, the
CloudWatch agent) or `[log.ship]`; an archive with object lock.

**Verify.** Find a request you just made in the central store by its `x-request-id`.

### EG-HARD-244 · The monitoring bundle's alerts are deployed and routed

**Severity:** High · **Reference:** [monitoring](../../deploy/reference/monitoring/), [`monitoring/`](../../monitoring/)

**Why.** The alerts are how most of INCIDENT-RESPONSE.md's detection signals reach a person.

**Config.** `monitoring/prometheus/alerts.yml` (bundle 1.6.2) and
`deploy/reference/monitoring/prometheus/rules-0.7.yml`, scraped from the admin port, routed to an
on-call channel.

**Verify.**
```sh
promtool test rules monitoring/prometheus/alerts.test.yml
```

### EG-HARD-245 · The clock is synchronised

**Severity:** Medium · **Reference:** —

**Why.** Every timeline in an investigation is built from timestamps on several machines (the
balancer, eggrd, the app, the database). Certificate validity depends on it too.

**Config.** chrony or systemd-timesyncd against your cloud's time service; alert on offset.

**Verify.**
```sh
chronyc tracking    # or: timedatectl show-timesync --all
```

### EG-HARD-246 · Principals are logged in a way your privacy rules allow

**Severity:** Low · **Reference:** [compose-single-vm](../../deploy/reference/compose-single-vm/) (`principal = "hash"`)

**Why.** `principal` is the API-key id, Basic user, JWT `sub` or certificate name, recorded whole
by default. If those are e-mail addresses, the access log is personal data. `hash` keeps lines from
one caller correlatable (`sha256:<16 hex>`) without the name; it is pseudonymous, not anonymous.
Per-consumer metric series carry the same names: `metrics.consumer_series_max = 0` turns them off.

**Config.**
```toml
[log]
principal = "hash"
query = "redact"

[metrics]
consumer_series_max = 0
```

### EG-HARD-247 · The containment levers are rehearsed

**Severity:** Medium · **Reference:** [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md#containment-levers)

**Why.** During an incident is the wrong time to find out that your config is a single-file mount
and nothing reloads, or that removing a route sends its traffic to the default upstream instead of
taking it offline.

**Config.** Once per quarter on a staging edge: deny a CIDR, switch the WAF to block, add a rule,
tighten a limit, take a path offline, rotate a key; time each and compare with the table in
INCIDENT-RESPONSE.md.
