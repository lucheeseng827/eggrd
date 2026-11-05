# Reference: L7 load balancers and chains (AWS ALB, CloudFront → ALB, GCP, mTLS)

eggrd 0.7.0 behind a load balancer that terminates the client's TLS and speaks HTTP to eggrd: an
AWS ALB, CloudFront in front of an ALB, a GCP external Application Load Balancer, and two ways to
carry a client certificate through such a balancer.

**Tested here:** `doctor` on every config, kubeconform on both EKS overlays, `terraform validate`
on the CloudFront lock, and every behaviour below run locally with nginx standing in for the
balancers (`./smoke.sh`). **Not run end to end on AWS or GCP here.** The ALB Ingress follows the
eggrd 0.7 end-to-end run on EKS (ALB with IP targets in mTLS passthrough mode), with that run's
names, subnets, certificate and tags replaced by placeholders.

## Pick the row for what is in front of eggrd

| In front | It appends to `X-Forwarded-For` | Config | `forwarded_hops` |
|---|---|---|---|
| AWS ALB, default `append` mode | the client | `append/edgeguard.toml` | `1` |
| CloudFront → ALB | CloudFront the viewer, then the ALB CloudFront's edge | `configs/cloudfront-alb.toml` | `2`, and lock the ALB to CloudFront |
| GCP external Application LB | the client, then **its own address** | `configs/gcp-alb.toml` | `2` |
| Cloudflare, Azure Application Gateway, nginx `$proxy_add_x_forwarded_for`, Traefik | the client | as `append/` | `1` |
| ALB in `preserve` mode | nothing | **do not** set `trust_forwarded_for` | — |
| Anything else (Cloud Run and other Google Front End services, PaaS routers) | **measure first** (below) | | |

Client certificates through the balancer:

| Setup | Config |
|---|---|
| ALB mTLS **passthrough** (forwards the certificate unverified in `X-Amzn-Mtls-Clientcert`) | `mtls-passthrough/` |
| A balancer whose addresses others share (a provider edge, a shared ingress tier): trust it by the certificate it presents to eggrd | `configs/trusted-proxy-names.toml` |

The ALB's **verify** mode (a trust store on the listener) is not this config: it sends the leaf
certificate in `X-Amzn-Mtls-Clientcert-Leaf`, not `X-Amzn-Mtls-Clientcert`. Point
`[trusted_client_cert_header] name` at that header and test it before relying on it.

## How eggrd picks the client (0.7)

A balancer *appends* to whatever `X-Forwarded-For` the client sent. Only entries on the right are
written by proxies you run; everything to their left is the client's own writing. With
`trust_forwarded_for = true`, eggrd takes the entry `forwarded_hops` from the right (default `1`)
and ignores the rest. A header with fewer entries, or a chosen entry that is not an address, falls
back to the TCP peer. `edgeguard_forwarded_for_total{result}` counts `used`, `absent`, `short` and
`invalid`.

**Up to 0.7.0-rc.1 the leftmost entry was taken.** That one is the client's, so any client could
choose its address *through* the balancer: a fresh rate-limit bucket per request, a way past
`[access]` rules, a forged address in the logs. Letting only the balancer reach eggrd did not help,
since the balancer forwards the header.

**Too low** (`1` behind GCP): every client is the balancer (one rate-limit bucket for everyone,
site-wide `429`s). The metric still says `used`: check the access log's `client_ip` after deploying.
**Too high**: a client chooses its address again.

**Measure an unknown platform.** Point it at a request echo for a moment (or `tcpdump -A` on
eggrd's port), send `X-Forwarded-For: 192.0.2.1` from a known address, and count the entries after
`192.0.2.1`: your address must be exactly `forwarded_hops` from the right.

## What the app receives

eggrd sends its own client headers upstream and drops the client's (0.7): `X-Forwarded-For` and
`X-Real-IP` are the resolved client, `Forwarded` is `for=<client>;proto=<proto>`,
`X-Forwarded-Host` is the `Host` eggrd received, and `True-Client-IP` is removed. Frameworks that
prefer `True-Client-IP` or `X-Real-IP` (chi's `RealIP`) see the client eggrd rate-limited. A CDN
that rewrites `Host` and sends the viewer's as `X-Forwarded-Host` should forward the original
`Host` instead.

## Hardening checklist

- [ ] **Only the balancer reaches eggrd.** eggrd 0.7 believes `X-Forwarded-For` from *any* peer; a
      client that connects directly writes the whole header (the smoke test shows it). The
      kustomization's NetworkPolicy admits only the ALB's subnets (on 443 and on 9090 for health
      checks); on VMs, the target security group. 0.8 adds `server.trusted_forwarders`.
- [ ] **In a chain, only the outermost proxy is reachable.** CloudFront → ALB: the ALB's security
      group admits only `com.amazonaws.global.cloudfront.origin-facing`, *and* the ALB forwards
      only requests carrying a secret header CloudFront adds (`cloudfront-lock/main.tf`). With the
      AWS Load Balancer Controller: `alb.ingress.kubernetes.io/security-groups: <that SG>` and
      `alb.ingress.kubernetes.io/conditions.eggrd: '[{"field":"http-header","httpHeaderConfig":{"httpHeaderName":"X-Origin-Verify","values":["<secret>"]}}]'`.
      GCP: the VPC firewall admits only `35.191.0.0/16` and `130.211.0.0/22`.
- [ ] ALB `routing.http.xff_header_processing.mode=append` (set explicitly in `ingress.yaml`).
- [ ] ALB → eggrd stays HTTPS (`backend-protocol: HTTPS`); the health check is HTTP on `:9090`
      `/__edgeguard/ready`.
- [ ] `trusted_proxies` (certificate header) lists only *your* balancer's subnets, and those
      subnets are dedicated to the ALB: no nodes or other workloads in them. Anything else in
      them can send the certificate header itself (a certificate is not a secret, so it proves
      nothing about the sender). The VPC CNI gives pods addresses from the nodes' subnets, so
      keep the ALB's subnet pair separate. In passthrough mode `ca_path` and `crl_paths` are
      set, since the ALB verifies nothing.
- [ ] A CRL is refreshed before its `nextUpdate` (`EdgeGuardCrlStale`); a stale CRL is still used,
      so revocations since then are not applied.
- [ ] `trusted_proxy_names`: the balancer's certificate comes from a CA that issues nothing else.
      With `auth.mode = "mtls"`, any other certificate from `tls.client_auth.ca_path` would
      authenticate as itself when its holder connects directly; `doctor` warns (or notes, with
      `allowed` set).

## Verify

`./smoke.sh` (Docker or Podman; kubectl for kubeconform) builds a throwaway PKI, then:

| Check | Expect |
|---|---|
| `doctor` × 5 configs | 0 errors |
| kubeconform `append/`, `mtls-passthrough/` | 14 objects valid each |
| `terraform validate` + `fmt -check` on `cloudfront-lock/` | valid |
| Through the ALB stand-in, client sends `X-Forwarded-For: 198.51.100.7` | the app sees the client's real address |
| The same, straight to eggrd (bypassing the ALB) | the app sees `198.51.100.7`: why only the ALB may connect |
| CloudFront → ALB → eggrd, `forwarded_hops = 2` | the real address |
| Straight to the ALB, skipping CloudFront | `198.51.100.7`: why the ALB must accept only CloudFront |
| mTLS passthrough: client-a / none / revoked client-b / another CA's | `200` with `X-Forwarded-Client-Cert` (`URI="spiffe://…/client-a"`) / `401` / `401` / `401` |
| The certificate header forged by a direct client | `401`, counted `untrusted_peer` |
| `trusted_proxy_names`: client-a via the balancer / revoked / forged directly / client-a's own cert directly | `200` (principal is client-a) / `401` / `401` / handshake refused |

Recorded run (2026-11-03, eggrd 0.7.0, Podman): 28 checks, all passed.
