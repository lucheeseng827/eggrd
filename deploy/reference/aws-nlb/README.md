# Reference: AWS NLB with PROXY protocol v2 (EKS)

eggrd 0.7.0 on EKS behind a Network Load Balancer made by the AWS Load Balancer Controller: IP
targets, TCP passthrough (eggrd terminates TLS), PROXY protocol v2 for the client's address, the
NLB's HTTP health check on eggrd's admin port, and a drain long enough for the NLB's
deregistration lag. Builds on `../kubernetes/base`.

**Tested here:** `doctor` on the config, kubeconform on every rendered object (Kubernetes 1.31 and
the PrometheusRule CRD), and eggrd's side of the contract run locally with HAProxy as the NLB
stand-in (`./smoke.sh`). **Not run end to end on AWS here.** The annotations and settings are the
ones used in the eggrd 0.7 end-to-end run on EKS (NLB with PROXY protocol v2, HTTP health check on
the admin port), with that run's names, subnets and tags removed; that run is where the
`drain_delay` and NetworkPolicy findings below come from.

## When to use it

- EKS (or any AWS setup) where an NLB is the entry point and eggrd must see real client addresses
  for rate limits, `[access]` rules and logs.
- You want TLS, and client certificates (`[tls.client_auth]`), terminated by eggrd, not the
  balancer: an NLB in TCP mode passes the handshake through.

For an ALB (L7, it terminates TLS and adds `X-Forwarded-For`) see `../aws-alb`.

## Architecture

```
client ──TCP──► NLB (internet-facing, IP targets, PROXY v2, preserve_client_ip=false)
                 │  connection from the NLB's private address, first bytes: PROXY v2 header naming the client
                 ▼
         pod IP :443  eggrd (TLS)  ── /ready 503 on SIGTERM
                 :9090 admin  ◄── NLB health check: HTTP GET /__edgeguard/ready, with a v2 LOCAL header
```

| File | What it is |
|---|---|
| `kustomization.yaml` | `../kubernetes/base` + the NLB Service + the alerts; replaces the config; grace 60 s; NetworkPolicy ingress from the NLB's subnets only. |
| `service-nlb.yaml` | The LoadBalancer Service with the controller's annotations. |
| `config/edgeguard.toml` | `proxy_protocol`, `proxy_protocol_trusted`, `drain_delay = "25s"`. |
| `prometheusrule.yaml` | `EdgeGuardProxyProtocolRefused` and `…Missing` for prometheus-operator. |
| `sim/haproxy.cfg` | The local NLB stand-in for `smoke.sh`. |

## The settings that matter

| Setting | Value | Why |
|---|---|---|
| `aws-load-balancer-nlb-target-type` | `ip` | Straight to pod IPs. Connections then come from the NLB's own addresses. |
| `aws-load-balancer-proxy-protocol` | `"*"` | PROXY v2 on every target group; eggrd reads it before the TLS handshake. |
| `preserve_client_ip.enabled` | `false` | **Client IP preservation must be off.** With it on, connections arrive from the clients' own addresses *with* a PROXY header; eggrd refuses those as `untrusted` (a client may not choose its address), so every client is cut off. |
| `server.proxy_protocol_trusted` | the NLB's subnets | The only peers whose header is believed. A `/0` is refused at startup. |
| health check | `http`, port `9090`, path `/__edgeguard/ready` | From 0.7.0 the admin listener reads the NLB's v2 `LOCAL` header (counted `listener="admin",result="local"`). `/ready` turns `503` at `SIGTERM`, so the NLB stops routing to a draining pod. |
| `server.admin_addr` | `0.0.0.0` | The NLB's checks reach the pod IP; the NetworkPolicy admits only its subnets on 9090. |
| `server.drain_delay` | `25s` (20–30 s) | The NLB keeps opening connections to a deregistering target for about 15 s. In the EKS run, `15s` let 1 request in 7,963 be refused during a rollout. |
| `terminationGracePeriodSeconds` | `60` | ≥ `drain_delay` + `drain_timeout` (50 s) plus margin. `doctor` warns at ≥ 30 s: expected here. |
| `deregistration_delay.timeout_seconds` | `30` | Longer than `drain_delay`. |
| `trust_forwarded_for` | `false` | An L4 balancer passes the client's own `X-Forwarded-For` through. `doctor` warns on both together. |

## Client IP preservation and the health check

The HTTP health check cannot see every misconfiguration:

- **The NLB's subnets change** (no longer in `proxy_protocol_trusted`): its health checks come from
  the new addresses too, their `LOCAL` header is refused, the check fails, and you notice.
- **Client IP preservation is turned on:** client connections are refused as `untrusted`, but the
  health checks still come from the NLB's private addresses, which are trusted. **The check passes
  while every client is cut off.**

Deploy `EdgeGuardProxyProtocolRefused` (`prometheusrule.yaml`, or the bundle's `alerts.yml`): it
fires on both. On a quiet listener, add `EdgeGuardProxyProtocolRefusedLowRate` (same files): the
critical alert needs more than one refusal every 10s, which a low-traffic listener may never
reach while every client is refused. A TCP health check is worse: it passes in both cases.

## Hardening checklist

Everything in `../kubernetes/README.md`, plus:

- [ ] `proxy_protocol_trusted` and the NetworkPolicy's `ipBlock`s list the NLB's subnets, nothing wider.
- [ ] `preserve_client_ip.enabled=false` on the target group.
- [ ] HTTP health check on `:9090` `/__edgeguard/ready`, not TCP.
- [ ] `EdgeGuardProxyProtocolRefused` deployed and routed to someone.
- [ ] `drain_delay` 20–30 s, grace period covering `drain_delay` + `drain_timeout`.
- [ ] The NLB's security group (or `loadBalancerSourceRanges`) admits only who should connect.
- [ ] The EKS VPC CNI network policy agent: the base's egress rule to the app carries an `ipBlock`
      for the service CIDR (`aws eks describe-cluster --query
      cluster.kubernetesNetworkConfig.serviceIpv4Cidr`); without it the edge timed out reaching a
      multi-port Service's ClusterIP in the EKS run.

## What clients see behind an NLB

The NLB holds the client's TCP connection and its own to eggrd separately. A connection eggrd
closes at accept (over `max_connections`) or for idling (`header_read_timeout`) looks open to the
client until it writes, then is reset; watch `edgeguard_connections_rejected_total` rather than
client errors. The NLB sends the PROXY header with the client's first bytes, so a client that
connects and sends nothing is closed after `header_read_timeout` and counted
`edgeguard_proxy_protocol_total{result="timeout"}`: a steady rate of those is idle clients, not a
broken balancer.

## Verify

`./smoke.sh` (Docker or Podman; kubectl for the kubeconform step):

| Check | Expect |
|---|---|
| `doctor` | 0 errors (the drain warning is expected) |
| kubeconform, strict | 15 objects valid, the PrometheusRule included |
| HAProxy's HTTP check of `:9090/__edgeguard/ready`, sent with a v2 header | the edge `UP`; `edgeguard_proxy_protocol_total{listener="admin",result="local"}` rising |
| `GET /` through the stand-in | `200`; `:80` → `308` (the redirect listener reads PROXY headers too) |
| A client at 10.231.77.20 through the stand-in, sending its own `X-Forwarded-For` | the app and the access log see `10.231.77.20` |
| A PROXY header sent straight to the edge from a non-trusted address | connection closed; counted `untrusted` |
| No header, straight to the edge | served, counted `direct` (pods and probes keep working) |
| `SIGTERM` | `/ready` `503`, the stand-in marks the edge `DOWN`, the edge still answers during `drain_delay` |

On EKS, after `kubectl apply -k`:

```bash
kubectl -n eggrd-edge get svc eggrd-nlb               # EXTERNAL-IP: the NLB's DNS name
aws elbv2 describe-target-health --target-group-arn <tg>   # targets healthy
curl -s https://app.example.com/ -o /dev/null -w '%{http_code}\n'
kubectl -n eggrd-edge logs deploy/eggrd | grep '"client_ip"' | tail -1   # your address, not 10.x
curl -s http://<pod>:9090/__edgeguard/metrics | grep proxy_protocol_total   # proxied, admin local
```
