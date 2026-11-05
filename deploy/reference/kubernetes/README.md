# Reference: Kubernetes (kustomize)

eggrd 0.7.0 as the edge of a Kubernetes cluster, in its own namespace, in front of an app in a
`restricted` namespace, with default-deny NetworkPolicies. Two variants:

| Variant | `kubectl apply -k` | For |
|---|---|---|
| LoadBalancer | `overlays/loadbalancer` | Any cluster with a LoadBalancer implementation. Two replicas, PDB, rolling updates, TLS from a Secret (cert-manager). Both namespaces `restricted`. |
| hostPort | `overlays/hostport` | A single-node cluster with no load balancer (k3s on a VM). One replica on the node's 443/80, ACME certificate on a PVC. The edge's namespace is `privileged`. |

On AWS, use `../aws-nlb` (NLB with PROXY protocol) or `../aws-alb` (ALB) on top of `base/`.
`./smoke-k3s.sh` runs both variants on a throwaway k3s and checks every claim below.

## Architecture

```
                         eggrd-edge (restricted | privileged for hostPort)        eggrd-app (restricted)
 LB :443/:80  ─────►  Service eggrd-public ─► eggrd ×2  :443 TLS, :80 → 308  ─────►  Service whoami ─► whoami ×2 :8000
 (or node :443/:80, hostPort)                    │ :9090 admin (probes; Prometheus from ns monitoring)
                                                 └── egress: app :8000, DNS, internet :443 (ACME/JWKS), nothing else
 Service eggrd (ClusterIP :443/:80)  — in-cluster callers, an Ingress or LB controller target
 Service eggrd-admin (ClusterIP :9090) — Prometheus only
```

| Path | What it is |
|---|---|
| `base/namespaces.yaml` | `eggrd-edge` and `eggrd-app`, both `enforce: restricted`. |
| `base/edge.yaml` | Deployment (2 replicas, probes on the admin port, limits, `terminationGracePeriodSeconds: 35`), ClusterIP Services `eggrd` and `eggrd-admin`, a PDB. |
| `base/app.yaml` | The sample app (`traefik/whoami`), `restricted`-compliant, with a ClusterIP Service. |
| `base/networkpolicies.yaml` | Default deny in both namespaces, then only the paths in the diagram. |
| `base/config/edgeguard.toml` | The policy. A kustomize `configMapGenerator` turns it into `eggrd-config-<hash>`. |
| `overlays/loadbalancer/` | Adds the `eggrd-public` LoadBalancer Service, `externalTrafficPolicy: Local`. |
| `overlays/hostport/` | `privileged` edge namespace, one replica with hostPorts 443/80 and `Recreate`, the `eggrd-acme` PVC, an ACME config. |
| `test/hostport-selfsigned/` | Test fixture: the hostPort overlay with a self-signed certificate on the PVC, so it runs without a CA. |
| `smoke.sh`, `smoke-k3s.sh` | The test, and a harness that runs it on k3s in Docker. |

## Deploy it

1. Replace `app.example.test` in the config (`redirect_hosts`, the Host rule via
   `../tools/host-rule.sh <host>`, and in the hostPort overlay `[tls.acme] domains`), the
   upstream (`server.upstream`) and the app in `base/app.yaml` with yours.
2. Set your cluster's CIDRs in `base/networkpolicies.yaml` (pod, service; see the EKS note there).
3. Run `doctor` on the config with the pinned image (0 errors):
   `docker run --rm -v "$PWD/base/config:/cfg:ro" mancube/eggrd:0.7.0@sha256:b19278b379a457e626954e148effffa2fe559613d55ff497fdaa862c8c4096f6 doctor --config /cfg/edgeguard.toml`
4. LoadBalancer variant: create the TLS Secret, then apply.
   ```bash
   kubectl create namespace eggrd-edge --dry-run=client -o yaml | kubectl apply -f -
   # cert-manager: a Certificate with secretName: eggrd-tls in eggrd-edge. Or by hand:
   kubectl -n eggrd-edge create secret tls eggrd-tls --cert tls.crt --key tls.key
   kubectl apply -k overlays/loadbalancer
   ```
   eggrd re-reads a renewed Secret on its own (`tls.watch`; hourly at worst), no roll needed.
5. hostPort variant: point DNS at the node, open 80/443 on it, `kubectl apply -k overlays/hostport`.
   The first start orders the certificate. Leave `directory_url` out (Let's Encrypt staging) until
   it works once.

## Hardening checklist

| | What | Where |
|---|---|---|
| ✔ | Image pinned by the 0.7.0 index digest | `base/edge.yaml` |
| ✔ | `runAsNonRoot` (65532), `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, every capability dropped but `NET_BIND_SERVICE` | `base/edge.yaml` |
| ✔ | Binds 443/80 as non-root via the safe sysctl `net.ipv4.ip_unprivileged_port_start=0` (allowed by `restricted`) and `NET_BIND_SERVICE` | `base/edge.yaml` |
| ✔ | `automountServiceAccountToken: false` (eggrd never talks to the API server) | both Deployments |
| ✔ | Requests and limits on CPU and memory; `/tmp` a 16 Mi memory `emptyDir` | `base/edge.yaml` |
| ✔ | Probes on the admin port: readiness `/__edgeguard/ready` (503 while the upstream is down and while draining), liveness `/__edgeguard/health`, a startup probe | `base/edge.yaml` |
| ✔ | `drain_delay` 10 s + `drain_timeout` 15 s < `terminationGracePeriodSeconds` 35 | config + `base/edge.yaml` |
| ✔ | PDB `maxUnavailable: 1`, rolling update `maxUnavailable: 0`, spread across nodes | `base/edge.yaml` |
| ✔ | Pod Security `restricted` on both namespaces; `privileged` only on the edge's, only for hostPort | `base/namespaces.yaml`, `overlays/hostport` |
| ✔ | Default-deny NetworkPolicies; the app reachable only from the edge; the admin port only from `monitoring` | `base/networkpolicies.yaml` |
| ✔ | Egress: the app, DNS, and 443 to the internet minus the cluster's ranges and the metadata endpoint | `base/networkpolicies.yaml` |
| ✔ | ConfigMap named by its content hash: an edit rolls the pods | `base/kustomization.yaml` |
| ✔ | WAF block + Host rule, `allow_methods`, rate limits, CSP/HSTS, admin split, `header_read_timeout`, `max_connections` | `base/config/edgeguard.toml` |
|   | `trust_forwarded_for = false`: the LoadBalancer Service keeps the client address (`externalTrafficPolicy: Local`) | config |
|   | ACME files on the PVC are written `0644` by 0.7 (0.8: `0600`); the PVC is readable by fsGroup 65532 and root on the node | `overlays/hostport/pvc.yaml` |

The WAF ships in `block`; on a live app roll it out report → review → block (see
`../compose-single-vm/README.md`). `rate`/`burst` with `store = "local"` is per replica.

## Config changes: the roll is the reload

eggrd hot-reloads when the directory its config lives in reports a change it attributes to the
config file. A ConfigMap volume edited in place is updated at the kubelet's next sync by swapping a
`..data` symlink; on k3s v1.31.14 (containerd) that swap made eggrd 0.7.0 reload, 27–62 s after the
edit, while one run on k3s v1.33.4 with the Docker runtime saw no reload within 90 s, and other
platforms are untested. With `subPath` the file is never updated at all. So on Kubernetes treat a
config change as a pod roll, and trigger the roll:

- **kustomize** (this setup): `configMapGenerator` names the ConfigMap `eggrd-config-<hash of the
  content>` and rewrites the Deployment's reference, so any edit is a new pod template. Old
  ConfigMaps stay until you prune them (`kubectl apply --prune`, or delete by label).
- **Helm or plain manifests**: put a checksum of the file in a pod-template annotation, e.g.
  `checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}`,
  or `sed` the sha256 of `edgeguard.toml` into the annotation in your deploy script. A literal
  placeholder that the script fails to replace is the classic failure: check the live annotation
  is a hash.

## Drain and the grace period

On `SIGTERM` eggrd turns `/ready` `503` at once, keeps accepting for `drain_delay` while the
endpoints controller and load balancers stop sending to it, then stops accepting and finishes
in-flight requests for up to `drain_timeout`. `terminationGracePeriodSeconds` must exceed the sum,
or the kubelet kills the pod mid-drain. `doctor` warns when the sum reaches 30 s (the default
grace). Behind an AWS NLB the deregistration lag is about 15 s: use `drain_delay = "25s"` and a
grace of 60 (`../aws-nlb`).

## Verify

`./smoke-k3s.sh` (Docker with `--privileged`, plus kubectl, curl, openssl) starts k3s v1.31.14
with its NetworkPolicy controller and ServiceLB, imports the images, and runs `smoke.sh` for both
variants. Run `smoke.sh` alone against any cluster (`VARIANT=`, `EDGE_ADDR=`). It checks:

| Check | Expect |
|---|---|
| Rendered ConfigMap | named `eggrd-config-<hash>` |
| Grace period vs drain | `terminationGracePeriodSeconds` > `drain_delay` + `drain_timeout` |
| Rollouts | app and edge Ready (the readiness probe on `:9090` passes under default-deny) |
| Namespaces | `eggrd-app` `restricted`; `eggrd-edge` `restricted` (LB) or `privileged` (hostPort) |
| A hostPort pod in `eggrd-app` | refused: `violates PodSecurity "restricted…"` |
| `GET /` via the LB / hostPort | `200`, HSTS, CSP |
| `:80` | `308` to `https://app.example.test/x` |
| Forged Host, SQLi, `PROPFIND`, `/__edgeguard/metrics` on 443, 12 × `/login` | `403`, `403`, `405`, `404`, a `429` |
| From `monitoring` to `eggrd-admin:9090` | allowed |
| From another namespace to `eggrd-admin:9090`, and to the app directly | denied |
| Edit the config and re-apply | a new `eggrd-config-<hash>`, the pods roll, `DELETE` turns `405` |
| LB: `rollout restart` under 5 req/s | every request `200` (201 of 201 in the recorded run) |
| hostPort: replace the pod | the same certificate from the PVC |

Recorded run (2026-11-03, k3s v1.31.14 in Docker, eggrd 0.7.0): both variants, all checks
passed. The node imported the image by tag (`EGGRD_IMAGE_OVERRIDE`), since an image exported
from a local store carries its platform digest, not the index digest the manifests pin.
