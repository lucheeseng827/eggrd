# eggrd 0.7 reference deployments

Tested starting points for running eggrd 0.7.0 (`mancube/eggrd:0.7.0`, pinned by its multi-arch
index digest `sha256:b19278b379a457e626954e148effffa2fe559613d55ff497fdaa862c8c4096f6`). Each
directory has a README (when to use it, the architecture, a hardening checklist, how to verify)
and a `smoke.sh` that brings the setup up, checks what the README promises, and takes it down.
Every config passes `edgeguard doctor` with 0 errors on 0.7.0.

| Setup | For | How it is tested |
|---|---|---|
| [`compose-single-vm/`](compose-single-vm/) | One VM, Docker Compose, eggrd terminating TLS (ACME, or self-signed locally) in front of an app | **Run**: the full stack on Docker/Podman |
| [`kubernetes/`](kubernetes/) | Kustomize: edge and app namespaces, default-deny NetworkPolicies, LoadBalancer or hostPort variant | **Run**: both variants on k3s v1.31 (`smoke-k3s.sh`) |
| [`aws-nlb/`](aws-nlb/) | EKS behind an NLB with PROXY protocol v2 and the admin-port health check | **Validated** (doctor, kubeconform); eggrd's side **run** locally with HAProxy as the NLB. Not run on AWS here. |
| [`aws-alb/`](aws-alb/) | An ALB (`forwarded_hops = 1`), CloudFront → ALB (`2`), GCP's external ALB (`2`), ALB mTLS passthrough, `trusted_proxy_names` | **Validated** (doctor, kubeconform, `terraform validate`); every behaviour **run** locally with nginx as the balancers. Not run on AWS or GCP here. |
| [`hybrid-pools/`](hybrid-pools/) | A pool of on-prem and cloud targets, mTLS to upstreams, an egress proxy, ACME through it | **Run**: nginx, squid and Pebble stand-ins |
| [`monitoring/`](monitoring/) | Prometheus + Grafana with monitoring bundle 1.6.2 and the 0.7 listener series | **Run**: against a live edge with traffic |

`tools/`: `host-rule.sh` (the interim Host allow-list rule), `mkpki.sh` (a throwaway test PKI),
`kubeconform.sh`, and `smoke-lib.sh` (the scripts' shared helpers).

The [security guides](../../docs/security/README.md) build on these setups: a hardening checklist
whose items name the setup that implements each, what to log and keep, and an incident-response
runbook with timed containment levers.

## Lessons that apply to every setup

These come from hardening real eggrd deployments. Each reference applies them; the checklists
say where.

- **Hot reload needs the config's directory mounted**, not the file. eggrd watches the directory
  (not recursively) and reloads on a change it attributes to the config file. A single-file bind
  mount never delivers one (and an editor that replaces the file leaves the container on the old
  inode), nor does a `subPath` mount (never updated). A ConfigMap volume edited in place is updated
  by the kubelet swapping its `..data` symlink at the next sync; on k3s v1.31.14 (containerd) that
  swap did make eggrd 0.7.0 reload, 27–62 s after the edit, while one run on k3s v1.33.4 with the
  Docker runtime saw no reload within 90 s, and other platforms are untested (see
  `docs/security/HARDENING-CHECKLIST.md`, EG-HARD-242). Do not depend on it. On Kubernetes, roll
  the pods on change: a kustomize `configMapGenerator` hash, or a checksum annotation, checked to
  be a hash and not a leftover placeholder. A host folder on
  Windows or macOS bind-mounted into Docker Desktop's or Podman's VM delivers no events either.
- **A distroless image has no shell for a healthcheck.** Probe the admin listener's
  `/__edgeguard/ready` (and `/health` for liveness) from outside the container: kubelet probes, a
  sidecar on the same network, or a host check on `127.0.0.1:<admin_port>`.
- **Behind an NLB with PROXY protocol**, health-check the admin port over HTTP (0.7 reads the
  NLB's `LOCAL` header there), keep client IP preservation off, set `drain_delay` to 20–30 s and
  `terminationGracePeriodSeconds` above `drain_delay` + `drain_timeout`, and deploy
  `EdgeGuardProxyProtocolRefused`.
- **eggrd 0.7 writes the ACME account file `0644`.** `chmod 600` it (and keep the directory
  `700`) until 0.8 writes it `0600`.
- **hostPort needs Pod Security `privileged`** in the edge's own namespace; keep every other
  namespace `restricted`. On the EKS VPC CNI, a NetworkPolicy egress rule to a Service needs an
  `ipBlock` for the service CIDR beside its `podSelector`.
- **Hardened container:** read-only root, a tmpfs `/tmp`, `cap_drop: ALL` with `NET_BIND_SERVICE`
  added back (or the `ip_unprivileged_port_start` sysctl on Kubernetes), `no-new-privileges`,
  memory/CPU/PID limits, user `65532`, the image pinned by digest, the admin listener on loopback
  or a private network only.
- **Host allow-list:** until 0.8's `allowed_hosts`, a WAF rule on the `Host` header
  (`tools/host-rule.sh <host>`) with the WAF in block mode and `inspect_headers = true`. Set
  `allow_methods` to the standard methods. From 0.7.1 the rule sees the request's host whatever
  the protocol (an HTTP/2 `:authority` included); on 0.7.0, a plain listener let cleartext HTTP/2
  (`h2c`) around it, so run 0.7.1 or put TLS in front.
- **Roll the WAF out report → review → block**, and CSP report-only → enforce.
- **`forwarded_hops` per provider** (`aws-alb/README.md`): `1` for an ALB in append mode,
  Cloudflare, nginx, Traefik; `2` for GCP's external ALB and for CloudFront → ALB; measure anything
  else. Only the balancer may reach eggrd: 0.7 believes the header from any peer.
- **The upstream header scrub (0.7):** the app receives eggrd's `X-Forwarded-For`, `X-Real-IP`,
  `Forwarded` and `X-Forwarded-Host`, and no `True-Client-IP`. `Host` is still the client's: an
  app that builds links from it must check it (or rely on the Host rule).

## Found while building these (eggrd 0.7.0)

- The `:80` redirect listener writes `server.port` into `Location`. An edge listening on 8443
  behind a Service or load balancer on 443 sends plaintext visitors to `https://host:8443/`. The
  Kubernetes setup therefore listens on 443 inside the pod.
- `edgeguard doctor` does not see unknown keys: a misspelt key passes and silently does nothing.
  Every key in these configs was checked against `src/config.rs`.
