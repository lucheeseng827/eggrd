#!/bin/sh
# Collect evidence about an eggrd Deployment on Kubernetes, before anything is changed.
# Tested with kubectl 1.31 against k3s v1.31 running deploy/reference/kubernetes. See
# ../INCIDENT-RESPONSE.md.
#
#   ./collect-evidence-k8s.sh <namespace> [label selector] [since]
#   ./collect-evidence-k8s.sh eggrd-edge app=eggrd 72h
#   SNAPSHOT_PVC=eggrd-acme ./collect-evidence-k8s.sh eggrd-edge     # also copy the state volume
#
# Read-only toward the edge: it restarts and edits nothing. Optional, and the only thing it
# creates: with SNAPSHOT_PVC, a short-lived pod in the namespace that mounts that claim read-only
# on the edge's node, tars it, and is deleted (restricted Pod Security; same user as the edge).
# The unpacked directory is removed once the .tgz is written and its hash verifies (it holds the
# same secrets); KEEP_UNPACKED=1 keeps it and says so.
#
# Secrets are listed by name and type only. Set EXPORT_SECRETS=1 to export them whole (the TLS
# key, API keys): the bundle is then as sensitive as the cluster's secrets. Either way the state
# volume holds the TLS and ACME account keys: encrypt the bundle before it leaves your machine.
set -eu

NS="${1:?usage: $0 <namespace> [selector, default app=eggrd] [since, default 72h]}"
SEL="${2:-app=eggrd}"
SINCE="${3:-72h}"
ADMIN_PORT="${ADMIN_PORT:-9090}"
# The snapshot pod's image, pinned by digest (busybox 1.36.1's multi-arch index). Override with a
# digest from your own registry mirror in an air-gapped cluster.
SNAPSHOT_IMAGE="${SNAPSHOT_IMAGE:-docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"
K="${KUBECTL:-kubectl}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
E="${OUT:-.}/eggrd-ir-$NS-$TS"

umask 077
mkdir -p "$E"
note() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$E/collection.log"; }
note "collector=$(id -un) context=$($K config current-context 2>/dev/null || echo in-cluster) ns=$NS selector=$SEL since=$SINCE"
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$E/clock.txt"
$K version > "$E/kubectl-version.txt" 2>&1 || true

# Events first: the API server keeps them for about an hour by default.
$K -n "$NS" get events --sort-by=.lastTimestamp -o wide > "$E/events.txt" 2>&1 || true
# Cluster-wide restarts and mount failures. Field selectors AND their terms, so one query per reason.
for r in Killing BackOff FailedMount OOMKilling Evicted; do
  $K get events -A --field-selector "reason=$r" -o wide --no-headers 2>/dev/null
done > "$E/events-cluster.txt" || true

# The objects, whole: the Deployment (image, securityContext, probes), the ConfigMap (the edge's
# config), Services, NetworkPolicies, the namespace (its Pod Security labels).
$K get ns "$NS" -o yaml > "$E/namespace.yaml" 2>&1 || note "FAILED: get ns $NS (see namespace.yaml)"
$K -n "$NS" get deploy,rs,sts,ds,pod,svc,endpointslices,cm,pvc,networkpolicy,pdb,sa,role,rolebinding -o wide > "$E/inventory.txt" 2>&1 || true
$K -n "$NS" get deploy,rs,sts,ds,pod,svc,cm,pvc,networkpolicy,pdb,sa -o yaml > "$E/objects.yaml" 2>&1 || note "FAILED: get objects (see objects.yaml)"
$K -n "$NS" get secret -o custom-columns=NAME:.metadata.name,TYPE:.type,CREATED:.metadata.creationTimestamp,RV:.metadata.resourceVersion > "$E/secrets-list.txt" 2>&1 || note "FAILED: list secrets (see secrets-list.txt)"
if [ "${EXPORT_SECRETS:-0}" = 1 ]; then $K -n "$NS" get secret -o yaml > "$E/secrets.yaml" && note "exported secrets" || note "FAILED: export secrets"; fi
$K get pv -o yaml > "$E/pv.yaml" 2>&1 || true

# What is running, by digest: imageID is what the node pulled, whatever the tag says.
$K -n "$NS" get pod -l "$SEL" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.nodeName}{"\t"}{.status.podIP}{"\t"}{range .status.containerStatuses[*]}{.name}{"="}{.image}{" "}{.imageID}{" restarts="}{.restartCount}{"\t"}{end}{"\n"}{end}' > "$E/pods-images.tsv" \
  || { note "FAILED: list pods for $SEL (no per-pod logs or admin endpoints)"; : > "$E/pods-images.tsv"; }
note "pods: $(cut -f1 "$E/pods-images.tsv" | tr '\n' ' ')"

for P in $(cut -f1 "$E/pods-images.tsv"); do
  $K -n "$NS" logs "$P" --all-containers --timestamps --since="$SINCE" > "$E/logs-$P.log" 2>&1 || true
  # The previous container's log, if it restarted (a crash, an OOM kill, a liveness failure).
  $K -n "$NS" logs "$P" --all-containers --timestamps --previous > "$E/logs-$P-previous.log" 2>/dev/null || rm -f "$E/logs-$P-previous.log"
  $K -n "$NS" describe pod "$P" > "$E/describe-$P.txt" 2>&1 || true
  # The admin endpoints through a port-forward (it enters the pod's network namespace, so it works
  # with admin_addr = 127.0.0.1 and is not subject to NetworkPolicy).
  PORT=$((20000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 20000))
  $K -n "$NS" port-forward "pod/$P" "$PORT:$ADMIN_PORT" > /dev/null 2>&1 &
  PF=$!
  i=0; while [ $i -lt 50 ] && ! curl -s -o /dev/null "http://127.0.0.1:$PORT/__edgeguard/health"; do sleep 0.2; i=$((i + 1)); done
  for ep in metrics tls upstreams ready; do
    curl -s -m 5 -o "$E/admin-$P-$ep.txt" -w "%{http_code}\n" "http://127.0.0.1:$PORT/__edgeguard/$ep" > "$E/admin-$P-$ep.status" || true
  done
  kill "$PF" 2>/dev/null || true
done

# Optional: the state volume (certificate, key, ACME account), read-only, from the edge's node.
# A snapshot that cannot run is recorded and the rest is still hashed and bundled; the script then
# exits non-zero at the very end, so the partial result is never left as loose, unhashed files.
SNAP_FAILED=0
remove_snapshot_pod() {
  [ -z "${H:-}" ] || $K -n "$NS" delete pod "$H" --ignore-not-found --wait=false > /dev/null 2>&1 || true
}
snapshot() {
  NODE=$(cut -f2 "$E/pods-images.tsv" | head -1)
  if [ -z "$NODE" ]; then
    note "SNAPSHOT FAILED: no pod matches $SEL in $NS, so the edge's node is unknown; $SNAPSHOT_PVC not copied"
    return 1
  fi
  H="eggrd-ir-snapshot-$TS"
  H=$(printf '%s' "$H" | tr 'A-Z' 'a-z')
  # Whatever happens from here, the pod goes: on any exit, and on Ctrl-C or TERM, which also stop
  # the script (exit 130) rather than letting it carry on to bundle a half-done collection.
  trap 'remove_snapshot_pod' EXIT
  trap 'remove_snapshot_pod; exit 130' INT TERM
  cat <<EOF | $K -n "$NS" apply -f - > /dev/null
apiVersion: v1
kind: Pod
metadata: { name: $H, labels: { app.kubernetes.io/name: eggrd-ir-snapshot } }
spec:
  nodeName: $NODE
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: tar
      image: $SNAPSHOT_IMAGE
      command: ["sleep", "600"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
      volumeMounts: [{ name: state, mountPath: /state, readOnly: true }]
  volumes: [{ name: state, persistentVolumeClaim: { claimName: $SNAPSHOT_PVC, readOnly: true } }]
EOF
  if ! $K -n "$NS" wait --for=condition=Ready "pod/$H" --timeout="${SNAPSHOT_TIMEOUT:-120s}" > /dev/null 2>&1; then
    note "SNAPSHOT FAILED: pod $H did not become ready (claim $SNAPSHOT_PVC missing, bound elsewhere, or the image not pullable)"
    $K -n "$NS" describe pod "$H" > "$E/snapshot-pod-describe.txt" 2>&1 || true
    return 1
  fi
  if ! $K -n "$NS" exec "$H" -- tar -C /state -cf - . > "$E/state-$SNAPSHOT_PVC.tar"; then
    note "SNAPSHOT FAILED: tar in $H failed; state-$SNAPSHOT_PVC.tar is incomplete"
    return 1
  fi
  $K -n "$NS" exec "$H" -- ls -lan /state /state/acme > "$E/state-$SNAPSHOT_PVC-listing.txt" 2>&1 || true
  note "copied PVC $SNAPSHOT_PVC from node $NODE"
}
if [ -n "${SNAPSHOT_PVC:-}" ]; then
  snapshot || SNAP_FAILED=1
  # The pod goes whether the snapshot worked or not (the traps cover an interrupt meanwhile).
  remove_snapshot_pod
  trap - EXIT INT TERM
fi

note "collection done; hashing"
(cd "$E" && sha256sum -- * > SHA256SUMS)
tar -C "$(dirname "$E")" -czf "$E.tgz" "$(basename "$E")"
# Relative name in the .sha256, so `sha256sum -c` works wherever the pair is moved.
(cd "$(dirname "$E")" && sha256sum "$(basename "$E").tgz" | tee "$(basename "$E").tgz.sha256")
echo "bundle $E.tgz: record the sha256 above in the chain-of-custody log"
# The unpacked copy holds the same secrets as the bundle: remove it once the bundle is written and
# its hash verifies. KEEP_UNPACKED=1 keeps it, and says so.
if [ "${KEEP_UNPACKED:-0}" = 1 ]; then
  echo "unpacked copy kept at $E (it contains keys): remove it once the .tgz is in evidence storage" >&2
elif tar -tzf "$E.tgz" > /dev/null && (cd "$(dirname "$E")" && sha256sum -c "$(basename "$E").tgz.sha256" > /dev/null); then
  rm -rf -- "$E"
else
  echo "the bundle does not read back or its hash does not verify: unpacked copy kept at $E (it contains keys)" >&2
fi
if [ "$SNAP_FAILED" != 0 ]; then
  echo "the state-volume snapshot FAILED (see collection.log); everything else is in the bundle" >&2
  exit 1
fi
