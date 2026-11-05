#!/usr/bin/env bash
# Run smoke.sh for both variants against a throwaway single-node k3s in Docker.
#
#   ./smoke-k3s.sh
#
# Needs docker (a daemon that allows --privileged), kubectl, curl and openssl. Starts k3s v1.31
# with its bundled NetworkPolicy controller and ServiceLB (klipper), publishes the node's 443/80
# on 127.0.0.1:28443/28080 and the API on 127.0.0.1:26443, imports the images the setup uses from
# the local Docker store (so the node needs no registry access: pre-pull them, or set
# PULL=1), runs VARIANT=loadbalancer then VARIANT=hostport, and removes the node.
#
# The node gets the eggrd image by TAG (mancube/eggrd:0.7.0): an image imported from a local
# store has its platform manifest's digest, not the multi-arch index digest the manifests pin, so
# EGGRD_IMAGE_OVERRIDE swaps the reference for the test. Production pulls by the pinned digest.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
N="${K3S_NAME:-egref-k3s}"
K3S_IMAGE="${K3S_IMAGE:-docker.io/rancher/k3s:v1.31.14-k3s1}"
IMAGES=(
  docker.io/mancube/eggrd:0.7.0
  docker.io/traefik/whoami:v1.10.3
  docker.io/curlimages/curl:8.11.1
  # k3s v1.31.14's own (the node has no registry access in an air-gapped run)
  docker.io/rancher/mirrored-pause:3.6
  docker.io/rancher/mirrored-coredns-coredns:1.13.1
  docker.io/rancher/local-path-provisioner:v0.0.32
  docker.io/rancher/mirrored-library-busybox:1.36.1
  docker.io/rancher/klipper-lb:v0.4.13
)
[ "${PULL:-0}" = 1 ] && for i in "${IMAGES[@]}" "$K3S_IMAGE"; do docker pull -q "$i" >/dev/null; done

docker rm -f -v "$N" >/dev/null 2>&1 || true
trap '[ "${KEEP:-0}" = 1 ] || docker rm -f -v "$N" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$N" --privileged --tmpfs /run --tmpfs /var/run \
  -p 127.0.0.1:26443:6443 -p 127.0.0.1:28443:443 -p 127.0.0.1:28080:80 \
  "$K3S_IMAGE" server --disable=traefik,metrics-server --disable-helm-controller \
  --tls-san 127.0.0.1 '--kubelet-arg=eviction-hard=memory.available<50Mi,nodefs.available<200Mi,imagefs.available<200Mi' \
  --kubelet-arg=image-gc-high-threshold=100 >/dev/null
for _ in $(seq 1 90); do docker exec "$N" kubectl get nodes --no-headers 2>/dev/null | grep -q ' Ready ' && break; sleep 2; done
for i in "${IMAGES[@]}"; do docker save "$i" | docker exec -i "$N" ctr -n k8s.io images import - >/dev/null; done
KC="$(mktemp)"
docker exec "$N" cat /etc/rancher/k3s/k3s.yaml | sed 's#https://127.0.0.1:6443#https://127.0.0.1:26443#' > "$KC"
export KUBECONFIG="$KC"
kubectl get nodes

rc=0
for v in loadbalancer hostport; do
  echo; echo "################ VARIANT=$v"
  VARIANT=$v EDGE_ADDR=127.0.0.1 EDGE_HTTPS_PORT=28443 EDGE_HTTP_PORT=28080 \
    EGGRD_IMAGE_OVERRIDE=docker.io/mancube/eggrd:0.7.0 "$HERE/smoke.sh" || rc=1
  # The namespaces go asynchronously; wait so the next variant starts clean.
  for _ in $(seq 1 60); do
    { ! kubectl get ns eggrd-edge >/dev/null 2>&1 && ! kubectl get ns eggrd-app >/dev/null 2>&1; } && break
    sleep 2
  done
done
rm -f "$KC"
exit $rc
