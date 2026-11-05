#!/usr/bin/env bash
# Smoke test for the Kubernetes reference, against the cluster in your kubeconfig.
#
#   VARIANT=loadbalancer ./smoke.sh     # overlays/loadbalancer (default)
#   VARIANT=hostport ./smoke.sh         # overlays/hostport, with a self-signed certificate on the
#                                       # PVC in place of ACME (test/hostport-selfsigned)
#
# Needs kubectl, curl and openssl, a cluster whose CNI enforces NetworkPolicy, and a way to reach
# the edge: EDGE_ADDR (default 127.0.0.1) with EDGE_HTTPS_PORT/EDGE_HTTP_PORT (default 443/80),
# i.e. the LoadBalancer's address or the node's for hostPort. smoke-k3s.sh provides all of it in
# a throwaway k3s. Creates the namespaces eggrd-edge, eggrd-app, monitoring and egref-client,
# and deletes them at the end unless KEEP=1.
#
# EGGRD_IMAGE_OVERRIDE=<ref> replaces the pinned image (an air-gapped node that has the image
# imported by tag, not by its index digest).
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../tools/smoke-lib.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VARIANT="${VARIANT:-loadbalancer}"
case "$VARIANT" in
  loadbalancer) KDIR=overlays/loadbalancer ;;
  hostport)     KDIR=test/hostport-selfsigned ;;
  *) die "VARIANT must be loadbalancer or hostport" ;;
esac
for c in kubectl curl openssl; do command -v "$c" >/dev/null || die "need $c"; done
ADDR="${EDGE_ADDR:-127.0.0.1}"; HP="${EDGE_HTTPS_PORT:-443}"; P80="${EDGE_HTTP_PORT:-80}"
HOST=app.example.test
HTTPS="https://$HOST:$HP"
TLS=(--resolve "$HOST:$HP:$ADDR" -k -H "Host: $HOST")
CURL_IMAGE="${CURL_IMAGE:-docker.io/curlimages/curl:8.11.1}"
k() { kubectl "$@"; }

WORK="$(mktemp -d)"
cp -R "$HERE/." "$WORK/"
MADE_NS=""
for ns in eggrd-edge eggrd-app; do
  if k get namespace "$ns" >/dev/null 2>&1; then
    die "namespace $ns already exists: refusing to run (cleanup deletes what this run creates)"
  fi
done
cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then note "KEEP=1: left applied"; else
    # shellcheck disable=SC2086 # MADE_NS is a word list of namespaces this run created
    k delete namespace eggrd-edge eggrd-app $MADE_NS --wait=false >/dev/null 2>&1 || true
    k delete pv -l egref=1 >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

render() { # dir -> stdout, with the optional image override
  k kustomize "$WORK/$1" | if [ -n "${EGGRD_IMAGE_OVERRIDE:-}" ]; then
    sed "s#image: docker.io/mancube/eggrd:0.7.0@sha256:[0-9a-f]*#image: $EGGRD_IMAGE_OVERRIDE#"
  else cat; fi
}

step "doctor: 0 errors on every config"
if [ "${SKIP_DOCTOR:-0}" != 1 ] && { command -v docker >/dev/null || command -v podman >/dev/null; }; then
  doctor "$HERE/base/config"; doctor "$HERE/overlays/hostport/config"; doctor "$HERE/test/hostport-selfsigned"
else note "no container engine here (or SKIP_DOCTOR=1): run doctor on base/config, overlays/hostport/config and test/hostport-selfsigned yourself"; fi

step "render and apply $KDIR"
render "$KDIR" > "$WORK/rendered.yaml"
grep -q 'name: eggrd-config-[a-z0-9]\{10\}' "$WORK/rendered.yaml" && pass "ConfigMap name carries a content hash" || fail "no hashed ConfigMap"
GRACE="$(grep -m1 '^ *terminationGracePeriodSeconds:' "$WORK/rendered.yaml" | awk '{print $2}')"
DD="$(grep -m1 '^ *drain_delay' "$WORK/rendered.yaml" | grep -o '[0-9]\+')"
DT="$(grep -m1 '^ *drain_timeout' "$WORK/rendered.yaml" | grep -o '[0-9]\+')"
[ "$GRACE" -gt $((DD + DT)) ] && pass "terminationGracePeriodSeconds $GRACE > drain_delay $DD + drain_timeout $DT" || fail "grace $GRACE does not cover drain $DD+$DT"
k apply -f "$WORK/rendered.yaml" >/dev/null
if [ "$VARIANT" = loadbalancer ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj "/CN=$HOST" -addext "subjectAltName=DNS:$HOST" \
    -keyout "$WORK/tls.key" -out "$WORK/tls.crt" >/dev/null 2>&1
  k -n eggrd-edge create secret tls eggrd-tls --cert "$WORK/tls.crt" --key "$WORK/tls.key" >/dev/null
fi
k -n eggrd-app rollout status deploy/whoami --timeout=180s >/dev/null && pass "app ready in eggrd-app (restricted)" || fail "app not ready"
k -n eggrd-edge rollout status deploy/eggrd --timeout=180s >/dev/null && pass "edge ready: readiness probe on the admin port passes" || fail "edge not ready"
k -n eggrd-edge get pods -o wide --no-headers | sed 's/^/    /'

step "Pod Security"
check "eggrd-app enforces" restricted "$(k get ns eggrd-app -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')"
WANT=restricted; [ "$VARIANT" = hostport ] && WANT=privileged
check "eggrd-edge enforces" "$WANT" "$(k get ns eggrd-edge -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')"
OUT="$(cat <<'EOF' | k apply --dry-run=server -f - 2>&1 || true
apiVersion: v1
kind: Pod
metadata: { name: hostport-probe, namespace: eggrd-app }
spec:
  securityContext: { runAsNonRoot: true, runAsUser: 1000, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: docker.io/curlimages/curl:8.11.1
      ports: [{ containerPort: 443, hostPort: 443 }]
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] } }
EOF
)"
check_has "a hostPort pod is refused in eggrd-app" 'violates PodSecurity "restricted' "$OUT"

step "through the edge ($ADDR:$HP)"
wait_code 200 60 "${TLS[@]}" "$HTTPS/" && pass "GET / over TLS -> 200" || fail "GET / never 200"
H="$(headers "${TLS[@]}" "$HTTPS/")"
check_has "HSTS" "strict-transport-security" "$H"
check_has "CSP" "content-security-policy: default-src 'self'" "$H"
R="$(headers --resolve "$HOST:$P80:$ADDR" -H "Host: $HOST" "http://$HOST:$P80/x")"
check_has ":80 -> 308" "308" "$R"
check_has "Location https on the pinned host" "location: https://$HOST/x" "$R"
check "forged Host -> 403" 403 "$(code --resolve "$HOST:$HP:$ADDR" -k -H 'Host: evil.example' "$HTTPS/")"
check "SQLi -> 403" 403 "$(code "${TLS[@]}" "$HTTPS/?id=1%20UNION%20SELECT%20password%20FROM%20users")"
check "PROPFIND -> 405" 405 "$(code "${TLS[@]}" -X PROPFIND "$HTTPS/")"
check "ops paths 404 on the public port" 404 "$(code "${TLS[@]}" "$HTTPS/__edgeguard/metrics")"
SAW=""; for _ in $(seq 1 12); do SAW="$SAW $(code "${TLS[@]}" "$HTTPS/login")"; done
check_has "/login -> 429 within 12 requests" 429 "$SAW"

step "NetworkPolicies (k3s applies them a second or two after a pod starts: probes wait first)"
if k create namespace monitoring >/dev/null 2>&1; then MADE_NS="$MADE_NS monitoring"; fi
if k create namespace egref-client >/dev/null 2>&1; then MADE_NS="$MADE_NS egref-client"; fi
probe() { # ns name cmd -> prints the pod's output
  k -n "$1" delete pod "$2" --now >/dev/null 2>&1 || true
  k -n "$1" run "$2" --image="$CURL_IMAGE" --restart=Never --image-pull-policy=IfNotPresent \
    --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":100,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"'"$2"'","image":"'"$CURL_IMAGE"'","command":["sh","-c","sleep 5; '"$3"'"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' >/dev/null
  k -n "$1" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$2" --timeout=90s >/dev/null 2>&1 || true
  k -n "$1" logs "$2" 2>/dev/null
}
ADM="http://eggrd-admin.eggrd-edge.svc.cluster.local:9090/__edgeguard/ready"
APP="http://whoami.eggrd-app.svc.cluster.local:8000/"
check_has "monitoring -> edge admin :9090 allowed" "code=200" "$(probe monitoring np-mon "curl -s -o /dev/null -m 5 -w code=%{http_code} $ADM")"
check_has "other namespace -> edge admin :9090 denied" "code=000" "$(probe egref-client np-adm "curl -s -o /dev/null -m 5 -w code=%{http_code} $ADM")"
check_has "other namespace -> app :8000 denied (only the edge reaches it)" "code=000" "$(probe egref-client np-app "curl -s -o /dev/null -m 5 -w code=%{http_code} $APP")"

step "config change rolls the pods (the checksum pattern)"
OLD_CM="$(k -n eggrd-edge get deploy eggrd -o jsonpath='{.spec.template.spec.volumes[0].configMap.name}')"
CFG="$WORK/base/config/edgeguard.toml"; [ "$VARIANT" = hostport ] && CFG="$WORK/test/hostport-selfsigned/edgeguard.toml"
sed 's/"PATCH", "DELETE", "OPTIONS"/"PATCH", "OPTIONS"/' "$CFG" > "$CFG.new" && mv "$CFG.new" "$CFG"
render "$KDIR" | k apply -f - >/dev/null
k -n eggrd-edge rollout status deploy/eggrd --timeout=180s >/dev/null
NEW_CM="$(k -n eggrd-edge get deploy eggrd -o jsonpath='{.spec.template.spec.volumes[0].configMap.name}')"
[ "$OLD_CM" != "$NEW_CM" ] && pass "Deployment now references $NEW_CM (was $OLD_CM)" || fail "ConfigMap name unchanged"
wait_code 405 60 "${TLS[@]}" -X DELETE "$HTTPS/x" && pass "DELETE -> 405 after the roll" || fail "the new policy is not serving"

if [ "$VARIANT" = loadbalancer ]; then
  step "rolling restart under traffic: drain_delay keeps every request served"
  : > "$WORK/codes"
  ( end=$((SECONDS + 45)); while [ $SECONDS -lt $end ]; do code "${TLS[@]}" "$HTTPS/" >> "$WORK/codes"; echo >> "$WORK/codes"; sleep 0.2; done ) &
  LOOP=$!
  sleep 2
  k -n eggrd-edge rollout restart deploy/eggrd >/dev/null
  k -n eggrd-edge rollout status deploy/eggrd --timeout=180s >/dev/null
  wait "$LOOP" || true
  TOTAL="$(grep -c . "$WORK/codes")"; BAD="$(grep -vc '^200$' "$WORK/codes" || true)"
  [ "$BAD" -eq 0 ] && pass "$TOTAL requests during the roll, all 200" || fail "$BAD of $TOTAL requests failed during the roll: $(sort "$WORK/codes" | uniq -c | tr '\n' ' ')"
else
  step "the PVC holds the certificate across a restart"
  FP1="$(echo | openssl s_client -connect "$ADDR:$HP" -servername "$HOST" 2>/dev/null | openssl x509 -noout -fingerprint -sha256)"
  k -n eggrd-edge rollout restart deploy/eggrd >/dev/null
  k -n eggrd-edge rollout status deploy/eggrd --timeout=180s >/dev/null
  wait_code 200 60 "${TLS[@]}" "$HTTPS/" >/dev/null || true
  FP2="$(echo | openssl s_client -connect "$ADDR:$HP" -servername "$HOST" 2>/dev/null | openssl x509 -noout -fingerprint -sha256)"
  [ -n "$FP1" ] && [ "$FP1" = "$FP2" ] && pass "same certificate after the pod was replaced" || fail "certificate changed: '$FP1' -> '$FP2'"
fi

summary
