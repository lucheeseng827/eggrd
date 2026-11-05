#!/usr/bin/env bash
# Smoke test for the aws-nlb reference. Two parts:
#   1. Validate: doctor on the config, kubeconform on the rendered manifests (the Service
#      annotations themselves are only checked for shape: no NLB is created).
#   2. Run eggrd's side locally: HAProxy stands in for the NLB (TCP passthrough, PROXY protocol
#      v2, an HTTP health check of /__edgeguard/ready on the admin port that carries a v2 header,
#      as the NLB's does), in front of the edge with this directory's config.
# Not run end to end on AWS here. Docker or Podman; KEEP=1 leaves the containers up.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../tools/smoke-lib.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="$(engine)"
NET=egref-nlb SUBNET=10.231.77.0/24 LB_IP=10.231.77.10 EDGE_IP=10.231.77.5 CLIENT_IP=10.231.77.20
HOST=app.example.test HP=38443
TLS=(--resolve "$HOST:$HP:127.0.0.1" -k -H "Host: $HOST")
ADMIN=http://127.0.0.1:39090
STATS="http://127.0.0.1:38404/stats;csv"

WORK="$(mktemp -d)"
cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then note "KEEP=1: containers egref-nlb-* left up"; return; fi
  "$E" rm -f egref-nlb-lb egref-nlb-edge egref-nlb-app >/dev/null 2>&1 || true
  "$E" network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step "validate"
doctor "$HERE/config"
if command -v kubectl >/dev/null; then
  if "$REF_DIR/tools/kubeconform.sh" "$HERE"; then pass "kubeconform: every rendered object valid (k8s 1.31, PrometheusRule CRD)"; else fail "kubeconform"; fi
else note "no kubectl: skipped kubeconform"; fi

step "run: HAProxy as the NLB, PROXY v2, health check on the admin port"
# The config as shipped, with two test-only changes: the stand-in LB's address is the trusted
# one, and a self-signed certificate replaces the eggrd-tls Secret.
sed -e "s#^proxy_protocol_trusted = .*#proxy_protocol_trusted = [\"$LB_IP/32\"]#" \
    -e 's#^cert_path = "/etc/eggrd-tls/tls.crt".*#self_signed = true\ncert_path = "/tmp/tls.crt"#' \
    -e 's#^key_path = "/etc/eggrd-tls/tls.key".*#key_path = "/tmp/tls.key"#' \
    "$HERE/config/edgeguard.toml" > "$WORK/edgeguard.toml"
grep -q "^proxy_protocol_trusted = \[\"$LB_IP/32\"\]" "$WORK/edgeguard.toml" || die "sed of the trusted list failed"
"$E" rm -f egref-nlb-lb egref-nlb-edge egref-nlb-app >/dev/null 2>&1 || true
"$E" network rm "$NET" >/dev/null 2>&1 || true
"$E" network create --subnet "$SUBNET" "$NET" >/dev/null
"$E" run -d --name egref-nlb-app --network "$NET" --network-alias whoami.eggrd-app.svc.cluster.local \
  --read-only --cap-drop ALL --user 65532:65532 docker.io/traefik/whoami:v1.10.3 --port 8000 >/dev/null
"$E" run -d --name egref-nlb-edge --network "$NET" --ip "$EDGE_IP" --network-alias edge \
  -p 127.0.0.1:39090:9090 --read-only --tmpfs /tmp --user 65532:65532 --cap-drop ALL \
  --cap-add NET_BIND_SERVICE --security-opt no-new-privileges -v "$(hostpath "$WORK"):/etc/eggrd:ro" \
  "$EGGRD_IMAGE" --config /etc/eggrd/edgeguard.toml >/dev/null
"$E" run -d --name egref-nlb-lb --network "$NET" --ip "$LB_IP" \
  -p 127.0.0.1:$HP:8443 -p 127.0.0.1:38080:8080 -p 127.0.0.1:38404:8404 \
  -v "$(hostpath "$HERE/sim"):/usr/local/etc/haproxy:ro" docker.io/library/haproxy:3.0.5-alpine >/dev/null
wait_code 200 60 "$ADMIN/__edgeguard/ready" || fail "edge never ready"

lb_status() { body "$STATS" | awk -F, '$1=="edge_https" && $2=="edge" {print $18}'; }
ST=""; for _ in $(seq 1 15); do ST="$(lb_status)"; [ "$ST" = UP ] && break; sleep 1; done
check "the LB's HTTP check of /__edgeguard/ready on :9090 (with a v2 header) passes" UP "$ST"

check "GET / through the LB" 200 "$(code "${TLS[@]}" "https://$HOST:$HP/")"
R="$(headers --resolve "$HOST:38080:127.0.0.1" -H "Host: $HOST" "http://$HOST:38080/x")"
check_has ":80 through the LB (PROXY v2 on the redirect listener too) -> 308" "location: https://$HOST/x" "$R"
# From a client container at a known address (published ports on rootless Podman would show the
# LB's own address as the client, which proves nothing).
CL=(--rm --network "$NET" --ip "$CLIENT_IP" docker.io/curlimages/curl:8.11.1)
B="$("$E" run "${CL[@]}" -s -k --resolve "$HOST:8443:$LB_IP" -H "Host: $HOST" -H 'X-Forwarded-For: 203.0.113.66' "https://$HOST:8443/pp-check" 2>/dev/null || true)"
XFF="$(printf '%s' "$B" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-forwarded-for" {print $2}')"
check "the app sees the client named in the PROXY header (not the LB, not the client's own X-Forwarded-For)" "$CLIENT_IP" "$XFF"
sleep 1
LOGL="$("$E" logs egref-nlb-edge 2>&1 | grep '/pp-check' | tail -1)"
check_has "the access log has the same client_ip" "\"client_ip\":\"$XFF\"" "$LOGL"

M="$(body "$ADMIN/__edgeguard/metrics" | grep '^edgeguard_proxy_protocol_total')"
printf '%s\n' "$M" | sed 's/^/    /'
check_has "public listener: proxied" 'listener="public",result="proxied"' "$M"
check_has "admin listener: the LB's checks read as LOCAL" 'listener="admin",result="local"' "$M"

step "a PROXY header from anyone but the LB is refused; no header is served as itself"
check "forged header straight to the edge: closed" 000 "$("$E" run "${CL[@]}" -s -o /dev/null -w '%{http_code}' -k --haproxy-protocol -H "Host: $HOST" https://edge:443/ 2>/dev/null || true)"
check "no header straight to the edge: served (direct)" 200 "$("$E" run "${CL[@]}" -s -o /dev/null -w '%{http_code}' -k -H "Host: $HOST" https://edge:443/ 2>/dev/null || true)"
M="$(body "$ADMIN/__edgeguard/metrics" | grep '^edgeguard_proxy_protocol_total')"
check_has "counted untrusted (EdgeGuardProxyProtocolRefused's input)" 'listener="public",result="untrusted"' "$M"
check_has "counted direct" 'listener="public",result="direct"' "$M"

step "drain: SIGTERM -> /ready 503 -> the LB takes the target out while it still accepts"
"$E" kill --signal TERM egref-nlb-edge >/dev/null
check "ready on the admin port" 503 "$(code "$ADMIN/__edgeguard/ready")"
ST=""; for _ in $(seq 1 15); do ST="$(lb_status)"; case "$ST" in DOWN*) break ;; esac; sleep 1; done
case "$ST" in DOWN*) pass "the LB marked the edge $ST within its fall count" ;; *) fail "LB status '$ST'" ;; esac
check "the edge still answers a direct request inside drain_delay (25s)" 200 "$("$E" run "${CL[@]}" -s -o /dev/null -w '%{http_code}' -k -H "Host: $HOST" https://edge:443/ 2>/dev/null || true)"

summary
