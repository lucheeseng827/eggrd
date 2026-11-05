#!/usr/bin/env bash
# Smoke test for the hybrid-pools reference: ACME through the egress proxy, upstream mTLS, and
# every pool behaviour the config sets up. Docker or Podman. KEEP=1 leaves the stack up.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../tools/smoke-lib.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
E="$(engine)"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-egref-hybrid}"
export EDGE_BIND=127.0.0.1 EDGE_HTTPS_PORT=30443 EDGE_HTTP_PORT=30080 EDGE_ADMIN_PORT=30090
HOST=app.example.test
HTTPS="https://$HOST:$EDGE_HTTPS_PORT"
ADMIN="http://127.0.0.1:$EDGE_ADMIN_PORT"
WORK="$(mktemp -d)"
export PKI_DIR="$(hostpath "$WORK/pki")"
cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then note "KEEP=1: stack $COMPOSE_PROJECT_NAME left up; PKI in $WORK/pki"; return; fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
T=(--resolve "$HOST:$EDGE_HTTPS_PORT:127.0.0.1")
srv() { body "${T[@]}" -k "$@" | sed -n 's/^server=\([a-z-]*\).*/\1/p'; }

step "PKI and the stand-ins"
"$REF_DIR/tools/mkpki.sh" "$WORK/pki" >/dev/null && pass "test PKI in $WORK/pki"
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d pebble egress onprem-a onprem-b cloud 2>&1 | grep -iE 'error|fail' || true
PEB="$(compose ps -q pebble)"
"$E" cp "$PEB:/test/certs/pebble.minica.pem" "$(hostpath "$WORK/pki")/pebble-minica.pem"
[ -s "$WORK/pki/pebble-minica.pem" ] && pass "the ACME CA's TLS root copied to pki/pebble-minica.pem" || fail "no Pebble root"
DOCTOR_ARGS=(-v "$PKI_DIR:/pki:ro")
doctor "$HERE/config"

step "up: the edge orders its certificate from the CA, through the proxy"
compose up -d edge ingress 2>&1 | grep -iE 'error|fail' || true
wait_code 200 120 "$ADMIN/__edgeguard/health" || fail "edge never healthy"
sleep 2
LOGS="$(compose logs --no-color edge 2>&1)"
check_has "the order ran against the CA through the proxy" "starting ACME order" "$LOGS"
check_has "certificate obtained and stored" "ACME certificate stored" "$LOGS"
SQ="$(compose logs --no-color egress 2>&1)"
check_has "the proxy carried the ACME traffic (CONNECT pebble:14000)" "CONNECT pebble:14000" "$SQ"
ISS="$("$E" run --rm --network "${COMPOSE_PROJECT_NAME}_site" --entrypoint sh docker.io/alpine/openssl:3.3.2 -c \
  'openssl s_client -connect edge:443 -servername app.example.test </dev/null 2>/dev/null | openssl x509 -noout -issuer' 2>/dev/null || true)"
echo "    served certificate: $ISS"
check_has "the edge serves the certificate the CA issued" "Pebble Intermediate" "$ISS"
PERMS="$("$E" run --rm -v "${COMPOSE_PROJECT_NAME}_edge-state:/s:ro" docker.io/library/busybox:1.36.1 sh -c 'stat -c "%a %n" /s/key.pem /s/acme/*.json' 2>/dev/null || true)"
printf '%s\n' "$PERMS" | sed 's/^/    /'
note "eggrd 0.7 writes these 0644 (0.8 writes 0600): chmod them, as compose-single-vm's sidecar does"

step "proxy-only egress, enforced by the topology"
EDGE_NETS="$("$E" inspect "$(compose ps -q edge)" --format '{{range $n, $v := .NetworkSettings.Networks}}{{$n}} {{end}}')"
check "the edge is on the internal site network and nothing else" "${COMPOSE_PROJECT_NAME}_site" "$(printf '%s' "$EDGE_NETS" | xargs)"
PROBE=("$E" run --rm --network "${COMPOSE_PROJECT_NAME}_site" docker.io/curlimages/curl:8.11.1 -s -o /dev/null -m 5 -w '%{http_code}')
check "from the site network, the CA is unreachable without the proxy" 000 "$("${PROBE[@]}" -k https://pebble:14000/dir 2>/dev/null || true)"
check "from the site network, a public address is unreachable without the proxy" 000 "$("${PROBE[@]}" http://1.1.1.1/ 2>/dev/null || true)"
check "through the proxy, the CA answers" 200 "$("${PROBE[@]}" -k -x http://egress:3128 https://pebble:14000/dir 2>/dev/null || true)"

step "pool \"/\": round robin 2:1, sticky cookie, cookie stripped"
A=0; B=0
for _ in $(seq 1 30); do case "$(srv "$HTTPS/")" in onprem-a) A=$((A+1)) ;; onprem-b) B=$((B+1)) ;; esac; done
[ "$A" -eq 20 ] && [ "$B" -eq 10 ] && pass "30 requests without a cookie: onprem-a $A, onprem-b $B (weights 2:1)" || fail "split a=$A b=$B, want 20/10"
H="$(headers "${T[@]}" -k "$HTTPS/")"
COOKIE="$(printf '%s' "$H" | tr -d '\r' | sed -n 's/^set-cookie: \(eg_upstream=[^;]*\).*/\1/Ip')"
check_has "the edge sets the sticky cookie (Max-Age from sticky_cookie_max_age)" "max-age=28800" "$(printf '%s' "$H" | grep -i 'set-cookie: eg_upstream')"
FIRST="$(srv -H "Cookie: $COOKIE; theme=dark" "$HTTPS/")"
SAME=1; for _ in $(seq 1 6); do [ "$(srv -H "Cookie: $COOKIE" "$HTTPS/")" = "$FIRST" ] || SAME=0; done
check "6 requests with the cookie all reach $FIRST" 1 "$SAME"
BODY="$(body "${T[@]}" -k -H "Cookie: $COOKIE; theme=dark" "$HTTPS/")"
check_has "the app gets the client's other cookies" "theme=dark" "$BODY"
check_lacks "but not eg_upstream (sticky_cookie_strip)" "eg_upstream" "$BODY"

step "pool \"/cache/\" (hash on path) and \"/tenant/\" (hash on a header)"
P1="$(srv "$HTTPS/cache/a.png")"; OK=1; for _ in 1 2 3 4; do [ "$(srv "$HTTPS/cache/a.png")" = "$P1" ] || OK=0; done
check "the same path reaches the same server" 1 "$OK"
SEEN=""; for p in a b c d e f g h; do SEEN="$SEEN $(srv "$HTTPS/cache/$p.png")"; done
check_has "different paths spread over both" "onprem-a" "$SEEN"; check_has "…and onprem-b" "onprem-b" "$SEEN"
T1="$(srv -H 'x-tenant: acme' "$HTTPS/tenant/x")"; OK=1; for _ in 1 2 3; do [ "$(srv -H 'x-tenant: acme' "$HTTPS/tenant/y")" = "$T1" ] || OK=0; done
check "one tenant, one server" 1 "$OK"

step "status endpoint: health checks over scheme/port/check_host/headers"
U="$(body "$ADMIN/__edgeguard/upstreams")"
check_has "check_host shown for the cloud target" '"check_host":"cloud-mgmt.example.internal"' "$U"
check_has "the check's scheme is http" '"scheme":"http"' "$U"
check_has "header names shown, never values" '"Host"' "$U"
check_lacks "…the Host value is not" "health.example.internal" "$U"

check_has "clients arrive through the ingress with a PROXY v2 header" 'edgeguard_proxy_protocol_total{listener="public",result="proxied"}' "$(body "$ADMIN/__edgeguard/metrics" | grep 'result="proxied"' | grep -v ' 0$')"
# The counter alone does not prove the address is the client's. A client at a known address on the
# public network, straight to the ingress (a published port on rootless Docker/Podman would hand
# the ingress the forwarder's address instead: README.md), must be the client_ip the edge logs.
CLIENT_IP=10.233.11.150
"$E" run --rm --network "${COMPOSE_PROJECT_NAME}_public" --ip "$CLIENT_IP" docker.io/curlimages/curl:8.11.1 \
  -sk -o /dev/null --resolve "$HOST:8443:10.233.11.200" -H "Host: $HOST" "https://$HOST:8443/client-ip-check" 2>/dev/null || true
sleep 1
check_has "the edge logs the client's own address, from the PROXY header" "\"client_ip\":\"$CLIENT_IP\"" "$(compose logs --no-color edge 2>&1 | grep '/client-ip-check' | tail -1)"

step "the ingress follows a recreated edge (runtime DNS, no ingress restart)"
OLD_IP="$("$E" inspect "$(compose ps -q edge)" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
compose rm -sf edge >/dev/null 2>&1
# Hold the old address so the new edge cannot get it back.
"$E" run -d --rm --name egref-hybrid-ipsquat --network "${COMPOSE_PROJECT_NAME}_site" --ip "$OLD_IP" docker.io/library/busybox:1.36.1 sleep 300 >/dev/null 2>&1 || true
compose up -d edge 2>&1 | grep -iE 'error' || true
NEW_IP="$("$E" inspect "$(compose ps -q edge)" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
check "the edge came back at a new address (was $OLD_IP)" 1 "$([ -n "$NEW_IP" ] && [ "$OLD_IP" != "$NEW_IP" ] && echo 1 || echo 0)"
wait_code 200 60 "${T[@]}" -k "$HTTPS/" && pass "the same ingress reaches it at $NEW_IP, not restarted" || fail "the ingress did not follow the new edge address"
"$E" rm -f egref-hybrid-ipsquat >/dev/null 2>&1 || true

step "eject_after_5xx: onprem-b answers /boom with 500"
# One curl for the twelve /boom requests and the four that follow: separate processes on a slow
# host can outlast eject_for (10 s), and the check would see onprem-b back in rotation.
BOOM=(); for _ in $(seq 1 12); do BOOM+=(-o /dev/null "$HTTPS/boom"); done
AFTER=""; for _ in 1 2 3 4; do AFTER="$AFTER $HTTPS/x"; done
OUT="$(curl -sk "${T[@]}" -w '%{http_code}\n' "${BOOM[@]}" $AFTER 2>/dev/null || true)"
echo "    /boom: $(printf '%s\n' "$OUT" | grep -E '^[0-9]{3}$' | head -12 | tr '\n' ' ')"
M="$(body "$ADMIN/__edgeguard/metrics")"
check_has "onprem-b ejected for 5xx" 'reason="http_5xx"' "$(printf '%s' "$M" | grep '^edgeguard_upstream_ejections_total' | grep -v ' 0$')"
check "while b is out, everything goes to onprem-a (4 of 4)" 4 "$(printf '%s\n' "$OUT" | grep -c '^server=onprem-a' || true)"

step "failover: both on-prem servers stop; the cloud standby takes over, over mTLS"
check "the cloud target refuses a client without a certificate" 400 "$("$E" run --rm --network "${COMPOSE_PROJECT_NAME}_site" docker.io/curlimages/curl:8.11.1 -sk -o /dev/null -w '%{http_code}' https://cloud.example.internal:8443/ 2>/dev/null || true)"
compose stop onprem-a onprem-b >/dev/null 2>&1
GOT=""; for _ in $(seq 1 10); do GOT="$(srv "$HTTPS/")"; [ "$GOT" = cloud ] && break; sleep 1; done
check "\"/\" now answered by the backup" cloud "$GOT"
check_has "…which saw the edge's client certificate" "CN=edge" "$(body "${T[@]}" -k "$HTTPS/")"
check "\"/api/\" (priority) falls through to its backup tier too" cloud "$(srv "$HTTPS/api/x")"
sleep 5
U="$(body "$ADMIN/__edgeguard/upstreams")"
check_has "pool state is backup" '"state":"backup"' "$U"
check "readiness holds: a pool at \"/\" with a target in rotation" 200 "$(code "$ADMIN/__edgeguard/ready")"
compose start onprem-a onprem-b >/dev/null 2>&1
GOT=""; for _ in $(seq 1 20); do GOT="$(srv "$HTTPS/api/x")"; [ "$GOT" = onprem-a ] && break; sleep 1; done
check "failback: onprem-a takes /api/ again after healthy_after passing checks" onprem-a "$GOT"

summary
