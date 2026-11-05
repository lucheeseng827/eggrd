#!/usr/bin/env bash
# Smoke test for the monitoring reference: the rules pass promtool (bundle and these), the stack
# comes up, Prometheus scrapes the 0.7.0 edge and has loaded every alert, the 0.7 series have
# data, and Grafana has provisioned the bundle's dashboards and this one. Docker or Podman.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../tools/smoke-lib.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
E="$(engine)"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-egref-mon}"
export EDGE_ADMIN_PORT=31092 PROMETHEUS_PORT=31091 GRAFANA_PORT=31300
PROM="http://127.0.0.1:$PROMETHEUS_PORT"
GRAF="http://127.0.0.1:$GRAFANA_PORT"
BUNDLE="$(cd "$HERE/../../../monitoring" && pwd)"
cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then note "KEEP=1: Grafana on $GRAF, Prometheus on $PROM"; return; fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
PT=("$E" run --rm --entrypoint promtool docker.io/prom/prometheus:v2.54.1)

step "rules and config"
check "monitoring bundle version" 1.6.2 "$(tr -d '\r\n' < "$BUNDLE/VERSION")"
DOCTOR_ARGS=(-e EDGEGUARD_API_KEYS=demo-key-alpha)   # the keys come from the environment, as in compose
doctor "$HERE/config"
"$E" run --rm --entrypoint promtool -v "$(hostpath "$HERE/prometheus"):/r:ro" -w /r docker.io/prom/prometheus:v2.54.1 test rules rules-0.7.test.yml >/dev/null 2>&1 \
  && pass "promtool test rules: rules-0.7.test.yml" || fail "promtool test rules-0.7"
"$E" run --rm --entrypoint promtool -v "$(hostpath "$BUNDLE/prometheus"):/r:ro" -w /r docker.io/prom/prometheus:v2.54.1 test rules alerts.test.yml >/dev/null 2>&1 \
  && pass "promtool test rules: the bundle's alerts.test.yml" || fail "promtool test bundle alerts"

step "up"
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d 2>&1 | grep -iE 'error' || true
wait_code 200 90 "http://127.0.0.1:$EDGE_ADMIN_PORT/__edgeguard/ready" || fail "edge not ready"
wait_code 200 90 "$PROM/-/ready" || fail "prometheus not ready"
wait_code 200 120 "$GRAF/api/health" || fail "grafana not ready"
note "letting traffic run for 40 s"; sleep 40

q() { body "$PROM/api/v1/query" --data-urlencode "query=$1"; }
nonzero() { # what promql
  local r; r="$(q "$2")"
  if printf '%s' "$r" | grep -q '"result":\[{'; then pass "$1"; else fail "$1: no data for $2"; fi
}

step "Prometheus: target, alerts"
check_has "edgeguard target up" '"value":[' "$(q 'up{job="edgeguard"} == 1')"
RULES="$(body "$PROM/api/v1/rules")"
for a in EdgeGuardProxyProtocolRefused EdgeGuardUpstreamPoolDown EdgeGuardConnectionsNearCap EdgeGuardCrlStale EdgeGuardRouteLatencyRegression EdgeGuardForwardedForFallback EdgeGuardTlsHandshakeFailureRatio; do
  check_has "alert loaded: $a" "\"name\":\"$a\"" "$RULES"
done

step "the 0.7 series have data"
nonzero "requests in flight (slow requests)" 'max_over_time(edgeguard_requests_in_flight{listener="public"}[1m]) > 0'
nonzero "TLS handshakes" 'rate(edgeguard_tls_handshakes_total[1m]) > 0'
nonzero "handshake failures (plaintext to the TLS port)" 'rate(edgeguard_tls_handshake_failures_total[1m]) > 0'
nonzero "connections closed before a ClientHello" 'rate(edgeguard_tls_no_client_hello_total[1m]) > 0'
nonzero "X-Forwarded-For used (through front)" 'rate(edgeguard_forwarded_for_total{result="used"}[1m]) > 0'
nonzero "X-Forwarded-For absent (straight to the edge)" 'rate(edgeguard_forwarded_for_total{result="absent"}[1m]) > 0'
nonzero "connections open vs cap" 'edgeguard_connections_max{listener="public"} == 512'
nonzero "per-route series (api, login, legacy)" 'count(count by (route) (edgeguard_route_requests_total)) >= 3'
nonzero "per-consumer series (3 keys + _anon)" 'count(count by (consumer) (edgeguard_consumer_requests_total)) >= 4'
nonzero "per-upstream connect_error (legacy)" 'edgeguard_upstream_requests_total{result="connect_error"} > 0'
nonzero "edge overhead histogram" 'edgeguard_edge_overhead_seconds_count > 0'

step "Grafana: dashboards provisioned"
S="$(body "$GRAF/api/search?type=dash-db")"
for uid in edgeguard-overview edgeguard-api-usage edgeguard-07-listeners; do check_has "dashboard $uid" "\"uid\":\"$uid\"" "$S"; done
DS="$(body "$GRAF/api/datasources/uid/edgeguard-prometheus/health" -u "admin:${GF_ADMIN_PASSWORD:-admin}")"
check_has "datasource reaches Prometheus" '"status":"OK"' "$DS"

summary
