#!/usr/bin/env bash
# Smoke test for the compose-single-vm reference: doctor, up, the promised status codes, hot
# reload, the drain, down. Runs on Docker or Podman; ports are moved off 80/443/9090 so it needs
# no privilege and leaves a real deployment on the same host alone.
#
#   ./smoke.sh            # KEEP=1 ./smoke.sh leaves the stack up afterwards
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../tools/smoke-lib.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-egref-compose}"
export EDGE_BIND=127.0.0.1 EDGE_HTTPS_PORT="${EDGE_HTTPS_PORT:-28443}" EDGE_HTTP_PORT="${EDGE_HTTP_PORT:-28080}" EDGE_ADMIN_PORT="${EDGE_ADMIN_PORT:-29090}"
HOST=app.example.test
HTTPS="https://$HOST:$EDGE_HTTPS_PORT"
TLS=(--resolve "$HOST:$EDGE_HTTPS_PORT:127.0.0.1" -k -H "Host: $HOST")
ADMIN="http://127.0.0.1:$EDGE_ADMIN_PORT"

# The edge runs from a COPY of config/ kept on the engine's own filesystem (/tmp/<project>-cfg on
# the Docker host, or inside the Podman/Docker Desktop VM). Two reasons: the checked-in file is
# never edited, and hot reload can be tested honestly. A bind mount of a Windows or macOS folder
# into the engine's VM delivers no file-change events, so eggrd never sees an edit there; on a
# Linux VM, the real target of this setup, ./config is on the engine's filesystem already.
CFG="/tmp/$COMPOSE_PROJECT_NAME-cfg"
on_engine() { "$(engine)" run --rm -i -v /tmp:/hosttmp docker.io/library/busybox:1.36.1 sh -c "$1"; }
put_config() { on_engine "cat > /hosttmp/$COMPOSE_PROJECT_NAME-cfg/edgeguard.toml"; }   # stdin -> config, same inode
on_engine "rm -rf /hosttmp/$COMPOSE_PROJECT_NAME-cfg && mkdir -p /hosttmp/$COMPOSE_PROJECT_NAME-cfg"
# drain_delay 2s -> 30s for the copy only: long enough to observe the drain from this script.
sed 's/^drain_delay = "2s"/drain_delay = "30s"/' config/edgeguard.toml | put_config
export EDGE_CONFIG_DIR="$CFG"

cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then note "KEEP=1: stack left up ($COMPOSE_PROJECT_NAME), config copy in $CFG on the engine host"; return; fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  on_engine "rm -rf /hosttmp/$COMPOSE_PROJECT_NAME-cfg" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "doctor: 0 errors on both configs"
doctor "$HERE/config"
doctor "$HERE/config-acme"

step "the logging override renders (validated, not shipped anywhere)"
if compose -f compose.yaml -f compose.logging.yaml config 2>/dev/null | grep -q 'driver: awslogs'; then pass "compose.logging.yaml merges: edge logs via awslogs"; else fail "compose.logging.yaml does not render"; fi

step "up"
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d 2>&1 | tail -n 3
wait_code 200 90 "$ADMIN/__edgeguard/ready" || fail "edge never became ready"
EDGE_CID="$(compose ps -q edge)"

step "the container runs hardened"
INSPECT="$("$(engine)" inspect "$EDGE_CID" --format '{{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} drop={{.HostConfig.CapDrop}} add={{.HostConfig.CapAdd}} sec={{.HostConfig.SecurityOpt}} mem={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}} img={{.Config.Image}}')"
echo "    $INSPECT"
check_has "runs as 65532" "65532:65532" "$INSPECT"
check_has "read-only root" "ro=true" "$INSPECT"
# Docker lists ALL in CapDrop and NET_BIND_SERVICE in CapAdd; Podman lists what it dropped. Either
# way the proof is that a non-root process holds :443, which the ready check above already showed.
case "$INSPECT" in
  *add=*NET_BIND_SERVICE*) pass "NET_BIND_SERVICE added back (CapAdd)" ;;
  *drop=\[*CAP_CHOWN*) case "$INSPECT" in *NET_BIND*) fail "NET_BIND_SERVICE dropped" ;; *) pass "every capability dropped but NET_BIND_SERVICE" ;; esac ;;
  *) fail "capabilities not as expected" ;;
esac
check_has "no-new-privileges" "no-new-privileges" "$INSPECT"
check_has "memory limit" "mem=201326592" "$INSPECT"
check_has "pids limit" "pids=256" "$INSPECT"
check_has "image pinned by digest" "@sha256:b19278b3" "$INSPECT"

step "admin listener: loopback only, not on the public port"
check "admin /__edgeguard/ready" 200 "$(code "$ADMIN/__edgeguard/ready")"
check "admin /__edgeguard/health" 200 "$(code "$ADMIN/__edgeguard/health")"
check "ops paths 404 on the public port" 404 "$(code "${TLS[@]}" "$HTTPS/__edgeguard/metrics")"
PUB="$("$(engine)" port "$EDGE_CID" 9090/tcp 2>/dev/null || true)"
check_has "admin published on 127.0.0.1 only" "127.0.0.1:$EDGE_ADMIN_PORT" "$PUB"

step "TLS, headers, redirect"
check "GET / over TLS" 200 "$(code "${TLS[@]}" "$HTTPS/")"
H="$(headers "${TLS[@]}" "$HTTPS/")"
check_has "HSTS" "strict-transport-security: max-age=63072000" "$H"
check_has "CSP enforced" "content-security-policy: default-src 'self'; script-src 'self'" "$H"
check_has "X-Frame-Options" "x-frame-options: DENY" "$H"
check_lacks "Server header stripped" "server:" "$H"
R="$(headers -H "Host: $HOST" "http://127.0.0.1:$EDGE_HTTP_PORT/login?next=1")"
check_has ":80 answers 308" "HTTP/1.1 308" "$R"
check_has "Location is https on the pinned host" "location: https://$HOST/login?next=1" "$R"
check "a forged Host gets no redirect" 400 "$(code -H 'Host: evil.example' "http://127.0.0.1:$EDGE_HTTP_PORT/")"

step "refusals: Host rule, WAF, methods, rate limit"
check "forged Host -> 403" 403 "$(code --resolve "$HOST:$EDGE_HTTPS_PORT:127.0.0.1" -k -H 'Host: evil.example' "$HTTPS/")"
check "raw-IP Host -> 403" 403 "$(code -k "https://127.0.0.1:$EDGE_HTTPS_PORT/")"
check "Host with the port -> 200" 200 "$(code --resolve "$HOST:$EDGE_HTTPS_PORT:127.0.0.1" -k -H "Host: $HOST:443" "$HTTPS/")"
check "SQLi in the query -> 403" 403 "$(code "${TLS[@]}" "$HTTPS/search?q=1%20UNION%20SELECT%20password%20FROM%20users")"
check "path traversal -> 403" 403 "$(code "${TLS[@]}" --path-as-is "$HTTPS/../../etc/passwd")"
check "PROPFIND -> 405" 405 "$(code "${TLS[@]}" -X PROPFIND "$HTTPS/")"
check "TRACE -> 405" 405 "$(code "${TLS[@]}" -X TRACE "$HTTPS/")"
SAW=""
for _ in $(seq 1 10); do SAW="$SAW $(code "${TLS[@]}" "$HTTPS/login")"; done
check_has "/login sheds at 5/min burst 3 -> 429" "429" "$SAW"
check "other routes still 200 after /login shed" 200 "$(code "${TLS[@]}" "$HTTPS/")"

step "what the app receives (0.7 header scrub)"
B="$(body "${TLS[@]}" -H 'X-Forwarded-For: 203.0.113.9' -H 'X-Real-IP: 203.0.113.10' -H 'True-Client-IP: 203.0.113.11' -H 'X-Forwarded-Host: evil.example' "$HTTPS/")"
check_lacks "client's X-Forwarded-For not believed" "203.0.113.9" "$B"
check_lacks "client's X-Real-IP replaced" "203.0.113.10" "$B"
check_lacks "True-Client-IP removed" "203.0.113.11" "$B"
check_lacks "client's X-Forwarded-Host replaced" "evil.example" "$B"
check_has "Forwarded set by the edge" "Forwarded: for=" "$B"

step "healthcheck sidecar (the distroless answer)"
HS=""
for _ in $(seq 1 30); do
  HS="$("$(engine)" inspect "$(compose ps -q edge-health)" --format '{{.State.Health.Status}}' 2>/dev/null || true)"
  [ "$HS" = healthy ] && break; sleep 2
done
check "edge-health reports the edge ready" healthy "$HS"

step "hot reload (directory mount): drop DELETE from allow_methods"
check "DELETE before the edit" 200 "$(code "${TLS[@]}" -X DELETE "$HTTPS/x")"
sed -e 's/^drain_delay = "2s"/drain_delay = "30s"/' -e 's/"PATCH", "DELETE", "OPTIONS"/"PATCH", "OPTIONS"/' config/edgeguard.toml | put_config
GOT=""
for _ in $(seq 1 15); do GOT="$(code "${TLS[@]}" -X DELETE "$HTTPS/x")"; [ "$GOT" = 405 ] && break; sleep 1; done
check "DELETE after the edit, no restart" 405 "$GOT"
check_has "the edge logged the reload" "config reloaded" "$(compose logs --no-color edge 2>&1 | grep -i 'config reloaded' | tail -1)"

step "drain: SIGTERM turns ready 503 while the edge keeps serving"
"$(engine)" kill --signal TERM "$EDGE_CID" >/dev/null
T0=$SECONDS
check "traffic during drain_delay" 200 "$(code "${TLS[@]}" "$HTTPS/")"
check "ready during drain_delay" 503 "$(code "$ADMIN/__edgeguard/ready")"
check "health during drain_delay" 200 "$(code "$ADMIN/__edgeguard/health")"
note "the three checks took $((SECONDS - T0)) s of the 30 s drain_delay (a loaded machine can run past it)"
sleep 32
# What happens next depends on the engine: Docker's restart policy starts the edge again, Podman's
# does not restart a container it was asked to signal. The edge's own log is what is checked.
LOGS="$("$(engine)" logs "$EDGE_CID" 2>&1 | grep -i -E 'still accepting during drain_delay|draining connections' || true)"
check_has "the edge kept accepting for drain_delay, then drained" "still accepting during drain_delay" "$LOGS"
note "edge now: $("$(engine)" inspect "$EDGE_CID" --format '{{.State.Status}} (exit {{.State.ExitCode}})' 2>/dev/null || true)"

summary
