#!/usr/bin/env bash
# Head-to-head: run the SAME k6 profile against EdgeGuard or a market competitor, on the same
# host, against the same trivial upstream, so the numbers are apples-to-apples (vendor white-paper
# RPS on foreign hardware is not comparable — this is).
#
#   ./run-compare.sh <target> [script]
#
#   <target>  edgeguard | nginx | haproxy | caddy | traefik | envoy
#   <script>  a k6 script in k6/ (sans .js); default: baseline
#
# Examples:
#   ./run-compare.sh edgeguard            # EdgeGuard baseline (auth/limit/waf off)
#   ./run-compare.sh nginx                # nginx pure passthrough, same profile
#   for t in edgeguard nginx haproxy caddy traefik envoy; do ./run-compare.sh "$t"; done
#   ./compare/summarize.sh                # build the comparison table from results/
#
# Container engine: auto-detects `docker` then `podman`; override with COMPOSE_BIN=podman.
# Leaves the target + upstream running; tear down with:
#   <engine> compose -f docker-compose.yml -f docker-compose.compare.yml down -v
set -euo pipefail
cd "$(dirname "$0")"

# Git-Bash/MSYS rewrites leading-slash args (the k6 container paths /scripts/.. and /results/..)
# into Windows paths (C:/Program Files/Git/..). Disable that so they reach k6 verbatim.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

TARGET="${1:?usage: run-compare.sh <edgeguard|nginx|haproxy|caddy|traefik|envoy> [script]}"
SCRIPT="${2:-baseline}"
[[ -f "k6/${SCRIPT}.js" ]] || { echo "no such script: k6/${SCRIPT}.js" >&2; exit 1; }

# Pick the container engine (podman exposes the same `compose`/`stats`/`ps` verbs as docker).
ENGINE="${COMPOSE_BIN:-}"
if [[ -z "$ENGINE" ]]; then
  if command -v docker >/dev/null 2>&1; then ENGINE=docker
  elif command -v podman >/dev/null 2>&1; then ENGINE=podman
  else echo "neither docker nor podman on PATH" >&2; exit 1; fi
fi
compose() { "$ENGINE" compose -f docker-compose.yml -f docker-compose.compare.yml "$@"; }

# target -> (compose service, published host port). edgeguard comes from the BASE compose file.
case "$TARGET" in
  edgeguard) SVC=edgeguard;   HOSTPORT=8080; export EG_SCENARIO=baseline ;;
  nginx)     SVC=nginx-proxy; HOSTPORT=8081 ;;
  haproxy)   SVC=haproxy;     HOSTPORT=8082 ;;
  caddy)     SVC=caddy;       HOSTPORT=8083 ;;
  traefik)   SVC=traefik;     HOSTPORT=8084 ;;
  envoy)     SVC=envoy;       HOSTPORT=8085 ;;
  *) echo "unknown target: $TARGET (want edgeguard|nginx|haproxy|caddy|traefik|envoy)" >&2; exit 1 ;;
esac

echo ">> engine=$ENGINE target=$TARGET service=$SVC script=$SCRIPT"
compose up -d --build upstream "$SVC"

# Uniform readiness: every proxy forwards "/" to the upstream stub (returns 200 "ok").
echo -n ">> waiting for $TARGET readiness "
ready=0
for _ in $(seq 1 90); do
  if curl -fsS --connect-timeout 1 --max-time 1 "http://localhost:${HOSTPORT}/" >/dev/null 2>&1; then echo "ok"; ready=1; break; fi
  echo -n "."; sleep 1
done
[[ "$ready" -eq 1 ]] || { echo; echo ">> $TARGET readiness timeout — aborting" >&2; exit 1; }

mkdir -p results
TS="$(date +%Y%m%d-%H%M%S)"
OUT="results/compare-${TARGET}-${SCRIPT}-${TS}"

# Sample CPU%/RSS of the target container for the duration of the run (flat == healthy).
CID="$(compose ps -q "$SVC")"
( while :; do "$ENGINE" stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' "$CID" 2>/dev/null; sleep 2; done ) > "${OUT}.stats" &
STATS_PID=$!
trap 'kill "$STATS_PID" 2>/dev/null || true' EXIT

echo ">> running k6 (BASE_URL=http://${SVC}:8080) -> ${OUT}.{json,log,stats}"
# --no-deps so `compose run k6` does NOT also boot the edgeguard service for competitor targets.
compose run --rm --no-deps -e BASE_URL="http://${SVC}:8080" \
  k6 run --summary-trend-stats="avg,min,med,p(90),p(95),p(99),max" \
  --summary-export "/${OUT}.json" "/scripts/${SCRIPT}.js" 2>&1 | tee "${OUT}.log"

kill "$STATS_PID" 2>/dev/null || true
echo ">> done: ${OUT}.json (k6 summary) + ${OUT}.stats (cpu/mem samples)"
echo ">> build the table: ./compare/summarize.sh"
