#!/usr/bin/env bash
# Drive one EdgeGuard load-test run end to end.
#
#   ./run.sh <scenario> <script> [--direct]
#
#   <scenario>  a config in configs/ (sans .toml): baseline | auth-apikey |
#               ratelimit-local | ratelimit-redis | waf-block | full
#   <script>    a k6 script in k6/ (sans .js): baseline | auth | ratelimit | waf |
#               saturation | soak
#   --direct    point k6 at the nginx stub instead of the proxy (same script/profile), to
#               measure the "proxy tax" as the delta vs. the proxied run.
#
# Examples:
#   ./run.sh baseline   baseline             # proxied baseline
#   ./run.sh baseline   baseline --direct    # direct-to-upstream baseline (for the delta)
#   ./run.sh full       saturation           # realistic policy, find the knee
#   ./run.sh ratelimit-redis ratelimit       # distributed limiter under overload
#
# Brings up the stack, waits for readiness, runs k6 with a JSON summary exported to results/,
# and leaves the stack running so you can scrape Prometheus (http://localhost:9091) or open
# Grafana (`docker compose --profile observability up -d grafana` -> http://localhost:3000).
# Tear down with: docker compose down -v
set -euo pipefail
cd "$(dirname "$0")"

SCENARIO="${1:?usage: run.sh <scenario> <script> [--direct]}"
SCRIPT="${2:?usage: run.sh <scenario> <script> [--direct]}"
DIRECT="${3:-}"
[[ -z "${DIRECT}" || "${DIRECT}" == "--direct" ]] || {
  echo "invalid third argument: ${DIRECT} (expected --direct)" >&2
  exit 1
}

[[ -f "configs/${SCENARIO}.toml" ]] || { echo "no such scenario: configs/${SCENARIO}.toml" >&2; exit 1; }
[[ -f "k6/${SCRIPT}.js" ]]          || { echo "no such script: k6/${SCRIPT}.js" >&2; exit 1; }

compose() { docker compose "$@"; }

echo ">> scenario=${SCENARIO} script=${SCRIPT} ${DIRECT}"
export EG_SCENARIO="${SCENARIO}"

# Bring up everything except k6 (which we invoke per-run) and grafana (opt-in profile).
compose up -d --build edgeguard upstream redis prometheus

# Wait until EdgeGuard reports the upstream reachable (readiness probe on the admin listener).
echo -n ">> waiting for edgeguard readiness "
ready=0
for _ in $(seq 1 60); do
  if curl -fsS "http://localhost:9090/__edgeguard/ready" >/dev/null 2>&1; then
    echo "ok"; ready=1; break
  fi
  echo -n "."; sleep 1
done
if [[ "${ready}" -ne 1 ]]; then
  echo
  echo ">> edgeguard readiness timeout after 60s — aborting (not running k6 against a dead target)" >&2
  exit 1
fi

mkdir -p results
TS="$(date +%Y%m%d-%H%M%S)"
OUT="results/${SCENARIO}-${SCRIPT}${DIRECT:+-direct}-${TS}"

# In --direct mode k6 hits the nginx stub on the compose network instead of the proxy.
BASE_URL="http://edgeguard:8080"
[[ "${DIRECT}" == "--direct" ]] && BASE_URL="http://upstream:80"

echo ">> running k6 (BASE_URL=${BASE_URL}) -> ${OUT}.{json,log}"
compose run --rm \
  -e BASE_URL="${BASE_URL}" \
  k6 run --summary-export "/${OUT}.json" "/scripts/${SCRIPT}.js" 2>&1 | tee "${OUT}.log"

echo ">> done. summary: ${OUT}.json   |   Prometheus: http://localhost:9091"
echo ">>   tear down with: docker compose down -v"
