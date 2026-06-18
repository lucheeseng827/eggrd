#!/usr/bin/env bash
# Drive the isolated benchmark: copy the harness to the proxy host, bring up ALL six proxies
# (each on its own port, the five idle ones cost ~nothing), then from the SEPARATE loadgen host
# run the k6 saturation profile against each over the PRIVATE NIC. Captures proxy-side CPU/RSS.
#
#   ./run-saturation.sh [script]      # script defaults to "saturation"; "baseline" also valid
#
# Run ./provision.sh first (writes instances.env). Pull-back results land in ./results/.
set -euo pipefail
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
source ./config.env
source "$INSTANCES_ENV"
SCRIPT="${1:-saturation}"

SSH=(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -i "$PEM_PATH")
proxy()   { "${SSH[@]}" "ec2-user@${PROXY_PUB}"   "$@"; }
loadgen() { "${SSH[@]}" "ec2-user@${LOADGEN_PUB}" "$@"; }

# target -> "hostport composeservice containername"
declare -A MAP=(
  [edgeguard]="8080 edgeguard   edgeguard-loadtest-edgeguard-1"
  [nginx]="8081 nginx-proxy edgeguard-loadtest-nginx-proxy-1"
  [haproxy]="8082 haproxy     edgeguard-loadtest-haproxy-1"
  [caddy]="8083 caddy       edgeguard-loadtest-caddy-1"
  [traefik]="8084 traefik     edgeguard-loadtest-traefik-1"
  [envoy]="8085 envoy       edgeguard-loadtest-envoy-1"
)
ORDER=(edgeguard nginx haproxy caddy traefik envoy)

echo ">> waiting for cloud-init bootstrap markers (docker on proxy, k6 on loadgen)"
boot_ready=0
for _ in $(seq 1 60); do
  if proxy test -f PROXY_READY 2>/dev/null && loadgen test -f LOADGEN_READY 2>/dev/null; then
    echo ">> both hosts bootstrapped"
    boot_ready=1
    break
  fi; echo -n "."; sleep 5
done
[[ "$boot_ready" -eq 1 ]] || { echo "Bootstrap timeout waiting for PROXY_READY/LOADGEN_READY" >&2; exit 1; }

echo ">> shipping harness -> proxy:${PROXY_PUB}"
CRATE="$(cd ../.. && pwd)"; PARENT="$(dirname "$CRATE")"; CRATE_NAME="$(basename "$CRATE")"
tar czf - -C "$PARENT" \
  --exclude="${CRATE_NAME}/target" --exclude="${CRATE_NAME}/.git" \
  --exclude="${CRATE_NAME}/worker/target" --exclude="${CRATE_NAME}/loadtest/results" \
  "$CRATE_NAME" | proxy "tar xzf - -C ~ && echo unpacked"

echo ">> shipping k6 scripts -> loadgen:${LOADGEN_PUB}"
( cd ../k6 && tar czf - . ) | loadgen "mkdir -p ~/k6 && tar xzf - -C ~/k6 && echo unpacked"

echo ">> bringing up all six proxies on the proxy host (building EdgeGuard image)"
proxy "cd ~/${CRATE_NAME}/loadtest && docker compose -f docker-compose.yml -f docker-compose.compare.yml up -d --build upstream nginx-proxy haproxy caddy traefik envoy edgeguard"
echo ">> waiting for proxies to answer"
for t in "${ORDER[@]}"; do
  read -r port _ _ <<<"${MAP[$t]}"
  target_ready=0
  for _ in $(seq 1 60); do
    if proxy "curl -fsS http://localhost:${port}/ >/dev/null 2>&1"; then
      echo "   $t ($port) ok"
      target_ready=1
      break
    fi
    sleep 2
  done
  [[ "$target_ready" -eq 1 ]] || { echo "Proxy readiness timeout for ${t} on ${port}" >&2; exit 1; }
done

mkdir -p results
TS="$(proxy date +%Y%m%d-%H%M%S | tr -d '\r')"
loadgen "mkdir -p ~/results"

for t in "${ORDER[@]}"; do
  read -r port svc cname <<<"${MAP[$t]}"
  echo ">> ===== $t (proxy ${PROXY_PRIV}:${port}) ====="
  base="sat-${t}-${SCRIPT}-${TS}"
  # proxy-side CPU/RSS sampler (self-stops after ~200s > one saturation run)
  proxy "nohup bash -c 'for i in \$(seq 1 100); do docker stats --no-stream --format \"{{.CPUPerc}} {{.MemUsage}}\" ${cname} >> ~/${base}.stats 2>/dev/null; sleep 2; done' >/dev/null 2>&1 &" || true
  # k6 from the loadgen host, over the private NIC
  loadgen "k6 run --summary-trend-stats='avg,min,med,p(90),p(95),p(99),max' \
    -e BASE_URL=http://${PROXY_PRIV}:${port} \
    --summary-export ~/results/${base}.json ~/k6/${SCRIPT}.js 2>&1 | tail -30"
  # pull artifacts
  scp -o StrictHostKeyChecking=accept-new -i "$PEM_PATH" "ec2-user@${LOADGEN_PUB}:~/results/${base}.json" "results/" 2>/dev/null || true
  scp -o StrictHostKeyChecking=accept-new -i "$PEM_PATH" "ec2-user@${PROXY_PUB}:~/${base}.stats" "results/" 2>/dev/null || true
done

echo ">> done. EC2 results in ./results/sat-*.{json,stats}"
echo ">> summarize: ./summarize-ec2.sh ${SCRIPT}   |   teardown: ./teardown.sh"
