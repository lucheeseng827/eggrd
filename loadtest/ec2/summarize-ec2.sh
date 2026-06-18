#!/usr/bin/env bash
# Reduce the EC2 saturation results (results/sat-*.json + .stats) to a Markdown table.
# Needs jq. Achieved RPS under the past-the-knee push ~ the sustained ceiling when Error % > 0
# (the proxy is shedding); Error % ~ 0 with achieved < offered means it kept up — no knee found.
set -euo pipefail
cd "$(dirname "$0")"
SCRIPT="${1:-saturation}"
command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }

echo "| Target | Achieved RPS | p95 ms | p99 ms | Error % (shed) | Peak CPU % | Peak RSS MB |"
echo "|---|---:|---:|---:|---:|---:|---:|"
for t in edgeguard nginx haproxy caddy traefik envoy; do
  f="$(ls -1t results/sat-${t}-${SCRIPT}-*.json 2>/dev/null | head -1 || true)"
  [[ -n "${f:-}" && -e "$f" ]] || continue
  read -r rps p95 p99 err < <(jq -r '.metrics as $m |
    [ ($m.http_reqs.rate//0),
      ($m.http_req_duration["p(95)"]//0),
      ($m.http_req_duration["p(99)"]//0),
      (($m.http_req_failed.value // (($m.http_req_failed.fails//0) as $fa|($m.http_req_failed.passes//0) as $pa|if ($fa+$pa)>0 then $fa/($fa+$pa) else 0 end))*100)
    ]|@tsv' "$f" 2>/dev/null | tr -d '\r')
  if [[ -z "${rps:-}" ]]; then continue; fi
  s="${f%.json}.stats"; cpu="n/a"; rss="n/a"
  if [[ -e "$s" ]]; then
    cpu="$(awk '{gsub(/%/,"",$1); if($1>m)m=$1} END{if(m>0)printf "%.0f",m; else print "n/a"}' "$s")"
    rss="$(awk '{v=$2; gsub(/[0-9.]+/,"",$2); u=$2; gsub(/[A-Za-z]+/,"",v); if(u~/[Gg]i?B/)v*=1024; else if(u~/[Kk]i?B/)v/=1024; if(v>m)m=v} END{if(m>0)printf "%.0f",m; else print "n/a"}' "$s")"
  fi
  printf "| %s | %.0f | %.2f | %.2f | %.3f | %s | %s |\n" "$t" "$rps" "$p95" "$p99" "$err" "$cpu" "$rss"
done
