#!/usr/bin/env bash
# Build the head-to-head comparison table from results/compare-*.json (+ matching .stats).
# Needs `jq`. Prints a Markdown table you can paste into docs/COMPARISON.md.
#
#   ./compare/summarize.sh            # latest run per target, baseline script
#   ./compare/summarize.sh auth       # ... for a different k6 script
#
# Note: k6's --summary-export emits p99 only as a threshold pass/fail (not a number), so the tail
# column is p95 (numeric) plus a p99<50ms PASS/FAIL. Run-compare passes --summary-trend-stats so
# newer runs also carry a numeric p(99); this script prefers it when present.
set -euo pipefail
cd "$(dirname "$0")/.."   # loadtest/
SCRIPT="${1:-baseline}"
command -v jq >/dev/null 2>&1 || { echo "jq required (apt/brew install jq)" >&2; exit 1; }

echo "| Target | Achieved RPS | p50 ms | p95 ms | p99 ms | Error % | Peak RSS* |"
echo "|---|---:|---:|---:|---:|---:|---:|"

for TARGET in edgeguard nginx haproxy caddy traefik envoy; do
  f="$(ls -1t results/compare-${TARGET}-${SCRIPT}-*.json 2>/dev/null | head -1 || true)"
  [[ -n "${f:-}" && -e "$f" ]] || continue

  read -r rps p50 p95 p99 err < <(jq -r '
    .metrics as $m |
    [ ($m.http_reqs.rate // 0),
      ($m.http_req_duration.med // 0),
      ($m.http_req_duration["p(95)"] // 0),
      ($m.http_req_duration["p(99)"] // -1),
      ( ($m.http_req_failed.value
         // ( ($m.http_req_failed.fails // 0) as $fa
              | ($m.http_req_failed.passes // 0) as $pa
              | if ($fa+$pa)>0 then $fa/($fa+$pa) else 0 end )) * 100 )
    ] | @tsv' "$f" 2>/dev/null | tr -d '\r')
  # Skip a partial/empty JSON (batch still writing): no achieved RPS yet.
  if [[ -z "${rps:-}" || "$rps" == "0" ]]; then continue; fi

  # Peak RSS from the matching .stats file. Handles podman (MB/GB/kB) and docker (MiB/GiB/KiB);
  # normalizes to MB. *Caveat: podman-on-WSL counts page cache, so treat as relative, not RSS truth.
  stats="${f%.json}.stats"; peak="n/a"
  if [[ -e "$stats" ]]; then
    peak="$(awk '{ v=$2; gsub(/[0-9.]+/,"",$2); u=$2; gsub(/[A-Za-z]+/,"",v)
        if (u ~ /[Gg]i?B/) v*=1024; else if (u ~ /[Kk]i?B/) v/=1024
        if (v>m) m=v } END { if (m>0) printf "%.0f MB", m; else print "n/a" }' "$stats")"
  fi

  p99disp="n/a"; [[ "$p99" != "-1" ]] && p99disp="$(printf '%.2f' "$p99")"
  printf "| %s | %.0f | %.2f | %.2f | %s | %.3f | %s |\n" \
    "$TARGET" "$rps" "$p50" "$p95" "$p99disp" "$err" "$peak"
done
