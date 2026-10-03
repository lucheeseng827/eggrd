#!/usr/bin/env bash
# Run the live-Redis tests (the distributed rate limiter's GCRA script and the LLM budget's
# reserve/reconcile) against a real Redis.
#
#   bash scripts/redis-live-test.sh
#
# ONE implementation, used by CI and by hand. The tests are `#[ignore]`d in the default suite
# because they need a Redis, and they return early with "skipping" when it is unreachable — an
# early return that cargo reports as "ok". So this script provides the Redis and then insists every
# test actually RAN, the same guard the Pebble job has.
#
# With EDGEGUARD_TEST_REDIS_URL set it uses that server. Otherwise it starts a throwaway
# redis:7-alpine under docker on a free loopback port and removes it on exit.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

TESTS=(
  limiter::tests::redis_store_enforces_global_limit_live
  limiter::tests::redis_store_per_key_limit_live
  budget::tests::redis_budget_reserve_and_reconcile_live
)

container=""
cleanup() {
  [ -z "$container" ] || docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ -z "${EDGEGUARD_TEST_REDIS_URL:-}" ]; then
  echo "Starting Redis"
  container="$(docker run -d --rm -p 127.0.0.1::6379 redis:7-alpine)"
  port="$(docker port "$container" 6379/tcp | head -n1 | sed 's/.*://')"
  for _ in $(seq 1 30); do
    docker exec "$container" redis-cli ping 2>/dev/null | grep -q PONG && break
    sleep 1
  done
  docker exec "$container" redis-cli ping 2>/dev/null | grep -q PONG \
    || { echo "Redis did not come up" >&2; exit 1; }
  export EDGEGUARD_TEST_REDIS_URL="redis://127.0.0.1:$port"
fi
# The URL may carry a password; say only that one is in use.
echo "Testing against a live Redis"

out="$(mktemp)"
cargo test --lib _live -- --ignored --nocapture --test-threads=1 2>&1 | tee "$out"

# The guard that makes this worth running: every live test must have RUN, not returned early.
fail=0
# Unanchored: with stdout and stderr merged, a test's "skipping …" line can land mid-line, right
# after cargo's "test … " prefix — and the test is then still reported as "ok".
if grep -q 'skipping' "$out"; then
  echo "::error::a live-Redis test skipped instead of running — Redis was unreachable" >&2
  fail=1
fi
for t in "${TESTS[@]}"; do
  if ! grep -q "$t \.\.\. ok" "$out"; then
    echo "::error::$t did not pass" >&2
    fail=1
  fi
done
rm -f "$out"
[ "$fail" -eq 0 ] || exit 1
echo "Rate limiter and LLM budget proven against a live Redis."
