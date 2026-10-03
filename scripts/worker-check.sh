#!/usr/bin/env bash
# Build the Cloudflare Worker's deployable bundle and run it on workerd, the runtime Cloudflare runs
# in production.
#
#   bash scripts/worker-check.sh
#
# ONE implementation, used by CI and by hand. `cargo build --target wasm32-unknown-unknown` passing
# says little: the step that has broken before is `worker-build --release`, which runs wasm-bindgen
# and emits the bundle (see "Why strip is absent" in worker/README.md). So this script builds that
# bundle, checks it exists, then serves it with `wrangler dev --local` in front of a local origin
# and checks what the README promises:
#
#   * no credentials, or a wrong password  -> 401, and the origin is not reached;
#   * the right credentials                -> 200 from the origin, hardening headers added,
#                                             the origin's `Server` header stripped.
#
# It proves the bundle loads and behaves on workerd. It does NOT prove a Cloudflare deploy: routes,
# custom domains, secret bindings and quotas need an account, and stay a README caveat.
#
# Needs: rustup, cargo, node/npx, python3, curl. Installs the wasm target and worker-build if absent.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../worker"

# Pinned so a new release of either cannot change the bundle under an unchanged commit. Bump on
# purpose, together with Cargo.lock's `worker` / wasm-bindgen.
WORKER_BUILD_VERSION=0.8.7
WRANGLER_VERSION=4.146.0

rustup target add wasm32-unknown-unknown >/dev/null
if ! worker-build --version 2>/dev/null | grep -q "$WORKER_BUILD_VERSION"; then
  cargo install worker-build --version "$WORKER_BUILD_VERSION" --locked
fi

echo "::group::native tests"
cargo test --locked
echo "::endgroup::"

echo "::group::worker-build --release"
rm -rf build
# --locked reaches cargo: the bundle is built from the committed Cargo.lock, not a fresh resolve.
worker-build --release -- --locked
echo "::endgroup::"
for f in build/index.js build/index_bg.wasm build/worker/shim.mjs; do
  [ -s "$f" ] || { echo "::error::worker-build did not emit $f" >&2; exit 1; }
done
echo "bundle: $(stat -c %s build/index_bg.wasm) B wasm"

work="$(mktemp -d)"
origin_pid=""
wrangler_pid=""
cleanup() {
  [ -z "$wrangler_pid" ] || kill "$wrangler_pid" 2>/dev/null || true
  [ -z "$origin_pid" ] || kill "$origin_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
origin_port="$(free_port)"
worker_port="$(free_port)"

# The origin: python's http.server, which sends `Server: SimpleHTTP/…` — the header the worker
# must strip. It logs each request, so "the origin was not reached" can be checked.
echo "origin ok" >"$work/index.html"
python3 -m http.server "$origin_port" --bind 127.0.0.1 --directory "$work" \
  >"$work/origin.log" 2>&1 &
origin_pid=$!

# The build step already ran; `--var` overrides wrangler.toml's [vars] for this run only.
npx --yes "wrangler@$WRANGLER_VERSION" dev --local --ip 127.0.0.1 --port "$worker_port" \
  --var "EDGEGUARD_ORIGIN:http://127.0.0.1:$origin_port" \
  --var EDGEGUARD_AUTH_MODE:basic \
  --var EDGEGUARD_BASIC_USER:alice \
  --var EDGEGUARD_BASIC_PASS:correct-horse \
  >"$work/wrangler.log" 2>&1 &
wrangler_pid=$!

url="http://127.0.0.1:$worker_port/"
for _ in $(seq 1 120); do
  curl -s -o /dev/null "$url" && break
  sleep 1
done
curl -s -o /dev/null "$url" || {
  echo "::error::wrangler dev did not come up" >&2
  cat "$work/wrangler.log" >&2
  exit 1
}

fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then
    echo "ok   $1"
  else
    echo "::error::$1: expected $2, got $3" >&2
    fail=1
  fi
}

check "no credentials" 401 "$(curl -s -o /dev/null -w '%{http_code}' "$url")"
check "wrong password" 401 "$(curl -s -o /dev/null -w '%{http_code}' -u alice:wrong "$url")"
reached="$(grep -c '"GET / ' "$work/origin.log" || true)"
check "origin not reached while unauthenticated" 0 "$reached"

headers="$work/headers"
body="$(curl -s -D "$headers" -u alice:correct-horse "$url")"
check "right credentials" 200 "$(awk 'NR==1{print $2}' "$headers")"
check "body from the origin" "origin ok" "$body"
for h in strict-transport-security content-security-policy x-frame-options \
  x-content-type-options referrer-policy permissions-policy; do
  check "adds $h" yes "$(grep -qi "^$h:" "$headers" && echo yes || echo no)"
done
check "strips Server" no "$(grep -qi '^server: *SimpleHTTP' "$headers" && echo yes || echo no)"

if [ "$fail" -ne 0 ]; then
  echo "--- wrangler log ---" >&2
  tail -n 50 "$work/wrangler.log" >&2
  exit 1
fi
echo "Worker bundle built and served on workerd: auth, forwarding and hardening as documented."
