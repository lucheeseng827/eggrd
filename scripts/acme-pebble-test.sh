#!/usr/bin/env bash
# Run the ACME issuance and renewal tests against Pebble, a real (test) ACME CA.
#
#   bash scripts/acme-pebble-test.sh
#
# ONE implementation, used by CI and by hand. ACME is the one path that can only be proven against
# a live CA — it needs a CA, DNS pointing at this host and the privilege to bind :80 — so its tests
# are `#[ignore]`d in the default suite. This script provides all three and then insists the tests
# actually ran: they return early with "skipping" when the CA is not configured, and an early return
# is a pass, so a broken rig would otherwise report green while proving nothing.
#
# Needs: docker (with compose), curl, and either root or passwordless sudo (to trust the test CA's
# root and to allow binding :80). Leaves the trust-store entry behind; CI runners are disposable.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
COMPOSE=(docker compose -f loadtest/pebble.compose.yaml)
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- Pebble / challtestsrv logs ---"
    "${COMPOSE[@]}" logs --no-color --tail=200 || true
  fi
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

echo "Starting Pebble"
"${COMPOSE[@]}" up -d

# The directory endpoint serves TLS from Pebble's *minica* root — not the root it issues from (see
# the compose file). Wait for it with -k, then trust the minica root so the ACME client verifies it.
for _ in $(seq 1 60); do
  curl -skf https://localhost:14000/dir >/dev/null && break
  sleep 1
done
curl -skf https://localhost:14000/dir >/dev/null || { echo "Pebble did not come up on :14000" >&2; exit 1; }

root="$(mktemp)"
"${COMPOSE[@]}" cp pebble:/test/certs/pebble.minica.pem "$root"
$SUDO cp "$root" /usr/local/share/ca-certificates/pebble-minica.crt
$SUDO update-ca-certificates >/dev/null
rm -f "$root"

# Validation dials the test domain on :80. Point challtestsrv's default A record at this host as
# seen from the compose network (its gateway); the hard-coded `host-gateway` in the compose file
# only resolves under Docker Desktop.
pebble_id="$("${COMPOSE[@]}" ps -q pebble)"
gateway="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$pebble_id")"
[ -n "$gateway" ] || { echo "could not determine the compose network gateway" >&2; exit 1; }
curl -sf -X POST -d "{\"ip\":\"$gateway\"}" http://localhost:8055/set-default-ipv4 >/dev/null
echo "Test domain resolves to $gateway"

# The HTTP-01 challenge port is fixed at 80 by RFC 8555. Let an unprivileged process bind it, rather
# than running cargo as root (which would leave root-owned files in target/).
if [ "$(id -u)" -ne 0 ]; then
  $SUDO sysctl -qw net.ipv4.ip_unprivileged_port_start=80
fi

out="$(mktemp)"
EDGEGUARD_TEST_ACME_DIR=https://localhost:14000/dir \
EDGEGUARD_TEST_ACME_DOMAIN=edgeguard.test \
EDGEGUARD_TEST_ACME_DNS_URL=http://localhost:8055 \
  cargo test --lib acme::tests:: -- --ignored --nocapture --test-threads=1 2>&1 | tee "$out"

# The guard that makes this worth running: every Pebble test must have RUN, not returned early.
fail=0
# Unanchored: with stdout and stderr merged, the test's "skipping …" line can land mid-line, right
# after cargo's "test … " prefix — and the test is then still reported as "ok".
if grep -q 'skipping' "$out"; then
  echo "::error::an ACME test skipped instead of running — the rig is not configured" >&2
  fail=1
fi
for t in acme_http01_issues_against_pebble acme_renewal_through_the_redirect_listener_against_pebble acme_dns01_wildcard_issues_against_pebble acme_ari_window_and_replacing_renewal_against_pebble; do
  if ! grep -q "acme::tests::$t \.\.\. ok" "$out"; then
    echo "::error::$t did not pass" >&2
    fail=1
  fi
done
rm -f "$out"
[ "$fail" -eq 0 ] || exit 1
echo "ACME issuance (HTTP-01 and DNS-01 wildcard), renewal and ARI proven against Pebble."
