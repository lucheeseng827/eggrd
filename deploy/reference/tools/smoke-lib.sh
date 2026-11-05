# shellcheck shell=bash
# Shared helpers for the reference setups' smoke.sh scripts.
#
#   source "$(dirname "$0")/../tools/smoke-lib.sh"
#
# Each smoke.sh brings its setup up, asserts the status codes the README promises, and takes it
# down again (also on failure). PASS/FAIL per check, non-zero exit on any FAIL.
set -euo pipefail
# Git Bash on Windows rewrites container paths (/etc/... -> C:/Program Files/Git/etc/...).
export MSYS_NO_PATHCONV=1

EGGRD_IMAGE="${EGGRD_IMAGE:-docker.io/mancube/eggrd:0.7.0@sha256:b19278b379a457e626954e148effffa2fe559613d55ff497fdaa862c8c4096f6}"
REF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  _R=$'\033[31m'; _G=$'\033[32m'; _Y=$'\033[33m'; _B=$'\033[1m'; _O=$'\033[0m'
else _R=''; _G=''; _Y=''; _B=''; _O=''; fi
_FAILS=0
step() { printf '\n%s==> %s%s\n' "$_B" "$*" "$_O"; }
pass() { printf '%sPASS%s %s\n' "$_G" "$_O" "$*"; }
fail() { printf '%sFAIL%s %s\n' "$_R" "$_O" "$*"; _FAILS=$((_FAILS + 1)); }
note() { printf '%sNOTE%s %s\n' "$_Y" "$_O" "$*"; }
die()  { printf '%sFATAL%s %s\n' "$_R" "$_O" "$*" >&2; exit 1; }

check() { # what want got
  if [ "$2" = "$3" ]; then pass "$1 (= $3)"; else fail "$1: expected '$2', got '$3'"; fi
}
check_has() { # what needle haystack (case-insensitive)
  if grep -qiF -- "$2" <<< "$3"; then pass "$1"; else fail "$1: '$2' not in: $(printf '%.300s' "$3")"; fi
}
check_lacks() { # what needle haystack (case-insensitive)
  if grep -qiF -- "$2" <<< "$3"; then fail "$1: '$2' present"; else pass "$1"; fi
}

code()    { curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$@" 2>/dev/null || true; }
body()    { curl -sS --max-time 10 "$@" 2>/dev/null || true; }
headers() { curl -sS -D - -o /dev/null --max-time 10 "$@" 2>/dev/null || true; }

# wait_code <want> <timeout-s> curl-args...
wait_code() {
  local want="$1" budget="$2" waited=0 got=""; shift 2
  while :; do
    got="$(code "$@")"
    [ "$got" = "$want" ] && return 0
    [ "$waited" -ge "$budget" ] && { note "last status: ${got:-none}"; return 1; }
    sleep 2; waited=$((waited + 2))
  done
}

# engine / compose detection: docker first, then podman (Podman Compose hands off to
# docker-compose or podman-compose, either works).
engine() {
  if [ -n "${ENGINE:-}" ]; then printf '%s' "$ENGINE"
  elif command -v docker >/dev/null 2>&1; then printf docker
  elif command -v podman >/dev/null 2>&1; then printf podman
  else die "need docker or podman"; fi
}
compose() { "$(engine)" compose "$@"; }

# A path the container engine can mount. On Windows (Git Bash) the engine wants C:/... paths.
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

# doctor <dir> [file]: `edgeguard doctor` on <dir>/<file> in the pinned image; 0 errors or FAIL.
doctor() {
  local dir file out rc
  dir="$(hostpath "$1")"; file="${2:-edgeguard.toml}"
  set +e
  out="$(MSYS_NO_PATHCONV=1 "$(engine)" run --rm -v "$dir:/cfg:ro" "${DOCTOR_ARGS[@]+"${DOCTOR_ARGS[@]}"}" "$EGGRD_IMAGE" doctor --config "/cfg/$file" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then pass "doctor: ${1#"$REF_DIR"/}/$file ($(printf '%s' "$out" | tail -1))"
  else fail "doctor: ${1#"$REF_DIR"/}/$file exited $rc"; printf '%s\n' "$out" | sed 's/^/    /'; fi
}

summary() {
  if [ "$_FAILS" -eq 0 ]; then printf '\n%sALL CHECKS PASSED%s\n' "$_G$_B" "$_O"; return 0; fi
  printf '\n%s%d CHECK(S) FAILED%s\n' "$_R$_B" "$_FAILS" "$_O"; return 1
}
