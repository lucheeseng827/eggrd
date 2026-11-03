#!/usr/bin/env bash
# Assert, heal and watch the published image tags of a release.
#
# Used by .github/workflows/release.yml after the multi-arch manifest is pushed. Kept as a
# script, rather than inline in the workflow, so the exact code that guards a release can be
# run against a local registry before it guards one.
#
#   release-tags.sh assert IMAGE TAG...
#   release-tags.sh watch  IMAGE MINUTES INTERVAL_SECONDS TAG...
#
# Environment:
#   EXPECT_DIGEST    the index digest every tag must resolve to. Unset: the first tag's digest,
#                    so the tags must at least agree with each other.
#   EXPECT_CHILDREN  space-separated per-arch digests this run built; each must be in the index.
#   HEAL=1           when a tag is wrong, re-point it to EXPECT_DIGEST once, then re-assert.
#   PLATFORMS        required platforms (default "linux/amd64 linux/arm64").
#
# `assert` checks every tag once: it must be a multi-platform index (OCI image index or Docker
# manifest list) that names every required platform, and all tags must share one digest. Any
# failure exits non-zero. With HEAL=1 and EXPECT_DIGEST set, a wrong tag is re-pointed once and
# the whole set is asserted again; a heal still exits 3, so the run is not green.
#
# `watch` repeats the check for MINUTES. A tag that is correct when the release finishes can be
# overwritten afterwards by any other publisher holding the repository's credentials. That is what
# happened to 0.5.0, 0.7.0-rc.1 and 0.7.0: an amd64-only image built outside this workflow replaced
# the index about 22 minutes after the tag, by which time the release run had already passed.
#
# Exit codes: 0 all good; 1 a tag is wrong (and was not healed); 2 usage; 3 a tag was wrong and
# has been healed (the tags are correct now, but something overwrote them); 4 (assert only) the
# registry could not be read, so there is no verdict.
set -euo pipefail

PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64}"

die_usage() { sed -n '8,9p' "$0" >&2; exit 2; }

# digest_of REF -> the manifest digest REF resolves to.
digest_of() {
  docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -r '.digest'
}

# check_tag IMAGE TAG WANT_DIGEST -> prints a reason and returns 1 if the tag is wrong, 2 if the
# registry could not be read (no verdict either way).
check_tag() {
  local image="$1" tag="$2" want="$3" ref raw mt digest plat
  ref="${image}:${tag}"
  if ! raw=$(docker buildx imagetools inspect --raw "$ref" 2>&1); then
    # A tag that is gone is wrong, not unreadable: heal can put it back.
    if grep -qi "not found" <<<"$raw"; then
      echo "${ref}: does not exist"
      return 1
    fi
    echo "${ref}: cannot be inspected: ${raw}"
    return 2
  fi
  mt=$(jq -r '.mediaType // empty' <<<"$raw")
  case "$mt" in
    application/vnd.oci.image.index.v1+json | application/vnd.docker.distribution.manifest.list.v2+json) ;;
    *)
      echo "${ref}: is a single-platform manifest (${mt:-no mediaType}), not a multi-arch index"
      return 1
      ;;
  esac
  for plat in $PLATFORMS; do
    if ! jq -e --arg os "${plat%%/*}" --arg arch "${plat#*/}" \
      '[.manifests[]? | select(.platform.os == $os and .platform.architecture == $arch)] | length > 0' \
      <<<"$raw" >/dev/null; then
      echo "${ref}: index has no ${plat} (has: $(jq -r '[.manifests[]?.platform | "\(.os)/\(.architecture)"] | join(",")' <<<"$raw"))"
      return 1
    fi
  done
  for child in ${EXPECT_CHILDREN:-}; do
    if ! jq -e --arg d "$child" '[.manifests[]? | select(.digest == $d)] | length > 0' <<<"$raw" >/dev/null; then
      echo "${ref}: index does not contain ${child}, which this run built"
      return 1
    fi
  done
  digest=$(digest_of "$ref")
  if [ -n "$want" ] && [ "$digest" != "$want" ]; then
    echo "${ref}: is ${digest}, expected ${want}"
    return 1
  fi
  return 0
}

# assert_once IMAGE TAG... -> 0 if every tag is right; prints ::error:: lines and returns 1 if not.
# Sets BAD_TAGS to the wrong ones and UNREAD to the number that could not be read at all.
assert_once() {
  local image="$1" want="${EXPECT_DIGEST:-}" tag reason crc rc=0
  shift
  BAD_TAGS=()
  UNREAD=0
  if [ -z "$want" ]; then
    want=$(digest_of "${image}:$1" 2>/dev/null || true)
  fi
  for tag in "$@"; do
    reason=$(check_tag "$image" "$tag" "$want") && crc=0 || crc=$?
    case "$crc" in
      0) echo "ok  ${image}:${tag} -> ${want} ($(echo "$PLATFORMS" | tr ' ' ','))" ;;
      2) echo "::warning::${reason}"; UNREAD=$((UNREAD + 1)); rc=1 ;;
      *) echo "::error::${reason}"; BAD_TAGS+=("$tag"); rc=1 ;;
    esac
  done
  return "$rc"
}

# heal IMAGE TAG... -> re-point each tag to EXPECT_DIGEST (an index already in the repository).
heal() {
  local image="$1" tag
  shift
  for tag in "$@"; do
    echo "::warning::re-pointing ${image}:${tag} to ${image}@${EXPECT_DIGEST}"
    docker buildx imagetools create -t "${image}:${tag}" "${image}@${EXPECT_DIGEST}"
  done
}

# assert_or_heal IMAGE TAG... -> exit-code semantics of the `assert` command.
assert_or_heal() {
  local image="$1"
  shift
  if assert_once "$image" "$@"; then
    return 0
  fi
  # Heal only what was read and found wrong; an unreadable registry is no reason to rewrite tags.
  if [ "${#BAD_TAGS[@]}" -eq 0 ] || [ "${HEAL:-0}" != 1 ] || [ -z "${EXPECT_DIGEST:-}" ]; then
    [ "${#BAD_TAGS[@]}" -eq 0 ] && [ "$UNREAD" -gt 0 ] && return 4
    return 1
  fi
  local healed=("${BAD_TAGS[@]}")
  heal "$image" "${healed[@]}"
  if assert_once "$image" "$@"; then
    echo "::error::healed ${healed[*]}: the tags are correct again, but something other than this workflow wrote them. Find that publisher and stop it."
    return 3
  fi
  echo "::error::re-pointing did not fix ${BAD_TAGS[*]}"
  return 1
}

cmd="${1:-}"
[ -n "$cmd" ] || die_usage
shift

case "$cmd" in
  assert)
    [ "$#" -ge 2 ] || die_usage
    assert_or_heal "$@"
    ;;
  watch)
    [ "$#" -ge 4 ] || die_usage
    image="$1" minutes="$2" interval="$3"
    shift 3
    deadline=$(($(date +%s) + minutes * 60))
    worst=0
    unread_rounds=0
    while :; do
      echo "== $(date -u +%H:%M:%S) =="
      assert_or_heal "$image" "$@" && rc=0 || rc=$?
      [ "$rc" -eq 4 ] && unread_rounds=$((unread_rounds + 1)) || unread_rounds=0
      case "$rc" in
        0) ;;
        3) worst=3 ;;
        # The registry could not be read this round (a 429, a blip): no verdict, try next round.
        # Three rounds in a row is not a blip, and a watch that saw nothing must not pass.
        4)
          if [ "$unread_rounds" -ge 3 ]; then
            echo "::error::registry unreadable for ${unread_rounds} rounds in a row; the tags were not watched"
            exit 1
          fi
          echo "::warning::registry unreadable this round; checking again in ${interval}s"
          ;;
        *) exit "$rc" ;;
      esac
      [ "$(date +%s)" -lt "$deadline" ] || break
      sleep "$interval"
    done
    exit "$worst"
    ;;
  *) die_usage ;;
esac
