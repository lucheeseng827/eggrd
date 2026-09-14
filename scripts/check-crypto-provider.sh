#!/usr/bin/env bash
# Fail if the aws-lc crypto stack re-enters the dependency graph.
#
#     ./scripts/check-crypto-provider.sh
#
# This crate links exactly ONE rustls crypto provider: ring. That is not a preference, it is
# load-bearing in two ways, both of which regress silently:
#
#   * aws-lc-sys is a cmake/bindgen C build — the only one in the graph, and by a wide margin
#     its most expensive crate in both compile time and binary size. It is also the piece most
#     likely to break on a new toolchain or a musl/cross target, which is what the
#     single-static-binary and distroless claims rest on.
#   * With two providers linked, `rustls::ClientConfig::builder()` PANICS unless a process
#     default was installed first. `tls::init_crypto()` installs one, but only runs under
#     `[tls] enabled`, so `ratelimit.store = "redis"` over `rediss://` with TLS termination off
#     used to abort the process on the first rate-limited request. See the rustls entry in
#     Cargo.toml for the full derivation.
#
# Neither shows up as a test failure. A `cargo update`, a new dependency, or a point release
# that flips a default feature anywhere in rustls / tokio-rustls / instant-acme / hyper-rustls /
# rcgen can put aws-lc back, and the lockfile hides rather than prevents it: the monorepo's
# workspace lock is ~26k lines, so the handful of changed edges is not something a reviewer
# spots. The crate also ships without a lock of its own (the OSS cut regenerates one), so there
# the resolve is genuinely fresh every time. Hence a graph check rather than a code check.

# Note this reads `cargo tree` (feature-resolved) and not Cargo.lock. The lock keeps entries for
# optional dependencies that no enabled feature activates — aws-lc-rs still appears there under
# rustls-webpki — so grepping it would report a regression that is not one.
#
# Both aws-lc-rs and aws-lc-sys are matched: aws-lc-rs is what makes the provider ambiguous,
# and aws-lc-sys is the C build. rcgen can pull aws-lc-rs without touching rustls's features,
# so neither name implies the other.
set -euo pipefail

cd "$(dirname "$0")/.."

# `cargo tree -i <pkg>` exits 101 both when the package is absent AND on any other cargo error,
# so a broken resolve would read as "clean". Match on real output instead, and let a cargo
# failure fail the script (set -e) rather than pass it.
tree="$(cargo tree -e normal --prefix none)"

# `(*)` marks a subtree cargo already printed elsewhere; strip it so a package that appears
# twice in the tree is reported once.
if hits="$(grep -E '^aws-lc-(sys|rs) ' <<<"$tree" | sed 's/ (\*)$//' | sort -u)"; then
    echo "ERROR: the aws-lc crypto stack is back in the dependency graph:" >&2
    echo "$hits" | sed 's/^/  /' >&2
    echo >&2
    echo "Who pulled it in:" >&2
    cargo tree -i aws-lc-rs -e normal 2>/dev/null | sed 's/^/  /' >&2 || true
    echo >&2
    echo "Fix the offending dependency's features (default-features = false + an explicit" >&2
    echo "ring path), don't delete this check — see the rustls entry in Cargo.toml." >&2
    exit 1
fi

echo "ok: no aws-lc in the dependency graph (ring is the only crypto provider)"
