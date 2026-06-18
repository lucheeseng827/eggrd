# Release image for EdgeGuard: a static musl binary on distroless — tiny, no shell, CA roots
# included. Published multi-arch (amd64 + arm64) as `mancube/eggrd` (Docker Hub).
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t mancube/eggrd:latest --push .
#   docker run -p 8080:8080 -e UPSTREAM=http://app:3000 mancube/eggrd:latest --config /etc/edgeguard/edgeguard.toml
#
# The binary lands at /usr/local/bin/edgeguard so the wrap-your-app templates in examples/ can
# `COPY --from=mancube/eggrd:latest /usr/local/bin/edgeguard ...`.

FROM rust:alpine AS build
ARG TARGETARCH
# ring (rustls crypto provider) compiles C/asm — needs a musl C toolchain.
RUN apk add --no-cache musl-dev build-base
WORKDIR /src
COPY . .
# Map TARGETARCH (injected by docker buildx) → Rust musl triple; stage binary at a fixed path.
RUN case "${TARGETARCH}" in \
      arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
      *)     RUST_TARGET=x86_64-unknown-linux-musl ;; \
    esac && \
    rustup target add "${RUST_TARGET}" && \
    cargo build --release --bin edgeguard --target "${RUST_TARGET}" && \
    cp "/src/target/${RUST_TARGET}/release/edgeguard" /edgeguard

# distroless/static: ~2 MB, no shell, runs as nonroot, ships CA roots — ideal for a static binary.
# Digest pinned for reproducibility; refresh with: docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot
FROM gcr.io/distroless/static-debian12:nonroot@sha256:cdf4daaf154e3e27cfffc799c16f343a384228f38646928a1513d925f473cb46
COPY --from=build /edgeguard /usr/local/bin/edgeguard
COPY --from=build /src/edgeguard.toml /etc/edgeguard/edgeguard.toml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/edgeguard"]
