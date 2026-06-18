#!/bin/bash
# Bootstrap the PROXY host: Docker engine + compose plugin. The harness builds EdgeGuard from the
# crate in-image, so only Docker is needed (no Rust toolchain on the host).
set -eux
dnf install -y docker
systemctl enable --now docker
usermod -aG docker ec2-user
mkdir -p /usr/libexec/docker/cli-plugins
COMPOSE_VERSION="v2.29.7"
arch="$(uname -m)"
case "$arch" in
  x86_64) compose_asset="docker-compose-linux-x86_64" ;;
  aarch64|arm64) compose_asset="docker-compose-linux-aarch64" ;;
  *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
esac
compose_base_url="https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}"
curl -fsSL "${compose_base_url}/${compose_asset}" \
  -o /usr/libexec/docker/cli-plugins/docker-compose
# Verify the binary against the release checksums before trusting it.
curl -fsSL "${compose_base_url}/checksums.txt" -o /tmp/compose-checksums.txt
grep " ${compose_asset}\$" /tmp/compose-checksums.txt | sha256sum -c -
rm -f /tmp/compose-checksums.txt
chmod +x /usr/libexec/docker/cli-plugins/docker-compose
# Readiness marker the orchestrator polls over SSH before copying code.
echo ok > /home/ec2-user/PROXY_READY
