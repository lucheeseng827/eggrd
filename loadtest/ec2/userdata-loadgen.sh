#!/bin/bash
# Bootstrap the LOAD-GENERATOR host: native k6 (no container, so the generator isn't itself
# paying container/network overhead). Raise the open-file / port limits so one k6 host can sustain
# tens of thousands of concurrent short-lived connections.
set -eux
K6_VER=v0.53.0
curl -fsSL "https://github.com/grafana/k6/releases/download/${K6_VER}/k6-${K6_VER}-linux-amd64.tar.gz" \
  -o /tmp/k6.tgz
tar -xzf /tmp/k6.tgz -C /tmp
install -m 0755 "/tmp/k6-${K6_VER}-linux-amd64/k6" /usr/local/bin/k6

# Kernel/ulimit headroom for a high-RPS arrival-rate generator.
cat >/etc/sysctl.d/99-k6.conf <<'EOF'
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = 65535
EOF
if ! sysctl --system; then
  echo "Failed to apply sysctl tuning for load generator" >&2
  exit 1
fi
cat >/etc/security/limits.d/99-k6.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
EOF
echo ok > /home/ec2-user/LOADGEN_READY
