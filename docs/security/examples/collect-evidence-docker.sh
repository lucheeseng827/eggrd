#!/bin/sh
# Collect evidence from a Docker host that runs eggrd, before anything is changed.
# Tested with Docker 28 (docker:dind) against mancube/eggrd:0.7.0. See ../INCIDENT-RESPONSE.md.
#
#   sudo ./collect-evidence-docker.sh <container> [since]
#   sudo ADMIN=http://127.0.0.1:9090 TLS_NAME=app.example.com ./collect-evidence-docker.sh eggrd 72h
#
# Read-only toward the edge: it stops, restarts and edits nothing. It copies the container's
# metadata, its log, its mounts (config, certificate, key, ACME account), the admin endpoints and
# the certificate it serves into one directory, hashes every file, and tars the lot.
# The unpacked directory is removed once the .tgz is written and its hash verifies (it holds the
# same secrets); KEEP_UNPACKED=1 keeps it and says so.
#
# THE BUNDLE HOLDS SECRETS: the TLS private key, the ACME account key, API keys or a JWT secret
# if they are in the config. It is written 0600/0700; move it to evidence storage and encrypt it
# (age -r <recipient> or gpg -e) before it leaves the host.
set -eu

C="${1:?usage: $0 <container> [since, default 72h]}"
SINCE="${2:-72h}"
ADMIN="${ADMIN:-http://127.0.0.1:9090}"   # the admin listener as the host reaches it
TLS_NAME="${TLS_NAME:-}"                  # the public name, to record the served certificate
TLS_ADDR="${TLS_ADDR:-127.0.0.1:443}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
E="${OUT:-/var/tmp}/eggrd-ir-$(hostname)-$TS"

umask 077
mkdir -p "$E"
note() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$E/collection.log"; }
note "collector=$(id -un) host=$(hostname) container=$C since=$SINCE"

# Clock first: every later timestamp is judged against it.
{ date -u +%Y-%m-%dT%H:%M:%S.%NZ; timedatectl 2>/dev/null || true; chronyc tracking 2>/dev/null || true; } > "$E/clock.txt"

docker inspect "$C" > "$E/container-inspect.json"
IMG=$(docker inspect --format '{{.Image}}' "$C")
docker image inspect "$IMG" > "$E/image-inspect.json"
# The registry digest(s) the image was pulled by. Empty when it was loaded or built locally.
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$IMG" > "$E/image-repodigests.txt"
note "image id $IMG; repo digests: $(tr '\n' ' ' < "$E/image-repodigests.txt")"

docker logs --timestamps --since "$SINCE" "$C" > "$E/eggrd-stdout.log" 2> "$E/eggrd-stderr.log" || note "docker logs failed (log driver without read support?)"
# The json-file driver's own files, byte for byte (rotated ones too), when that driver is in use.
LP=$(docker inspect --format '{{.LogPath}}' "$C")
if [ -n "$LP" ] && [ -f "$LP" ]; then cp -p "$LP"* "$E/" && note "copied $LP*"; fi
docker events --since "$SINCE" --until "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --filter "container=$C" > "$E/docker-events.txt" || true
docker top "$C" > "$E/processes.txt" || true
docker diff "$C" > "$E/filesystem-diff.txt" || true
docker port "$C" > "$E/ports.txt" || true
for n in $(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$C"); do
  docker network inspect "$n" > "$E/network-$n.json" || true
done

# Every mount as the container sees it: the config directory, the state (certificate, key, ACME
# account). `docker cp` needs no shell in the container, so it works on the distroless image.
for m in $(docker inspect --format '{{range .Mounts}}{{.Destination}} {{end}}' "$C"); do
  name=$(printf '%s' "$m" | tr '/' '_')
  if docker cp "$C:$m" - > "$E/mount$name.tar" 2> "$E/mount$name.err" && [ -s "$E/mount$name.tar" ]; then
    note "copied mount $m"; rm -f "$E/mount$name.err"
  else
    note "FAILED to copy mount $m: $(tr '\n' ' ' < "$E/mount$name.err") (copy it from the host path in container-inspect.json)"
  fi
done

# The edge's own view of itself (the admin listener: keep it on loopback or a private network).
for p in metrics tls upstreams ready; do
  curl -s -m 5 -o "$E/admin-$p.txt" -w "%{http_code}\n" "$ADMIN/__edgeguard/$p" > "$E/admin-$p.status" || true
done

# The certificate on the wire, and the one on disk.
if [ -n "$TLS_NAME" ] && command -v openssl >/dev/null; then
  openssl s_client -connect "$TLS_ADDR" -servername "$TLS_NAME" </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -serial -dates -fingerprint -sha256 > "$E/served-cert.txt" || true
fi

# Host context: who listens, the firewall, the daemon's view.
{ ss -tlnpu 2>/dev/null || netstat -tlnpu 2>/dev/null || true; } > "$E/host-listeners.txt"
{ iptables-save 2>/dev/null || nft list ruleset 2>/dev/null || true; } > "$E/host-firewall.txt"
docker info > "$E/docker-info.txt" 2>&1 || true

note "collection done; hashing"
(cd "$E" && sha256sum -- * > SHA256SUMS)
tar -C "$(dirname "$E")" -czf "$E.tgz" "$(basename "$E")"
# Relative name in the .sha256, so `sha256sum -c` works wherever the pair is moved.
(cd "$(dirname "$E")" && sha256sum "$(basename "$E").tgz" | tee "$(basename "$E").tgz.sha256")
echo "bundle $E.tgz: record the sha256 above in the chain-of-custody log"
# The unpacked copy holds the same secrets as the bundle: remove it once the bundle is written and
# its hash verifies. KEEP_UNPACKED=1 keeps it, and says so.
if [ "${KEEP_UNPACKED:-0}" = 1 ]; then
  echo "unpacked copy kept at $E (it contains keys): remove it once the .tgz is in evidence storage" >&2
elif tar -tzf "$E.tgz" > /dev/null && (cd "$(dirname "$E")" && sha256sum -c "$(basename "$E").tgz.sha256" > /dev/null); then
  rm -rf -- "$E"
else
  echo "the bundle does not read back or its hash does not verify: unpacked copy kept at $E (it contains keys)" >&2
fi
