#!/usr/bin/env bash
# Smoke test for the aws-alb reference.
#   1. Validate: doctor on every config, kubeconform on both overlays, terraform validate on the
#      CloudFront lock. No ALB, CloudFront or GCP load balancer is created.
#   2. Run eggrd's side locally, with nginx standing in for the balancers (sim/): an ALB in append
#      mode (forwarded_hops = 1), CloudFront -> ALB (2), ALB mTLS passthrough, and a balancer
#      trusted by its certificate (trusted_proxy_names).
# Docker or Podman; kubectl for kubeconform. KEEP=1 leaves the containers up.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../tools/smoke-lib.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="$(engine)"
NET=egref-alb SUBNET=10.231.78.0/24 ALB_IP=10.231.78.10 CF_IP=10.231.78.11 CLIENT_IP=10.231.78.20
HOST=app.example.test
CONTAINERS=(egref-alb-cf egref-alb-alb egref-alb-e1 egref-alb-e2 egref-alb-e4 egref-alb-e5 egref-alb-app)

WORK="$(mktemp -d)"
cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then note "KEEP=1: containers egref-alb-* left up"; return; fi
  "$E" rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
  "$E" network rm "$NET" >/dev/null 2>&1 || true
  # The Terraform container writes $WORK/tf as root; remove that as root or rm -rf fails here.
  "$E" run --rm -v "$(hostpath "$WORK"):/w" --entrypoint sh docker.io/alpine/openssl:3.3.2 -c 'rm -rf /w/tf' >/dev/null 2>&1 || true
  rm -rf "$WORK" || true
}
trap cleanup EXIT

step "test PKI (throwaway, never committed)"
"$REF_DIR/tools/mkpki.sh" "$WORK/pki" >/dev/null && pass "made $WORK/pki"
DOCTOR_ARGS=(-v "$(hostpath "$WORK/pki"):/etc/eggrd/pki:ro")

step "validate"
doctor "$HERE/append"
doctor "$HERE/mtls-passthrough"
doctor "$HERE/configs" cloudfront-alb.toml
doctor "$HERE/configs" gcp-alb.toml
doctor "$HERE/configs" trusted-proxy-names.toml
if command -v kubectl >/dev/null; then
  for d in append mtls-passthrough; do
    "$REF_DIR/tools/kubeconform.sh" "$HERE/$d" && pass "kubeconform: $d" || fail "kubeconform: $d"
  done
else note "no kubectl: skipped kubeconform"; fi
mkdir -p "$WORK/tf" && cp "$HERE/cloudfront-lock/main.tf" "$WORK/tf/"
TF=("$E" run --rm -v "$(hostpath "$WORK/tf"):/w" -w /w docker.io/hashicorp/terraform:1.9.8)
if "${TF[@]}" init -backend=false -input=false >/dev/null 2>&1 && "${TF[@]}" validate >/dev/null 2>&1 \
   && "${TF[@]}" fmt -check >/dev/null 2>&1; then pass "terraform validate + fmt: cloudfront-lock"
else fail "terraform validate: cloudfront-lock"; fi

step "run: nginx as the ALB / CloudFront, four edges"
# Each config as shipped, with test-only changes: a self-signed certificate in place of the
# eggrd-tls Secret, and the stand-in ALB's address as the trusted one.
prep() { # src name
  mkdir -p "$WORK/$2"
  sed -e 's#^cert_path = "/etc/eggrd-tls/tls.crt"#self_signed = true\ncert_path = "/tmp/tls.crt"#' \
      -e 's#^key_path = "/etc/eggrd-tls/tls.key"#key_path = "/tmp/tls.key"#' \
      -e "s#^trusted_proxies = .*#trusted_proxies = [\"$ALB_IP/32\"]#" "$1" > "$WORK/$2/edgeguard.toml"
}
prep "$HERE/append/edgeguard.toml" e1
prep "$HERE/configs/cloudfront-alb.toml" e2
prep "$HERE/mtls-passthrough/edgeguard.toml" e4
prep "$HERE/configs/trusted-proxy-names.toml" e5
"$E" rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
"$E" network rm "$NET" >/dev/null 2>&1 || true
"$E" network create --subnet "$SUBNET" "$NET" >/dev/null
"$E" run -d --name egref-alb-app --network "$NET" --network-alias whoami.eggrd-app.svc.cluster.local \
  --read-only --cap-drop ALL --user 65532:65532 docker.io/traefik/whoami:v1.10.3 --port 8000 >/dev/null
for e in e1 e2 e4 e5; do
  "$E" run -d --name "egref-alb-$e" --network "$NET" --network-alias "$e" --read-only --tmpfs /tmp \
    --user 65532:65532 --cap-drop ALL --cap-add NET_BIND_SERVICE \
    -v "$(hostpath "$WORK/$e"):/etc/eggrd:ro" -v "$(hostpath "$WORK/pki"):/etc/eggrd/pki:ro" \
    "$EGGRD_IMAGE" --config /etc/eggrd/edgeguard.toml >/dev/null
done
sleep 3
"$E" run -d --name egref-alb-alb --network "$NET" --ip "$ALB_IP" --network-alias alb \
  -v "$(hostpath "$HERE/sim/alb.conf"):/etc/nginx/nginx.conf:ro" -v "$(hostpath "$WORK/pki"):/pki:ro" \
  docker.io/library/nginx:1.27-alpine >/dev/null
"$E" run -d --name egref-alb-cf --network "$NET" --ip "$CF_IP" \
  -v "$(hostpath "$HERE/sim/cf.conf"):/etc/nginx/nginx.conf:ro" docker.io/library/nginx:1.27-alpine >/dev/null
sleep 3

# client <curl args...>: curl from a container at CLIENT_IP, PKI at /pki. Prints body, then code.
client() { "$E" run --rm --network "$NET" --ip "$CLIENT_IP" -v "$(hostpath "$WORK/pki"):/pki:ro" \
  docker.io/curlimages/curl:8.11.1 -sk -H "Host: $HOST" -w '\ncode=%{http_code}' "$@" 2>/dev/null || true; }
xff() { printf '%s' "$1" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-forwarded-for" {print $2}'; }
codeof() { printf '%s' "$1" | tail -1 | sed 's/^code=//'; }

step "ALB append mode, forwarded_hops = 1"
R="$(client -H 'X-Forwarded-For: 198.51.100.7' http://alb:8001/)"
check "via the ALB" 200 "$(codeof "$R")"
check "the client's own X-Forwarded-For entry is ignored: the app sees the address the ALB appended" "$CLIENT_IP" "$(xff "$R")"
R="$(client -H 'X-Forwarded-For: 198.51.100.7' https://e1:443/)"
check "BYPASSING the ALB, the client chooses its address (why only the ALB may reach eggrd)" "198.51.100.7" "$(xff "$R")"

step "CloudFront -> ALB, forwarded_hops = 2"
R="$(client -H 'X-Forwarded-For: 198.51.100.7' http://10.231.78.11:8000/)"
check "via CloudFront and the ALB" 200 "$(codeof "$R")"
check "the client is 2 from the right (CloudFront's entry)" "$CLIENT_IP" "$(xff "$R")"
R="$(client -H 'X-Forwarded-For: 198.51.100.7' http://alb:8002/)"
check "straight to the ALB, skipping CloudFront: the client's entry is believed (why the ALB must accept only CloudFront)" "198.51.100.7" "$(xff "$R")"

step "ALB mTLS passthrough ([trusted_client_cert_header], ca_path, CRL)"
R="$(client --cert /pki/client-a.pem --key /pki/client-a.key https://alb:8443/)"
check "client-a's certificate -> 200" 200 "$(codeof "$R")"
check_has "the app gets X-Forwarded-Client-Cert with the SPIFFE ID" 'URI="spiffe://example.test/ns/web/client-a"' "$R"
check_lacks "the certificate header itself is removed before the app" "X-Amzn-Mtls-Clientcert" "$R"
check "no certificate -> 401" 401 "$(codeof "$(client https://alb:8443/)")"
check "client-b, revoked in the CRL -> 401" 401 "$(codeof "$(client --cert /pki/client-b.pem --key /pki/client-b.key https://alb:8443/)")"
check "a certificate from another CA -> 401" 401 "$(codeof "$(client --cert /pki/rogue.pem --key /pki/rogue.key https://alb:8443/)")"
PEM="$("$E" run --rm -v "$(hostpath "$WORK/pki"):/pki:ro" --entrypoint sh docker.io/alpine/openssl:3.3.2 -c 'cat /pki/client-a.pem' | tr -d '\r' | sed 's/ /%20/g' | awk '{printf "%s%%0A", $0}')"
check "the header forged by a client connecting directly (not the ALB) -> 401" 401 "$(codeof "$(client -H "X-Amzn-Mtls-Clientcert: $PEM" https://e4:443/)")"
M="$("$E" run --rm --network "$NET" docker.io/curlimages/curl:8.11.1 -s http://e4:9090/__edgeguard/metrics 2>/dev/null || true)"
check_has "counted untrusted_peer" 'edgeguard_client_cert_header_total{result="untrusted_peer"}' "$M"

step "a balancer trusted by its certificate (trusted_proxy_names)"
R="$(client --cert /pki/client-a.pem --key /pki/client-a.key https://alb:8444/)"
check "client-a through the balancer (which presents lb.example.internal) -> 200" 200 "$(codeof "$R")"
check_has "the principal is the client's certificate, not the balancer's" 'spiffe://example.test/ns/web/client-a' "$R"
check "client-b (revoked) through the balancer -> 401" 401 "$(codeof "$(client --cert /pki/client-b.pem --key /pki/client-b.key https://alb:8444/)")"
check "the header forged directly, without the balancer's certificate -> 401" 401 "$(codeof "$(client -H "X-Client-Cert: $PEM" https://e5:443/)")"
check "client-a presenting its own certificate directly: the balancer-only CA refuses the handshake" 000 "$(codeof "$(client --cert /pki/client-a.pem --key /pki/client-a.key https://e5:443/)")"

summary
