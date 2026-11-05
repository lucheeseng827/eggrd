#!/usr/bin/env bash
# mkpki.sh <dir>: a throwaway test PKI for the smoke tests and workshop labs, made with OpenSSL in
# a container (no OpenSSL needed on the host). TEST ONLY: the keys are world-readable so a
# container running as any uid can read them, and nothing here is ever committed.
#
#   ca.pem / ca.key              "Example Test CA": signs servers and clients
#   server.pem / server.key      app.example.test, edge, localhost, 127.0.0.1   (serverAuth)
#   upstream-*.pem / .key        onprem-a, onprem-b, cloud .example.internal    (serverAuth)
#   client-a.pem / .key          CN client-a, URI spiffe://example.test/ns/web/client-a (clientAuth)
#   client-b.pem / .key          CN client-b, URI spiffe://example.test/ns/web/client-b (revoked)
#   edge-client.pem / .key       CN edge, the edge's own identity to upstreams        (clientAuth)
#   crl.pem                      the CA's CRL: client-b revoked, next update in 7 days
#   lb-ca.pem / lb-ca.key        "Example Balancer CA": a CA that issues only the balancer's cert
#   lb.pem / lb.key              DNS lb.example.internal, signed by lb-ca          (clientAuth)
#   other-ca.pem, rogue.pem/.key a CA nobody trusts, and a client cert it signed
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/smoke-lib.sh"
out="${1:?usage: $0 <dir>}"
mkdir -p "$out"
"$(engine)" run --rm -i --entrypoint sh -v "$(hostpath "$out"):/pki" docker.io/alpine/openssl:3.3.2 -s <<'EOF'
set -e
cd /pki
cat > ext.cnf <<'X'
[server]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
[client]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
X
ca() { # name cn
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=$2" \
    -keyout "$1.key" -out "$1.pem" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}
leaf() { # name cn ca ext san
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$2" -keyout "$1.key" -out "$1.csr" 2>/dev/null
  printf '[%s]\n' "$4" > "$1.ext"; sed -n "/^\[$4\]/,/^\[/p" ext.cnf | sed '1d;/^\[/d' >> "$1.ext"
  [ -n "$5" ] && echo "subjectAltName = $5" >> "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -days 30 \
    -extfile "$1.ext" -extensions "$4" -out "$1.pem" 2>/dev/null
  rm -f "$1.csr" "$1.ext"
}
ca ca "Example Test CA"
ca lb-ca "Example Balancer CA"
ca other-ca "Untrusted Other CA"
leaf server app.example.test ca server "DNS:app.example.test,DNS:edge,DNS:localhost,IP:127.0.0.1"
for u in onprem-a onprem-b cloud; do leaf "upstream-$u" "$u.example.internal" ca server "DNS:$u.example.internal"; done
leaf client-a client-a ca client "URI:spiffe://example.test/ns/web/client-a"
leaf client-b client-b ca client "URI:spiffe://example.test/ns/web/client-b"
leaf edge-client edge ca client "DNS:edge.example.internal"
leaf lb lb.example.internal lb-ca client "DNS:lb.example.internal"
leaf rogue rogue other-ca client "URI:spiffe://example.test/ns/web/rogue"
# CRL: client-b revoked.
mkdir -p db && : > db/index.txt && echo 1000 > db/crlnumber
cat > ca.cnf <<'X'
[ca]
default_ca = d
[d]
database = /pki/db/index.txt
crlnumber = /pki/db/crlnumber
default_md = sha256
default_crl_days = 7
X
openssl ca -config ca.cnf -cert ca.pem -keyfile ca.key -revoke client-b.pem 2>/dev/null
openssl ca -config ca.cnf -cert ca.pem -keyfile ca.key -gencrl -out crl.pem 2>/dev/null
rm -rf db ca.cnf ext.cnf *.srl
chmod 0644 ./*
ls
EOF
