#!/bin/sh
# A throwaway PKI and key file at the paths the docs' TOML blocks name, so `edgeguard doctor` can
# load each block (it refuses a CA bundle, CRL or key it cannot read). Test material only: every key
# here is generated on the spot and worthless.
#
#   sh make-test-pki.sh <dir>     # writes <dir>/pki/*, <dir>/state/{cert,key}.pem, <dir>/api-keys
#
# Mount <dir>/pki at /etc/edgeguard/pki and <dir>/state at /var/lib/edgeguard, and set
# EDGEGUARD_API_KEYS_FILE=<dir>/api-keys (the API-key blocks expect keys from that file).
set -eu
D="${1:?usage: $0 <dir>}"
mkdir -p "$D"
D="$(cd "$D" && pwd)" # absolute, so the paths below stay valid after the cd
P="$D/pki"; S="$D/state"
mkdir -p "$P" "$S/acme"
cd "$P"
# Every certificate is X.509 v3 with explicit extensions: rustls refuses a v1 certificate
# (UnsupportedCertVersion), and whether `openssl req -x509` or `openssl x509 -req` add extensions on
# their own depends on the openssl version and its config (Ubuntu 24.04's 3.0 signs a CSR as v1).
ec() { openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 "$@" 2>/dev/null; }
ca() {
  ec -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -addext subjectKeyIdentifier=hash "$@"
}
ca -subj /CN=test-clients-ca -keyout clients-ca.key -out clients-ca.pem
printf '[ ca ]\ndefault_ca = t\n[ t ]\ndatabase = %s/index.txt\ncrlnumber = %s/crlnumber\ndefault_md = sha256\ndefault_crl_days = 7\n' "$P" "$P" > ca.cnf
: > index.txt
echo 01 > crlnumber
openssl ca -config ca.cnf -gencrl -keyfile clients-ca.key -cert clients-ca.pem -out clients-ca.crl.pem 2>/dev/null
ca -subj /CN=test-upstream-ca -keyout upstream-ca.key -out upstream-ca.pem
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=edge-client \
  -keyout edge-client.key -out edge-client.csr 2>/dev/null
printf '%s\n' 'basicConstraints = critical, CA:FALSE' 'keyUsage = critical, digitalSignature' \
  'extendedKeyUsage = clientAuth' 'subjectKeyIdentifier = hash' 'authorityKeyIdentifier = keyid' > edge-client.ext
openssl x509 -req -in edge-client.csr -CA upstream-ca.pem -CAkey upstream-ca.key -CAcreateserial \
  -days 30 -extfile edge-client.ext -out edge-client.pem 2>/dev/null
ec -subj /CN=app.example.com -addext subjectAltName=DNS:app.example.com \
  -addext basicConstraints=critical,CA:FALSE -addext keyUsage=critical,digitalSignature \
  -addext extendedKeyUsage=serverAuth -keyout "$S/key.pem" -out "$S/cert.pem"
# Fail here, not later in doctor, if any certificate came out below v3.
for c in clients-ca.pem upstream-ca.pem edge-client.pem "$S/cert.pem"; do
  openssl x509 -in "$c" -noout -text | grep -q 'Version: 3 ' || { echo "$c is not X.509 v3" >&2; exit 1; }
done
echo "example-key-0001" > "$D/api-keys"
chmod -R a+rX "$D"
echo "test PKI in $D"
