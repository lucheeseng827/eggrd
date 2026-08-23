# Testing ACME issuance

`src/acme.rs` obtains certificates over ACME HTTP-01. It cannot be covered by the
ordinary suite — it needs a certificate authority to talk to and port 80 to bind
— so it lives behind `#[ignore]` and the two recipes below.

Both were run on **2026-08-24** and both pass. That is new: the test had existed
for months and had **never once passed**, for four separate reasons. They are all
written down in [Everything that was wrong](#everything-that-was-wrong), because
every one of them produced a misleading symptom, and a future reader hitting any
of them will otherwise conclude that `acme.rs` is broken when it is not.

---

## Recipe A — Pebble, on your machine

[Pebble](https://github.com/letsencrypt/pebble) is a small but real ACME CA. This
is the fast loop: about ten seconds, no cloud, no public DNS.

```sh
docker compose -f loadtest/pebble.compose.yaml up -d
```

Trust Pebble's **directory** certificate — see [Which Pebble root](#which-pebble-root),
this is not the obvious one:

```sh
curl -sL https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/pebble.minica.pem \
  | sudo tee /usr/local/share/ca-certificates/pebble.crt >/dev/null
sudo update-ca-certificates
```

Run it. `sudo` (or `CAP_NET_BIND_SERVICE`) is required because the HTTP-01
challenge server binds port 80, which RFC 8555 §8.3 fixes:

```sh
EDGEGUARD_TEST_ACME_DIR=https://localhost:14000/dir \
EDGEGUARD_TEST_ACME_DOMAIN=edgeguard.test \
sudo -E cargo test -p eggrd --lib acme_http01 -- --ignored
```

Expected:

```
test acme::tests::acme_http01_issues_against_pebble ... ok
```

### Running it in containers instead

If your host cannot spare port 80, run the test in a container on the same
network with a fixed address, and point `challtestsrv` at that address. This is
how the 2026-08-24 run was done:

```sh
podman network create acmenet --subnet 10.91.0.0/24
podman run -d --name cts --network acmenet --ip 10.91.0.10 \
  ghcr.io/letsencrypt/pebble-challtestsrv:latest \
  -defaultIPv4 10.91.0.20 -defaultIPv6 "" -dnsserver ":8053" -management ":8055"
podman run -d --name pebble --network acmenet --ip 10.91.0.11 -e PEBBLE_VA_NOSLEEP=1 \
  -v "$PWD/loadtest:/cfg" ghcr.io/letsencrypt/pebble:latest \
  -config /cfg/pebble-config.json -dnsserver 10.91.0.10:8053

# the test container takes 10.91.0.20 — the address challtestsrv hands out
podman run --rm --network acmenet --ip 10.91.0.20 \
  -v "$PWD:/repo" -w /repo --add-host "pebble:10.91.0.11" \
  -e EDGEGUARD_TEST_ACME_DIR=https://pebble:14000/dir \
  -e EDGEGUARD_TEST_ACME_DOMAIN=edgeguard.test \
  docker.io/library/rust:latest \
  sh -c 'cp /repo/pebble.minica.pem /usr/local/share/ca-certificates/pebble.crt \
         && update-ca-certificates >/dev/null \
         && cargo test -p eggrd --lib acme_http01 -- --ignored'
```

`--add-host pebble:...` matters: Pebble's certificate carries
`DNS:localhost, DNS:pebble, IP:127.0.0.1`, so it must be reached by one of those
names. An IP literal fails hostname verification.

---

## Recipe B — Let's Encrypt staging, on a public host

Pebble proves the protocol. Only a public CA proves the whole thing, because only
a public CA has to reach *your* port 80 from the internet. Use **staging**: it has
generous rate limits, and burning production limits to test a code path is a bad
trade.

You need a domain in a zone you control and a host with a public IP.

1. Launch a small instance with **inbound tcp/80 open** — that is all ACME needs.
2. Point an A record at it (`acme-test.<your-domain>`) and let it propagate.
3. Run eggrd with:

```toml
[tls]
enabled   = true
cert_path = "/tls/cert.pem"
key_path  = "/tls/key.pem"

[tls.acme]
enabled       = true
domains       = ["acme-test.example.com"]
email         = "ops@example.com"
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
cache_dir     = "/acme"
accept_tos    = true
```

The 2026-08-24 run issued in **five seconds**:

```
INFO edgeguard::acme: starting ACME order domains=["acme-test.eggrd.dev"]
     directory=https://acme-staging-v02.api.letsencrypt.org/directory
INFO edgeguard::acme: ACME certificate stored cert=/tls/cert.pem key=/tls/key.pem

subject = CN=acme-test.eggrd.dev
issuer  = C=US, O=Let's Encrypt, CN=(STAGING) Artificial Amaranth YE1
notAfter= Nov 21 16:18:44 2026 GMT
```

**Tear the host down afterwards.** It exists to answer one challenge.

### AWS Certificate Manager is not a route to this

Worth stating because it looks like one: **ACM will not export the private key of
a public certificate**, so an ACM certificate cannot be handed to eggrd's TLS
listener. ACM certificates only attach to AWS services that terminate TLS for you
(CloudFront, ALB). If you want eggrd to terminate TLS with an ACM certificate, put
CloudFront or an ALB in front and let eggrd speak plaintext behind it — which is a
different architecture, not this one.

---

## Everything that was wrong

In the order they surfaced. Each hid the next, which is why the test had never
passed and why nobody had noticed it *could* not pass.

### 1. The test never installed a rustls crypto provider

```
Could not automatically determine the process-level CryptoProvider
from Rustls crate features.
```

It panicked before a single line of ACME logic ran. `main.rs` calls
`tls::init_crypto()` immediately before the ACME block, so **the shipping binary
was always fine** — this was purely a test-harness gap. The test now calls it too.

Worth internalising: a test that has never been run is not a passing test, and
this one had been quietly not-run for long enough that its own recipe had rotted.

### 2. `instant-acme` 0.7 could not be pointed at a private CA

The old recipe said to `export SSL_CERT_FILE=/path/to/pebble.minica.pem`. That
cannot work. 0.7 pulled `hyper-rustls` with **`webpki-roots` compiled in**:

```
webpki-roots v1.0.9
└── hyper-rustls v0.27.9
    └── instant-acme v0.7.2
```

Compiled-in roots ignore `SSL_CERT_FILE` *and* the system trust store. Both were
tried; both still failed `invalid peer certificate: UnknownIssuer`. Under 0.7,
testing against any private CA was impossible by construction.

**0.8 verifies with `rustls-platform-verifier`** — the platform trust store — so
installing the root the normal way now works.

### 3. `instant-acme` 0.7 could not parse Let's Encrypt's response

This was the real, user-facing bug, and it was only ever going to surface against
a live CA:

```
Error: ACME certificate provisioning
Caused by:
    0: fetching authorizations
    1: failed to (de)serialize JSON: missing field `token` at line 34 column 5
```

The account was created and the order opened; it failed *reading the reply*. 0.7.2
dates from October 2024 and its authorization model requires `token` on every
challenge, which no longer matches what the CA returns. **Issuance was broken in
production, not merely untested.**

Fixed by the 0.7 → 0.8 bump. That is a breaking change: `NewOrder::new()`,
`authorizations()` as a stream, challenges marked ready through a handle, and
`poll_ready`/`poll_certificate` with a `RetryPolicy`. 0.8 also generates the key
and CSR inside `finalize()`, so rcgen is no longer used on this path.

### 4. The test rig had three bugs of its own

Each produced a symptom that pointed away from the real cause.

#### Which Pebble root

Pebble serves **two different roots** and they are not interchangeable:

| Source | Signs |
|---|---|
| `https://localhost:15000/roots/0` | the certificates Pebble **issues** |
| `test/certs/pebble.minica.pem` | Pebble's own **directory endpoint** TLS certificate |

Trusting `/roots/0` — the obvious choice, and the one tried first — still fails
with `UnknownIssuer`, which reads exactly like problem 2 above and sent the
investigation back down a dead end. You need the *minica* root.

#### The challtestsrv flag does not exist

`loadtest/pebble.compose.yaml` said `-dns01 ":8053"`. There is no such flag; it is
`-dnsserver`. The container exits with status 2 printing usage, and the failure
arrives much later, from the CA, as:

```
dial tcp 10.91.0.10:8053: i/o timeout
```

An opaque timeout from the certificate authority, whose actual cause was a dead
container in the test rig.

#### IPv6 wins, and points nowhere

`challtestsrv` answers AAAA with `::1` unless told otherwise. Pebble prefers IPv6,
so validation dialled `[::1]:80` and was refused — while the A record was
completely correct and `dig` looked perfect:

```
API error: Get "http://edgeguard.test:80/.well-known/acme-challenge/..."
           dial tcp [::1]:80: connect: connection refused
```

`-defaultIPv6 ""` is required. Also set Pebble's `httpPort` to **80** (default is
5002) so it validates where the challenge server actually listens —
`loadtest/pebble-config.json` does this.

### 5. Cloud-host mistakes, for Recipe B

Not eggrd's fault, but they cost three instance launches:

- **IMDSv2.** Amazon Linux 2023 rejects an untokened metadata request with 401, so
  a naive `curl .../public-ipv4` returns empty. The script then compared DNS
  against an empty string and waited forever. Get a token first.
- **The image runs as non-root.** Mounting a root-owned volume gives
  `Permission denied` on `/acme/account.json`, and — more seriously — a non-root
  process cannot bind port 80 at all. `--user 0:0` plus a writable directory.
- **glibc.** A binary built in `rust:latest` (Debian) will not run on AL2023:
  `/lib64/libc.so.6: version 'GLIBC_2.38' not found`. Ship the container image
  instead; the Dockerfile already builds a static musl binary.
- **`set -x` into `/dev/console`** overflows the 64 KB console buffer, and console
  output is the only way to see anything on a host with no SSH key and no SSM
  role. Log deliberately and sparingly.

---

## Why it works now

Two of the four were fixed by one dependency bump — 0.8 both parses the CA's
current payload and verifies against the platform trust store. The other two were
the test harness: a missing crypto provider, and a compose file with three wrong
flags.

None of them were bugs in `acme.rs`. That code was correct the whole time and had
simply never been allowed to run.

## When to re-run this

- Any change to `src/acme.rs`.
- Any bump of `instant-acme` — issue 3 is exactly what a stale ACME client looks
  like, and it is invisible until a real CA is involved.
- Before claiming ACME works in any public material. Recipe A is ten seconds and
  catches protocol regressions; Recipe B is the one that proves it end to end.
