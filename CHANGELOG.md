# Changelog

All notable changes to EdgeGuard are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] — 2026-09-14

Three new hardening defaults, so this is a minor release per `docs/RELEASE.md`'s versioning
policy, not a patch. Two ship new capability that stays off until configured (self-signed TLS,
the `:80` redirect listener) — the third changes what a running deployment already does:
**`[log] query` now defaults to `redact`.** A deployment that scrapes access logs expecting the
full query string — a dashboard keyed on a `?campaign=` value, a SIEM rule matching on
`?session=` — will see `<redacted>` there after upgrading. Set `[log] query = "full"` to keep the
previous verbatim behaviour; nothing else about the request, routing or the upstream changes.

### Added
- **HTTPS works without first obtaining a certificate, and plaintext traffic is upgraded rather
  than dropped.** These were the two remaining places where "secure by default" required the
  operator to already know something. `tls.enabled = true` used to be a promise you could not
  keep until you had a PEM pair in hand, and even once TLS was up, nothing listened on `:80` — so
  a visitor typing a bare hostname got a connection error, and an app still bound there answered
  in the clear. The proxy was hardening a door people were walking past.

  - `[tls] self_signed = true` generates a certificate at `cert_path`/`key_path` when none is
    there yet, then serves it. The key is written `0600` — a private key that lands
    world-readable is a worse outcome than the missing certificate it fixes. Generation is
    skipped once the files exist, so a restart does not hand every client a new identity, and
    ACME still wins when both are configured: `self_signed` is a floor ("never fail to start for
    want of a certificate"), not a ceiling. `self_signed_hosts` sets the SANs (empty means
    `localhost`/`127.0.0.1`/`::1`), with IP literals becoming IP SANs rather than DNS names,
    because that is what clients actually match an address against.

    **What it buys is stated plainly, in the docs and by `doctor`.** It encrypts the connection —
    which is what makes HSTS, `Secure` cookies and the hardening headers mean anything at all —
    and it proves no identity, so browsers warn and strict clients refuse. Right for localhost, a
    private network, a sidecar hop or staging; wrong for a public domain, where `[tls.acme]` is
    the answer. Selling it as more than that would be the same overstatement the Status table in
    the README exists to prevent.

  - `edgeguard cert [--host h]... [--days n] [--cert-out p] [--key-out p] [--force]` writes the
    same pair as a standalone utility — no config file, no listener — for a Docker build stage or
    a compose init step. It refuses to overwrite without `--force`: replacing a certificate is
    not recoverable, since the previous key is gone and anything that trusted it breaks.

  - `[tls] redirect_port` (also `REDIRECT_PORT`) runs a small plaintext listener that redirects to
    HTTPS. The default status is **308, not 301**, so a `POST` that lands on the plaintext port is
    replayed over TLS instead of being silently downgraded to a `GET`. The TLS port is carried
    into the `Location`, so a proxy on `:8443` redirects there rather than to a `:443` nothing is
    listening on.

    **It does not ship the hole it exists to close.** The `Host` header is attacker-controlled, and
    a redirect listener that reflects it unchecked is an open redirect wearing the site's own
    name. A malformed host — spaces, CR/LF, userinfo, an over-long name — is answered `400`
    rather than reflected, and `redirect_hosts` pins redirects to an allow-list.
    `/.well-known/acme-challenge/` is answered `404` and never redirected: a CA must read the
    HTTP-01 token in plaintext, and bouncing it to the port whose certificate is being issued
    would deadlock the order. With ACME enabled, issuance runs first and the redirect listener
    binds afterwards, so the two never contend for `:80`.

  - `doctor` gained the checks that make the above discoverable rather than documented: TLS on
    with no certificate source at all is an **error** (it will not start), `self_signed` warns
    that it is not publicly trusted, a `redirect_port` colliding with `server.port` or
    `admin_port` is an error, a non-3xx `redirect_status` is an error, and `redirect_port = 0`
    is called out because TLS that nothing redirects to is the most common way it gets bypassed.
    It also now flags **`headers.hsts = true` with `tls.enabled = false`** — the shipped default —
    which reads as protected and is not, since browsers ignore HSTS on a plain-HTTP response.

  **Review round.** Eight findings from the PR review bot, seven acted on. The one that
  mattered: the code did the *opposite* of its own comment. `self_signed` generation ran before
  ACME, wrote to the same `cert_path`, and the ACME branch skips issuance when a certificate is
  already there — so with both enabled on a public domain, the untrusted self-signed certificate
  silently won over the publicly trusted one the operator asked for. ACME now runs first, which
  is also what makes `self_signed` the floor it was documented to be. Alongside it: `Host` is now
  parsed as a whole authority rather than split on the first colon (`attacker.example:443@victim.example`
  was reduced to `attacker.example` and redirected instead of refused — the strictness the docs
  already claimed); `redirect_status` is validated before the listener binds, since failing inside
  the spawned task left the port closed while HTTPS carried on, turning a typo into "connection
  refused"; an out-of-range `--days` returns an error instead of panicking on `OffsetDateTime`
  overflow; identical `cert_path`/`key_path` is refused rather than writing the key over the
  certificate and reporting success; and both files are now staged and renamed into place, which
  also fixes a real permissions hole — `OpenOptions::mode` only applies when it *creates* a file,
  so regenerating over an existing `0644` key had been leaving new key material world-readable.
  Not taken: a cross-process lock around generation — with the reasoning stated more carefully
  than the first draft managed, because whether a lock helps depends on the storage. On **shared**
  storage one would work: the first replica generates, the rest find a complete pair and reuse it,
  and they converge on one identity. On **per-replica** storage it cannot — there is nothing to
  coordinate through, so each replica necessarily holds a different self-signed identity. The
  second case has no fix at this layer and the first is better solved by not generating at boot,
  so the documented answer for either is to generate once with `edgeguard cert` and mount it
  read-only, and `ensure` now says exactly that rather than dismissing locks outright.

  A second round found four more, all taken. `is_redirection()` accepts the whole 3xx class, so
  `redirect_status = 304` was allowed and would answer a cache validator with a `Location`,
  leaving the client on plaintext — the exact failure the feature exists to prevent, reached
  through a value we accepted; only 301/302/303/307/308 now pass. The ACME skip-issuance guard
  tested `cert_path` alone, so a certificate whose key was missing skipped the order and handed
  the half-pair to `ensure`, which regenerates both — the precedence bug again, through a
  different door; both files must now be present to skip. And `Path::exists()` follows symlinks,
  so a dangling one read as "absent" and let a no-force `edgeguard cert` replace the operator's
  symlink with a regular file; presence is now tested with `symlink_metadata`.

  A third round closed the pair-publication gap properly. The previous attempt staged and
  renamed one file at a time while its own comment claimed it staged both first — the third
  comment/code mismatch this change produced, and the reviewer was right that an ordinary I/O
  error on the key (not just a crash) could therefore leave a new certificate live against the
  old key. Both files are now staged before either live path moves, and the live certificate is
  set aside first and put back if the key never lands, so **any** failure leaves the operator's
  existing pair exactly as it was. Writing the test for that caught the remaining hole in the
  fix: a `rename` fails on its own too (a directory in the way, a read-only mount), so staging
  alone was not enough — hence the rollback.

  **Build cost: none measurable.** `rcgen` is declared directly for the first time since 0.3.0, but
  `instant-acme` already depends on it, so it was compiled on every build regardless: the graph
  stays at **218 crates**, cold release build time is unchanged, and the stripped binary grows
  **331 KiB (+1.9%)**, from 16.63 MiB to 16.96 MiB. Both features are always-on code paths with
  no feature flag, because a security default behind an opt-in flag is not a default.

- **Access logs no longer carry credentials.** The request line is the most useful field in an
  access log and the easiest place to leak a secret: password-reset links, OAuth `?code=`,
  presigned URLs and `?api_key=` all travel in the query string, and access logs are the
  most-copied artifact a service produces — scraped, shipped to a SIEM, retained for months, read
  by people who were never meant to hold the credential. EdgeGuard was logging
  `path_and_query()` verbatim, which for a proxy that advertises DLP is the wrong component to be
  writing them to disk.

  Query values are now redacted on two independent signals: **by name** (a built-in list covering
  `key`, `token`, `secret`, `password`, `auth`, `code`, `state`, `email`, … matched
  case-insensitively as substrings, plus whatever `[log] redact_params` adds) and **by shape** (a
  JWT, or a long high-entropy token — which catches `?t=eyJhbGciOi…` where the parameter name is
  innocuous and a name list never would). Ordinary values — page numbers, slugs, dates, search
  terms — stay readable, so the log keeps its debugging value. The replacement is a fixed
  `<redacted>`, so neither the value nor its length leaks.

  `[log] query` selects `redact` (default), `drop` (path only), or `full` (verbatim, opt-in).

  **Only the log is affected.** The upstream receives the client's target byte-for-byte, and the
  WAF, per-route rate limits, route-scoped DLP and upstream selection all still see the raw
  request — redacting those would break routing and blind the security pipeline. Both properties
  are covered by integration tests, including a WAF test whose SQLi payload sits in a parameter
  named `code`, which is on the redaction list.

  Path segments are *not* redacted: `/reset/<token>` cannot be distinguished from `/users/<id>`
  without knowing the application's routes, and guessing would mangle ordinary paths. Use `drop`
  where secrets ride in path segments.

  **Encoded parameters do not slip past it.** Classification runs on the decoded form as well as the
  raw text, so `?%74%6f%6b%65%6e=secret` (that is `?token=secret`) and a JWT whose dots are `%2E`
  are both caught — otherwise redaction would have covered exactly the credentials nobody bothered
  to obfuscate. Only classification decodes; the logged text keeps the original encoding, because
  rewriting it would change what the request actually said.

  **Upstream failure logs are covered too.** `upstream timed out` and `upstream unreachable` printed
  the forwarded URI, query and all — redacting the access line and then leaking the same `?api_key=`
  in a `warn!` would give it up on the path an operator is most likely to be reading. The forwarded
  URI is still verbatim; only the logged one is sanitised.

  The setting is deliberately **not** pushable from a control plane. A managed plane able to flip
  an edge to `query = "full"` could turn that edge's own logs into an exfiltration channel for
  every credential its users put in a URL, without touching the edge's config file.
- **A documentation site at `eggrd.dev/docs`, so the reference is not the source.** The landing
  page's "Documentation" link pointed at the GitHub README, which meant every question about a
  configuration key ended in `config.rs`. There are now four pages: an overview, the CLI and
  environment variables, the full configuration reference, and operations (endpoints, every
  Prometheus series, and what fails closed).

  **The configuration page is generated** from `src/config.rs` by
  `scripts/build-config-reference.py` — 151 keys across 21 tables, with the doc comment as the
  description and the `Default` impl as the stated default. It cannot describe a binary that
  does not exist, and a field added without a doc comment fails the generator rather than
  producing a blank row: a reference with silent holes looks complete and is not.

  Writing it found **21 public config fields with no doc comment at all**, including
  `auth.realm`, all six `[headers]` policy values and every `enabled` flag. Those are now
  documented in `config.rs`, which improves the source as much as the page.

### Added
- **The LLM gateway's ordering guarantee is now enforced by tests, not asserted in comments.**
  The landing page claims the budget reserve, model allowlist and DLP gates run *before the
  provider is called* — the whole economic argument, since a request that reaches the provider has
  been paid for whatever the client eventually sees. Every denial test checked the client's status
  and the metric and said "never reaches the upstream" in a comment; none of them observed the
  upstream. A gate that forwarded first and denied afterwards would have passed all of them.

  Five tests now use a counting stub provider and assert it saw **exactly zero** requests: over
  budget, DLP block, off-allowlist model, and a budget-store outage (fail-closed, the default).
  A control test asserts an admitted request registers exactly one hit — without it, a counter
  that never incremented would make the rest pass vacuously.

  Confirmed to have teeth by mutation: making the denial path call the provider before returning
  makes `over_budget_request_never_reaches_the_provider` fail with `left: 1, right: 0`, while the
  client still receives the same `429` the old test accepted.
- **The same guarantee is now covered for the gates in front of an ordinary app**, not just the
  LLM path: unauthenticated (`401`), WAF block (`403`), IP-denied (`403`), oversized body (`413`),
  rate-limited (`429`), and a rate-limiter store outage (`503`, fail-closed). Each asserts the
  upstream saw zero requests, with a control asserting an allowed request reaches it exactly once.
  Mutating the auth path to forward before rejecting makes
  `unauthenticated_request_never_reaches_the_upstream` fail the same way.

### Changed
- **`aws-lc-sys` is gone from the dependency graph.** It was the single most expensive crate in
  the build — 54.8s of a 139s cold `cargo build --release --bin edgeguard` on 4 cores, 17.4% of
  total unit-time — and nothing used it. `src/tls.rs` has always pinned `ring`: `init_crypto()`
  installs the ring provider and `load_server_config()` builds the `ServerConfig` with an
  explicit one. The aws-lc stack was in the graph purely by feature unification, because
  `rustls = { features = ["ring"] }` adds `ring` *on top of* rustls's defaults rather than
  replacing them, leaving `aws_lc_rs` on — and `tokio-rustls` and `instant-acme` each turned it
  back on through their own defaults, so fixing only `rustls` was not enough.

  All three now take an explicit ring path (`default-features = false` plus the features the
  crate actually uses). `reqwest` and `redis` needed no change and are annotated as such in
  `Cargo.toml`, so the next person does not re-derive it: reqwest's `rustls-tls` already implies
  `__rustls-ring`, and redis declares rustls with `default-features = false`.

  Measured on the same 4-core box, cold target and warm registry: **139s → 111s wall**, total
  unit-time **314.7s → 255.7s**, 285 → 271 compilation units, and `cargo tree -i aws-lc-rs`
  reports nothing under default, `--all-features` and `--features ner`. The stripped release
  binary goes from **16.6 MiB to 7.5 MiB** — 54.7% smaller, since the whole of libcrypto was
  being linked in unused. It also removes the build's only cmake/bindgen C dependency, which was
  the piece most likely to break on a new toolchain or a musl/cross target — the thing the
  single-static-binary and distroless claims rest on.

  Nothing changes on the wire. rustls's `prefer-post-quantum` default is dropped along with the
  rest (it is an `aws_lc_rs` alias), but it was already inert: the listener builds with an
  explicit ring provider and ring has no ML-KEM. Before and after both negotiate
  `TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519 / RSASSA-PSS`.

- **The single-provider rule is now enforced, not just documented.**
  `scripts/check-crypto-provider.sh` fails the build if `aws-lc-rs` or `aws-lc-sys` reappears
  anywhere in the resolved graph, and names what pulled it in. It runs in CI and as `make deps`
  (part of `make test-all`).

  It has to be a graph check rather than a test, because neither consequence surfaces as a test
  failure: the C build is a build-time and binary-size cost, and the provider ambiguity only
  bites the `rediss://` path at runtime. A lockfile does not remove the need for it: a
  `cargo update`, a new dependency, or a point release that flips a default feature anywhere
  across rustls / tokio-rustls / instant-acme / hyper-rustls / rcgen can put aws-lc back, and in
  a ~26k-line workspace lock diff the handful of changed edges is not something a reviewer
  spots. The crate also ships without a lock of its own, so the OSS cut resolves fresh every
  time.

  The check reads `cargo tree`, not `Cargo.lock`, because the lock keeps entries for optional
  dependencies that no enabled feature activates — `aws-lc-rs` is still listed there under
  `rustls-webpki` — so grepping the lock would report a regression that is not one. Both package
  names are matched: `rcgen` can pull `aws-lc-rs` without touching rustls's features, so neither
  name implies the other.

### Fixed
- **`ratelimit.store = "redis"` over `rediss://` aborted the process when TLS termination was
  off.** Linking two rustls crypto providers makes `rustls::ClientConfig::builder()` panic —
  *"Could not automatically determine the process-level CryptoProvider"* — unless a default has
  been installed first. `tls::init_crypto()` installs one, but only runs under `[tls] enabled`,
  and the `redis` crate calls that builder when it opens a `rediss://` connection. So an operator
  terminating TLS at a load balancer (the documented deployment) and pointing the distributed
  limiter at a TLS Redis lost the process on the first rate-limited request, with a panic
  message about crate features rather than anything resembling their config.

  With `ring` now the only provider linked, the lookup resolves from crate features and the path
  behaves like every other store failure: the connection is attempted, and an unreachable store
  fails closed with `503` and a `rate-limit store error` warning.

- **`dead_addr()` in the integration tests was racy.** It bound an ephemeral port and dropped it,
  assuming nothing would claim it — but the OS is free to hand that port to the next listener, and
  with more concurrent tests it does. The "down" upstream then answered `200` and
  `bad_gateway_when_upstream_down` failed pointing at the proxy, when the fault was in the
  fixture. Now returns `127.0.0.1:1`, which is privileged, unallocated, and refuses immediately.

### Fixed (release tooling, no crate change)
- **The crate is published to crates.io again.** The mirror's release workflow had a `crates`
  job that published `edgeguard-ner` and then `eggrd`; rewriting that workflow upstream dropped
  it, and nothing noticed because the images kept publishing. crates.io stopped at **0.2.1**
  (2026-07-14) while 0.2.2, 0.3.0 and 0.3.1 shipped as containers — so `cargo install eggrd`,
  which the site and this README both recommend, was installing the version whose ACME issuance
  is broken.

  Restored, and deliberately independent of the image jobs so a Docker Hub outage cannot block
  the crate. It keeps the ordering the original had, which a dry run confirms is still required:
  `eggrd` declares `edgeguard-ner = "^0.1.1"`, only `0.1.0` is on the index, and packaging
  `eggrd` fails outright until the new `edgeguard-ner` is published *and* indexed. Both steps
  treat an already-published version as success, and the retry loop waits only on index
  propagation — any other failure exits immediately rather than burning four minutes to report
  the wrong cause.

  A `workflow_dispatch` with `push: false` now skips the crate publish as well as the image
  push. A crates.io release cannot be withdrawn, only yanked, so a "dry run" that publishes one
  is not a dry run.

## [0.3.1] — 2026-08-24

A patch release, but read the argument-parsing note before upgrading: it changes what happens to
a command line the proxy previously accepted.

Both fixes came from the same habit as 0.3.0 — running the thing rather than reading it. Both
turned out to be the project being wrong about itself: one flag that silently did nothing, and
one build failure blamed on the wrong component for weeks.

### Added
- **`edgeguard --version` / `-V`.** There was previously no way to ask a binary or a published
  image what version it was — the flag fell through the parser's catch-all and started a proxy
  instead. Works for the subcommands too (`edgeguard doctor --version`).

### Fixed
- **The WASM edge worker builds and runs — the toolchain was never the problem.** `worker-build`
  failed with `externref table required for catch wrappers`, which was recorded as a pinned-
  toolchain incompatibility and left the worker as the one unproven capability. It was actually
  `strip = true` in the worker's own `[profile.release]`: `worker-build` invokes wasm-bindgen with
  `--force-enable-abort-handler`, whose catch wrappers need the externref table, and stripping
  removes the symbols used to find it. The error names neither `strip` nor the manifest.

  Bisected by holding everything else constant — `lto = true` + no strip builds; `lto = false` +
  strip fails. LTO, the usual suspect, was never involved.

  With `strip` removed, `worker-build --release` emits the bundle (`index.js` +
  a 415 KB `index_bg.wasm`), and it was **run on workerd**, the runtime Cloudflare runs in
  production: `401` unauthenticated, `401` on a wrong password, `200` fetched from a live origin
  carrying all six hardening headers with `Server` and `X-Powered-By` stripped. Deployment to a
  Cloudflare account — routes, custom domains, secret bindings — remains untested.
- **Unknown arguments are rejected instead of silently discarded.** The serve path and
  `generate` ended in `_ => {}`, so any token the parser did not recognise was dropped without
  a word. A typo such as `--wrpa "npm start"` started an unwrapped, unconfigured proxy that
  looked healthy, and `generate --targt vercel` emitted the default `_headers` target and
  reported success. Both now fail with the offending argument named, matching what `doctor` and
  `init` already did. A front door that ignores its instructions is worse than one that refuses
  to open.

  This is a **behaviour change**: a deployment currently passing an argument that was being
  ignored will now fail at startup rather than run with settings it did not ask for.

### Fixed (release tooling, no crate change)
- **The 0.3.0 manifest assertion could never pass.** It grepped the raw manifest for
  `"architecture":"amd64"`, but `docker buildx imagetools inspect --raw` returns
  pretty-printed JSON — `"architecture": "amd64"`, with a space. The 0.3.0 release therefore
  reported `amd64 missing` and failed while all three tags were in fact correctly
  multi-arch. It now parses the index with `jq` and prints what it found, so a real failure
  is diagnosable and a false one cannot recur. An assertion that cannot pass is worse than
  no assertion: it teaches people to re-run through red.
- **Two release pipelines could run concurrently.** `gh release create` creates the tag,
  raising a push event alongside the release event, so 0.3.0 ran the whole pipeline twice
  against the same tags. Serialized with a concurrency group keyed on the ref, deliberately
  *without* `cancel-in-progress` — cancelling mid-push is what leaves half-written tags.
- **The Docker Hub overview stopped updating.** `dockerhub-readme.yml` existed only on the
  public mirror, hand-placed and untracked upstream, so the first sync that owned
  `.github/workflows/` deleted it. The overview kept advertising 0.2.1 after 0.3.0 shipped.
  Restored upstream and added to the sync manifest, which is the only place it survives.

## [0.3.0] — 2026-08-24

Three capabilities this crate shipped were compiled but had never been run against real
infrastructure. Running them found one of the three genuinely broken, and that fix is the
reason this is a minor bump rather than a patch.

### Fixed
- **ACME certificate issuance was broken in the field, and is now proven working.**
  The pinned `instant-acme` 0.7.2 (October 2024) could no longer parse Let's Encrypt's
  current authorization payload, so every issuance attempt failed at the first
  authorization with:

      Error: ACME certificate provisioning
      Caused by:
        0: fetching authorizations
        1: missing field `token`

  This affected anyone relying on `[tls] acme = true` for automatic certificates — the
  proxy started, then failed to obtain a certificate. Bumped to `instant-acme` 0.8 and
  reworked the order flow around its API: the HTTP-01 challenge responder is now started
  **before** the authorizations are walked (the previous order raced the CA's validation),
  challenges are marked ready explicitly, and both the order and the certificate are polled
  with a retry policy instead of a hand-rolled sleep loop.

  Verified end to end twice: against a local Pebble CA, and against Let's Encrypt's staging
  environment, which issued a real certificate in about five seconds
  (`CN=acme-test.eggrd.dev`, issuer `(STAGING) Artificial Amaranth YE1`).
  `docs/ACME_TESTING.md` carries both recipes and every trap that stopped them working.

### Removed
- **The `rcgen` dependency.** `instant-acme` 0.8 generates the key pair and CSR inside
  `finalize()` and returns the private key, so nothing in this crate constructed a
  certificate itself any more. `rcgen` had been left behind as an unused dependency — in a
  proxy that terminates TLS, an unused crypto dependency is supply-chain surface with no
  compensating benefit.

### Added
- **Native `linux/arm64` images.** Releases now build each architecture on its own native
  runner (`ubuntu-24.04` and `ubuntu-24.04-arm`), push by digest, and merge the two into one
  multi-arch manifest. The release fails if the merged manifest does not contain both
  architectures, so a half-published image cannot pass as a green release. Previous images
  were amd64 only. The release also now asserts that `Cargo.toml` matches the tag being
  released — the image tag came from the git tag while `--version` came from the manifest,
  and nothing compared them, so a forgotten bump could have published an image labelled
  `0.3.0` containing a binary reporting `0.2.2`.
- **`examples/tls-termination.toml`** — a TLS configuration that has actually been run,
  with the reproduce recipe in its header. Explicitly marked as a demonstration rather than
  a production template.
- **`docs/ACME_TESTING.md`** — how to test ACME locally against Pebble and against Let's
  Encrypt staging, plus each failure encountered on the way and the misleading symptom it
  presented.

### Changed
- **CI now runs on the public repository.** The crate's `ci.yml` travelled with the source
  but was never registered, so the public repository had no CI at all after 2026-07-28. It
  and the new `release.yml` are now shipped by the release pipeline and run on every push
  there.

### Proven, not changed
No code change, but previously undemonstrated and now exercised:
- **TLS termination with a supplied certificate** — TLS 1.3 negotiated, certificate
  verified, the upstream response proxied back through it, plaintext refused on the TLS
  port, and all six hardening headers present on the response.
- **The shared-store rate limiter** — two replicas against one Redis, thirty requests from
  a single client alternating between them: **5 allowed** against one shared key. The same
  run with the per-replica store allowed **10**, exactly twice, which is the reason the
  shared store exists.

The **WASM edge worker remains unproven.** The crate compiles to
`wasm32-unknown-unknown`, but `worker-build` — the step that produces the deployable
bundle — fails on the pinned toolchain, so there is no artifact to run.

## [0.2.2] — 2026-07-28

### Changed
- **Documentation comments describe failure modes rather than attributing them.** A number of
  doc comments across the LLM metering, DLP and alerting paths justified a design choice by
  pointing at a specific defect in another vendor's issue tracker. The engineering rationale is
  unchanged and still stated — an unmask that can restore another caller's value is still the
  thing reversible masking is built to avoid, and an unknown model is still never served at a
  silent `$0` — but the reasoning now stands on its own rather than on a third-party bug report
  that this project does not re-check and cannot keep current.

## [0.2.1] — 2026-07-15

### Fixed
- **Cookie hardening no longer forces `HttpOnly` on cookies that must stay JS-readable.**
  EdgeGuard's `[headers]` hardening added `HttpOnly` to every `Set-Cookie` unconditionally,
  which silently broke apps behind the proxy that use a **double-submit CSRF cookie** the
  frontend reads from `document.cookie` (the cookie became unreadable → the app saw no
  session). Two new `[headers]` keys make it configurable:
  - `httponly_cookies` (bool, default `true`) — global toggle for adding `HttpOnly`.
  - `httponly_cookie_exempt` (string list, default `[]`) — cookie **names** to never add
    `HttpOnly` to, e.g. `["doneyet_csrf"]`. The surgical fix.

  `Secure` and the `SameSite=Lax` default are unchanged. Existing configs keep the previous
  behaviour (HttpOnly on by default); opt out only for cookies you intend JS to read.

## [0.2.0] — 2026-06-28

### Hardened (pre-release review follow-ups)
- **CORS on error responses**: EdgeGuard-generated `401`/`403`/`429` are now CORS-decorated too
  (centralized in `proxy::handle`), so an allowed browser origin sees the real status instead of a
  generic CORS failure.
- **WebSocket upgrade path**: forwards under the same `upstream_timeout`, caps a rejected
  (non-`101`) body by `max_response_body`, and strips hop-by-hop headers before forwarding (so a
  client can't smuggle connection-scoped headers upstream).
- **`[[upstreams]]` validation**: a `path` without a leading `/` (e.g. `api/`) is now rejected at
  startup instead of silently never matching.
- **`edgeguard doctor`**: also validates the managed-mode control-plane path (`CpClient::from_cfg`),
  no longer prints "no issues found" when info-level findings were emitted, and no longer warns
  about secrets "in the config file" when they were actually sourced from the env / `*_FILE`.
- **CLI**: `doctor` / `init` now reject unknown flags (a typo like `--confg` no longer silently
  validates the default config).

### Added
- **Request IDs** (`X-Request-Id`): for every request EdgeGuard reuses a well-formed inbound id (a
  short, printable-ASCII token — validated so it can't inject control characters into the log) or
  mints a UUID v4, forwards it upstream, echoes it on every response (including errors), and adds it
  to the JSON access log — one id correlates the client, EdgeGuard, and the app. Always on. See
  `src/proxy.rs`.
- **Per-path upstreams** (`[[upstreams]]`, single upstream by default): a static path-prefix →
  upstream map (longest prefix wins; unmatched falls back to the default upstream), for the common
  "static frontend + `/api` backend" shape. Deliberately not a gateway — no service discovery, load
  balancing, or request rewriting. Edge-local (not pushed by the control plane). See `src/config.rs`.
- **Response compression** (`validation.compress_responses`, off by default): gzip for clients that
  send `Accept-Encoding: gzip`, via `tower-http`, skipping small/already-compressed responses and
  (always) `text/event-stream` so SSE streaming is never buffered by the compressor. Listener-level
  (restart to toggle). See `src/lib.rs`.
- **Prometheus alert rules** (`monitoring/prometheus/alerts.yml`): reusable alerts on upstream-5xx
  ratio, p95 latency, auth-failure / WAF / rate-limit spikes, and limiter-store errors, wired into
  the bundled monitoring stack and droppable into any Prometheus.
- **WebSocket / `Upgrade` passthrough** (`[validation] websocket_passthrough`, **off by default**):
  tunnel WebSocket connections through to the upstream. The normal path strips the hop-by-hop
  `Upgrade`/`Connection` headers (so a handshake would fail); when enabled, an authenticated,
  rate-limited upgrade request is forwarded intact and, on the upstream's `101 Switching
  Protocols`, EdgeGuard splices the client and upstream connections into a raw bidirectional tunnel
  (`tokio::io::copy_bidirectional` over `hyper::upgrade`). A non-`101` reply is passed back
  unchanged. Response hardening / WAF body inspection don't apply to a tunneled connection. See
  `src/proxy.rs`.
- **IP access control** (`[access]`, allow-all by default): CIDR `allow`/`deny` lists (IPv4 + IPv6)
  evaluated by client IP **before auth and rate limiting** — lock the app to an office/VPN range or
  drop an abusive subnet. `deny` wins over `allow`; a non-empty `allow` is a whitelist. Matching is
  implemented directly (no new dependency); a bad CIDR fails at startup/reload. Keys on the same
  resolved client IP rate limiting uses. See `src/access.rs`.
- **`*_FILE` secret loading**: every secret env var now also accepts a `*_FILE` variant
  (`EDGEGUARD_JWT_SECRET_FILE`, `EDGEGUARD_API_KEYS_FILE`, `EDGEGUARD_REDIS_URL_FILE`,
  `EDGEGUARD_CP_EDGE_TOKEN_FILE`) pointing at a file whose contents are the value — the Docker /
  Kubernetes / systemd-`LoadCredential` secret-mount convention, so secrets stay out of the config
  file and the process environment. The direct variable wins when both are set; an unreadable
  `*_FILE` is a hard startup error. See `src/config.rs`.
- **Deploy examples**: a hardened systemd unit (`examples/edgeguard.service` — sandboxed, binds
  80/443 via `CAP_NET_BIND_SERVICE`, secrets via `LoadCredential` + `*_FILE`) and a
  `docker compose` front-door layout (`examples/docker-compose.yml` — app reachable only through
  EdgeGuard, file-mounted secret).
- **CORS** (`[cors]`, **off by default**): a small, explicit Cross-Origin Resource Sharing policy
  so a separate-origin browser frontend (a static host, a preview URL, `localhost:5173` in dev) can
  call the app EdgeGuard fronts. EdgeGuard answers browser **preflight** `OPTIONS` requests itself —
  *before* auth, since preflights carry no credentials — and **decorates** actual responses with the
  matching `Access-Control-*` headers (echoing the request `Origin` + `Vary: Origin` for an explicit
  allow-list, or the cacheable `*` for a wildcard). A credentialed wildcard
  (`allow_credentials = true` with `allow_origins = ["*"]`) is rejected at startup/reload, since the
  Fetch spec forbids it. Configure `allow_origins`/`allow_methods`/`allow_headers`/`expose_headers`/
  `allow_credentials`/`max_age`. Compiled into a `crate::cors::CorsPolicy` on the hot-swappable
  runtime. See `src/cors.rs`.
- **`edgeguard init`**: scaffold a starter `edgeguard.toml` (the annotated, secure-by-default
  reference, embedded so it can't drift) plus a `Dockerfile.edgeguard` that wraps your app behind
  EdgeGuard — tailored to the runtime detected from the working directory (Node / Python / Go /
  Rust). Refuses to clobber existing files unless `--force`. Turns adoption from "read the README and
  hand-write a config + Dockerfile" into one command. See `src/scaffold.rs`.
- **`edgeguard doctor`**: load + validate a config (the same `Config::load` + `build_runtime` paths
  the proxy uses) and report the common deployment foot-guns — the shipped **placeholder credential**
  still in place (a malformed argon2 hash that can never authenticate), `auth.mode = "none"`, secrets
  committed to the file, an over-permissive or credentialed-wildcard CORS policy, a `redis` store with
  no URL, `enforce_quota` without managed mode, and more. Exits non-zero on a hard error, so it can
  gate a deploy in CI. See `src/doctor.rs`.

## [0.1.5] — 2026-06-21

### Added
- **Streaming / LLM-proxy passthrough** (`[validation] stream_passthrough`, **off by default**):
  forward `text/event-stream` (Server-Sent Events) responses **unbuffered, frame-by-frame** instead
  of buffering the whole body first. This makes EdgeGuard a viable front door for **streaming LLM
  backends** (OpenAI-compatible token streams) and any SSE app — time-to-first-byte is preserved
  rather than collapsing to time-to-completion. A small `CountingBody` wrapper tallies egress bytes
  as frames flow, so managed-mode usage stays correct without buffering. On a streamed response the
  `max_response_body` cap and the body-read deadline don't apply (the connect/first-byte
  `upstream_timeout` still does). Non-SSE responses are unchanged. See `src/proxy.rs`.

### Docs
- Grafana dashboard for the load-test harness (`loadtest/grafana/`): an auto-provisioned
  **"EdgeGuard — proxy overview"** dashboard (request rate by outcome, p50/p95/p99 latency from the
  histogram, rate-limit hits by scope, WAF hits by rule) wired to the harness Prometheus, plus a
  pinned datasource uid so it binds deterministically.

## [0.1.4] — 2026-06-20

### Added
- **Managed mode** (`[control_plane]`, **off by default**): an optional client that pulls this
  edge's policy from a remote control plane and hot-reloads it (conditional `GET` with an ETag →
  `304`, applied through the same `build_runtime` + arc-swap path as a local file edit), reports
  usage deltas (requests + ingress/egress bytes), and forwards received CSP reports. The pushed
  policy is the *policy subset* (auth/ratelimit/validation/headers/waf) — the edge keeps its own
  local `[server]`/`[tls]`. The edge token comes from `EDGEGUARD_CP_EDGE_TOKEN`. With no
  `[control_plane]` configured the proxy is byte-for-byte unchanged. See `src/cp.rs`.
- **Live-dependency proof tests** (`#[ignore]`d — no effect on the default suite): two against a
  live **Redis** exercising the real GCRA Lua script (global per-IP + per-key limits;
  `cargo test --lib redis_ -- --ignored`), and one **ACME HTTP-01** end-to-end against
  [Pebble](https://github.com/letsencrypt/pebble) (`src/acme.rs`), plus a
  `loadtest/pebble.compose.yaml` starting point.

### Docs
- Expanded the **distributed rate-limiting** README section: *why* a shared store (a per-replica
  limit multiplies under autoscale — Redis keeps one global cap) and *how to run it* (a local
  one-Redis snippet and a 3-replica compose).

## [0.1.3] — 2026-06-19

### Added
- README **"Where it fits"** section: high-level architecture diagrams (front-door + wider-stack
  placement), a "what it does *not* replace" list, and migration examples for moving an existing
  app behind EdgeGuard (from no-proxy / plain nginx / a hosted gate / a static host).
- **Multi-arch release image** `mancube/eggrd` (Docker Hub) — `linux/amd64` + `linux/arm64`, a
  static musl binary on `distroless/static`; see `Dockerfile`.

### Changed
- Deploy templates and docs point the container image at `mancube/eggrd` (Docker Hub) and the
  build-from-source step at `cargo install eggrd`; repository links use `lucheeseng827/eggrd`.

## [0.1.2] — 2026-06-18

### Changed
- Crate `repository` metadata now points at the public mirror `lucheeseng827/eggrd` (was the
  development monorepo, whose link 404s for the public). Metadata-only; no code change.

## [0.1.1] — 2026-06-18

### Changed
- README rewritten to a neutral, data-plane-only, user-facing tone. No code change.

## [0.1.0] — 2026-06-18

First public release on crates.io, published as the **`eggrd`** package — the name `edgeguard`
was already taken, so the crate is `eggrd` while the binary and library keep the name
`edgeguard` (the CLI, the `EDGEGUARD_*` env vars, and the `/__edgeguard/*` namespace are
unchanged). Ships the v0–v2.5 feature set below.

> **Note:** 0.1.0 and 0.1.1 are **yanked** — they carried, respectively, a `repository` link that
> 404s for the public and an interim README. Use **0.1.2+**.

### Changed
- **License consolidated to Apache-2.0** (was MIT OR Apache-2.0), pre-release.

### Added
- **Phase 5 / v2.5 (static/edge surface):**
  - **Static-host / edge config generator** (`edgeguard generate --target <t>`): renders the
    `[headers]` policy into a `_headers` file (Netlify / Cloudflare Pages), a `vercel.json` headers
    block, a Vercel Edge Middleware (`middleware.ts`), or a Netlify Edge Function. `--out <path>`
    writes to a file (otherwise stdout). Every target renders from a new shared
    `proxy::security_headers` — the **same** source of truth the live proxy injects — so generated
    config can't drift from runtime; an integration test cross-checks the generated `_headers`
    against a real proxied response. (A static `_headers` file can only *add* headers, so cookie
    hardening / leaky-header stripping / auth are documented as worker-only.) See `src/generate.rs`.
  - **Rust→WASM Cloudflare Worker** (`worker/`): a detached-workspace crate that compiles to
    `wasm32-unknown-unknown` via `worker-build`. It authenticates at the edge (HTTP Basic / static
    API key, constant-time), forwards to the configured origin, and hardens the response (security
    headers + cookie hardening + leaky-header stripping) — mirroring `src/proxy.rs` / `src/auth.rs`.
    The pure logic (header set, auth decision, cookie hardening, env parsing, origin-URL joining)
    is unit-tested on the native target and the wasm entrypoint compiles clean under
    `cargo clippy --target wasm32-unknown-unknown -D warnings`; the `fetch` runtime is *proven only
    against a live Cloudflare deploy* (like ACME / Redis). Rate limiting and JWT are out of scope
    for the edge subset. See `worker/README.md`.
  - Refactor: extracted `proxy::security_headers` + `proxy::HSTS_VALUE` as the single source of
    truth for the injected security-header set, now shared by the live proxy and the generator.
- **Phase 4 / v2 (WAF-lite), in progress:**
  - **WAF-lite input inspection** (`[waf]`, **off by default**): built-in heuristic **SQLi**,
    **XSS**, and **path-traversal** rulesets screen the request path/query (matched both raw and
    percent-decoded) and, opt-in (`inspect_headers` / `inspect_body`), header values and the
    size-capped request body. `mode = "report"` logs + counts matches without blocking;
    `mode = "block"` returns `403 Forbidden`. Each built-in ruleset is individually toggleable.
    Runs after auth and the size/method checks; the internal `/__edgeguard/*` endpoints are
    never inspected. See `src/waf.rs`.
  - **Custom deny patterns / pluggable rule sets** (`[[waf.rules]]`): operator-defined RE2 regex
    rules with a per-rule `target` (`path` / `headers` / `body` / `all`), evaluated alongside the
    built-ins. RE2 matching is linear-time and rejects backreferences/lookaround, so an operator
    pattern can't cause catastrophic backtracking (ReDoS); a pattern that fails to compile (or an
    unknown `target`) is rejected at startup/reload like any other config error.
  - `edgeguard_waf_hits_total{rule="sqli|xss|path_traversal|custom"}` metric, counting both
    report-only and blocked matches; blocked requests are additionally counted under the existing
    `forbidden` request outcome. The startup log line now also reports the active `waf` mode.
  - **Distributed (shared-store) rate limiter** (`ratelimit.store`): in addition to the default
    in-process `governor` limiter (`"local"`), a **Redis**-backed shared store (`"redis"`) so
    multiple replicas enforce one global GCRA limit (`redis_url` / `redis_prefix`, or the
    `EDGEGUARD_REDIS_URL` env var; `rediss://` TLS supported). The GCRA check-and-update runs
    atomically as a Redis Lua script. `ratelimit.fail_open` controls behavior when the store is
    unreachable: fail-closed `503` (default) or fail-open allow — this is the failure path the
    removed `fail_mode` knob was meant for. A `"memory"` store exercises the same shared-store
    code path in-process. *The Redis transport is compiled but, like ACME, is not covered by the
    in-process test suite (the GCRA core and the in-memory store are); see `src/limiter.rs`.*
  - **Public/private service split** (`server.admin_port` / `server.admin_addr`, or the
    `ADMIN_PORT` env var): when set, the internal ops endpoints (`/__edgeguard/health`, `/ready`,
    `/metrics`) are served on a separate, plain-HTTP **private listener**, keeping them off the
    public port; the public port serves only the proxy plus the browser-facing CSP report sink.
    The `/__edgeguard/*` namespace is now **reserved** — unknown internal paths return `404`
    rather than being forwarded upstream (`not_found` outcome). New `build_public_router` /
    `build_admin_router`, and a `limiter_error` outcome for fail-closed store errors.
- **Phase 3 / v1 (self-hostable & production-usable):**
  - **JWT auth** (`auth.mode = "jwt"`): HS/RS/ES/PS/EdDSA verification with either a static
    secret/PEM key or a fetched, **cached JWKS** (keys selected by `kid`, refreshed on miss or
    TTL expiry). The configured algorithm is pinned, so a token can't substitute its own `alg`
    (`alg=none`/HS-vs-RS confusion). Optional `issuer`/`audience`/leeway checks.
  - **Static API-key / bearer-token gate** (`auth.mode = "apikey"`): constant-time match of
    `Authorization: Bearer <key>` or a configurable header (default `X-API-Key`); keys may come
    from `EDGEGUARD_API_KEYS`.
  - **Per-route and per-key rate limits**: per-route overrides matched by longest path prefix
    (`[[ratelimit.routes]]`) and an optional per-principal limit (`[ratelimit.per_key]`) keyed
    by API-key id / JWT subject.
  - **TLS termination** (`[tls]`) via `rustls` + `tokio-rustls`, loading a PEM cert/key, with
    **ACME / Let's Encrypt** automatic certificates over HTTP-01 (`[tls.acme]`, via
    `instant-acme` + `rcgen`; staging by default). *ACME is compiled/CI-checked but provable
    only against a live CA — it binds port 80 and needs a public domain.*
  - **Prometheus metrics** at `/__edgeguard/metrics`: requests by outcome, rate-limit hits by
    scope, a request-latency histogram, and CSP report count (hand-rolled text exposition, no
    new metrics dependency).
  - **Config hot-reload** via `notify`: the config file is watched and policy is rebuilt and
    swapped atomically (`arc-swap`) with no dropped connections; an invalid edit is logged and
    the previous policy retained. The connection pool and metric counters survive a reload.
  - **CSP report-only mode + violation sink**: `headers.csp_report_only` emits
    `Content-Security-Policy-Report-Only`; `headers.csp_report_uri` appends a `report-uri`
    directive, and `POST /__edgeguard/csp-report` logs + counts received reports.
  - **Max-header-size limit** (`validation.max_header_bytes`): requests whose total header
    bytes exceed the cap get `431` (completes the Phase 3 timeout/header-size item).
- OSS launch scaffolding: dual `LICENSE-MIT` / `LICENSE-APACHE`, `CONTRIBUTING.md`, this
  changelog, and the `docs/` set (`REQUIREMENTS.md`, `DEPLOYMENT.md`, `ROADMAP.md`).
- `examples/` directory holding the deploy templates (`Dockerfile.node`,
  `Dockerfile.python`, `render.yaml`, `fly.toml`).
- Test suite (Phase 0): unit tests for `parse_size`, `parse_rate`, `client_ip` (XFF
  parsing), `harden_cookie`, and `check_basic_auth` (plaintext + argon2 + bad-creds paths);
  and in-process integration tests that drive the real pipeline against a stub upstream —
  401 without auth, 200 with auth, 429 over the limit, 413 on oversized body, 405 on a
  disallowed method, security headers injected, leaky headers stripped, cookie hardened, 502
  when the upstream is down, plus the health/readiness endpoints.
- `edgeguard --hash`: reads a password on stdin and prints an Argon2id PHC hash for
  `auth.users`, so operators don't need a separate argon2 tool.
- Configurable upstream timeout (`validation.upstream_timeout`, default `30s`; `0` disables):
  the proxy bounds the upstream request + body read with a single deadline and returns
  `504 Gateway Timeout` if the upstream stalls, instead of pinning the handler task.
- Library target (`src/lib.rs`) exposing `build_state` / `build_router`, so the binary and
  the tests share one code path rather than a reimplementation.

### Changed
- Restructured the repository into `src/` + `docs/` + `examples/` and rewrote the README as
  a clean, user-facing document (the product/requirements prose moved to `docs/`).
- `/__edgeguard/ready` now probes the upstream — it returns `200` only when the upstream
  accepts a connection, `503` otherwise — instead of always returning `200`.
  `/__edgeguard/health` remains unconditional liveness.
- Made the co-process supervisor cross-platform: Unix keeps full process-group signaling;
  Windows uses a `cmd /C` launch with a best-effort child kill on shutdown.
- `libc` is now a Unix-only dependency (`[target.'cfg(unix)'.dependencies]`).
- `argon2` now enables its `std` feature (provides the getrandom-backed `OsRng` the `--hash`
  helper uses to generate a salt).

### Removed
- `server.fail_mode` config field. It was parsed but never honored, and v0 has no failure
  path for it to govern (the in-memory limiter cannot fail; an unreachable upstream stays a
  `502`). EdgeGuard remains fail-closed; a configurable fail-open returns with the
  distributed limiter (see `docs/ROADMAP.md`, Phase 4). Configs that still set `fail_mode`
  are ignored, not rejected.

### Security
- `X-Forwarded-For` is no longer trusted by default — client identity uses the real peer
  address unless `server.trust_forwarded_for` is enabled (behind a trusted proxy). Prevents
  spoofed per-IP rate limiting and forged access logs.
- Cookie hardening now parses cookie attributes by token instead of substring matching, so
  a value like `session=securetoken` can no longer skip the `Secure` flag.
- The default `auth.users` value is a non-working placeholder rather than a plaintext
  password, so the shipped config can't be copied straight to production.

### Fixed
- The crate now compiles on Windows (previously failed with 7 errors from Unix-only
  `setsid`/`pre_exec`/`libc::kill` usage in the supervisor).
- `parse_size` is now overflow-checked (returns an error instead of silently wrapping).
- The startup readiness wait is skipped when pointing at an external `UPSTREAM`, avoiding a
  needless cold-start stall.
- Added an optional `validation.max_response_body` cap so a huge upstream response can't
  OOM the proxy.

[Unreleased]: https://github.com/lucheeseng827/eggrd/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/lucheeseng827/eggrd/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/lucheeseng827/eggrd/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/lucheeseng827/eggrd/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/lucheeseng827/eggrd/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/lucheeseng827/eggrd/compare/v0.1.5...v0.2.0
[0.1.3]: https://github.com/lucheeseng827/eggrd/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/lucheeseng827/eggrd/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/lucheeseng827/eggrd/releases/tag/v0.1.1
[0.1.0]: https://crates.io/crates/eggrd/0.1.0
