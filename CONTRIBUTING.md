# Contributing to EdgeGuard

Thanks for your interest in improving EdgeGuard! This document covers how to get set up,
the standards we hold code to, and how to propose changes.

## Getting started

EdgeGuard is a Rust crate (a member of the parent workspace). You'll need a recent stable
Rust toolchain — CI builds against current stable; no MSRV is pinned yet.

```bash
# from the crate directory
cargo build
cargo run -- --config edgeguard.toml --wrap "your-app-start-command"

# or from the workspace root
cargo build -p eggrd
```

To try it end-to-end without an app, run it as a front proxy against any URL:

```bash
PORT=8099 UPSTREAM=https://example.com cargo run
curl -i http://localhost:8099/__edgeguard/health   # -> 200 ok
```

## Before you open a PR

Please make sure the following pass locally:

```bash
cargo fmt --all                      # format
cargo clippy -- -D warnings          # lint (no warnings)
cargo test                           # tests (suite is landing — see docs/ROADMAP.md)
cargo build                          # compiles on your platform
```

EdgeGuard targets **Unix and Windows**. The supervisor (`src/supervisor.rs`) has
platform-specific paths behind `#[cfg(unix)]` / `#[cfg(windows)]`; if you touch it, make
sure it still compiles on both. The Unix path (process groups + POSIX signals) is the
supported one; Windows uses a best-effort child kill.

## Standards

- **Match the surrounding style.** Keep the comment density and naming idioms already in
  the file.
- **Security-by-default.** This is a security tool. New options must default to the safe
  choice; risky behavior is opt-in.
- **Don't claim what isn't there.** If a config field isn't honored yet, say so in the docs
  rather than implying it works.
- **Tests for behavior changes.** Request/response-path changes should come with a unit or
  integration test (see the Phase 0 list in [docs/ROADMAP.md](docs/ROADMAP.md)).

## Commit & PR process

1. Branch off `main`.
2. Keep PRs focused; one logical change per PR where possible.
3. Update `CHANGELOG.md` under `## [Unreleased]` for any user-visible change.
4. Update the relevant doc (`README.md`, `docs/*`, `edgeguard.toml`) when behavior changes.
5. Open the PR against `main`; CI must be green.

## Reporting security issues

Please **do not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) (once published) for private disclosure instructions, or contact
the maintainer directly.

## License

By contributing, you agree that your contributions are licensed under the
[Apache-2.0](LICENSE) license, matching the project.
