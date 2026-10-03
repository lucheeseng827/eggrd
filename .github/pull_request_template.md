## What this changes

<!-- One logical change. What it does and why; link the issue if there is one. -->

## How it was checked

<!-- The test that covers it, or what you ran. A request/response-path change needs a unit or integration test. -->

## Checklist

- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test --all-targets` pass
- [ ] New options default to the safe choice; risky behaviour is opt-in
- [ ] `CHANGELOG.md` updated under `## [Unreleased]` for a user-visible change
- [ ] Docs (`README.md`, `docs/`, `edgeguard.toml`) updated where behaviour changed, and nothing claims more than the code does
