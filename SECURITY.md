# Security Policy

EdgeGuard is a security tool — it sits in front of other people's apps. Vulnerabilities
here can expose every app behind it, so we take reports seriously.

## Supported versions

EdgeGuard is pre-1.0 (`0.x`). Only the latest released version receives security fixes.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately via one of:

- GitHub's [private vulnerability reporting](https://github.com/lucheeseng827/eggrd/security/advisories/new)
  (preferred), or
- email the maintainer directly.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal config + request is ideal),
- the EdgeGuard version / commit, and
- any suggested remediation.

## What to expect

- Acknowledgement of your report as soon as practical.
- An assessment and, if confirmed, a fix shipped as a patch release.
- Credit in the release notes / advisory, unless you prefer to remain anonymous.

## Scope notes

- The `v0` Basic-auth plaintext mode is a documented dev convenience, not a vulnerability —
  use `$argon2` hashes for anything exposed.
- The Windows supervisor path is best-effort by design (no POSIX signals); the supported
  production path is Unix.
