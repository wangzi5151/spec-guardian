# Security Policy

## Supported versions

Spec-Guardian is pre-1.0. Security fixes are applied to the latest release and
`main`.

| Version | Supported |
|---------|-----------|
| latest  | ✅ |
| older   | ❌ |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

- Use GitHub's private vulnerability reporting (Security → Report a vulnerability), or
- Email the maintainers at `security@example.com` (replace with your address).

Include: affected version, a minimal reproduction, impact, and any suggested fix.
We aim to acknowledge within 72 hours and to ship a fix or mitigation promptly.

## Scope

Spec-Guardian is a **metadata auditor**, not a scanner. In-scope issues include:

- the tool modifying files it should not,
- path traversal or arbitrary file reads outside the scanned repository,
- SSRF or resource exhaustion in the link checker,
- unexpected network access in `--offline` mode.

Out of scope:

- false positives/negatives from heuristic rules (report them as normal bugs),
- findings the tool does not make about *your* code security.

## Our own practices

Releases are built with `CGO_ENABLED=0` and publish `SHA256SUMS`. The link
checker caps concurrency globally and per host and never probes localhost.
