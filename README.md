# Spec-Guardian

**Spec-Guardian — Open-Source Repository Health Auditor. Not a Code Linter.**

[![CI](https://github.com/wangzi5151/spec-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/wangzi5151/spec-guardian/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/wangzi5151/spec-guardian?include_prereleases)](https://github.com/wangzi5151/spec-guardian/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/wangzi5151/spec-guardian.svg)](https://pkg.go.dev/github.com/wangzi5151/spec-guardian)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Spec-Guardian audits **repository metadata and engineering health** — the things
that decide whether a stranger can use, rebuild and trust your project. It looks
at your repository *as an artifact of open-source engineering*, not at your
program logic.

> Think of it as a health check for the *bookkeeping* of a repository: license,
> docs, build reproducibility, release hygiene and obvious secret mistakes.

---

## ⚡ Quick Start

```sh
# macOS / Linux (single static binary, no runtime dependencies)
curl -fsSL https://raw.githubusercontent.com/wangzi5151/spec-guardian/main/install.sh | sh -s -- -b /usr/local/bin

# Windows
winget install wangzi5151.spec-guardian

# From source (Go >= 1.22; 1.23+ on macOS)
go install github.com/wangzi5151/spec-guardian/cmd/spec-guardian@latest
```

Then scan any repository:

```sh
spec-guardian scan .                 # scan the current directory
spec-guardian scan /path/to/repo     # scan a local path
spec-guardian scan --repo https://github.com/owner/repo   # shallow clone & scan
```

Prefer a visual report?

```sh
spec-guardian scan . --format html
open specguard-report.html
```

---

## What it does

- Audits **repository root files**: `LICENSE`, `.gitignore`, `README`, community files.
- Checks **README baselines**: quick-start, minimum dependency versions, purpose, limitations.
- Scans **documentation links** for dead `http(s)` URLs (with WayBack Machine fallback).
- Audits **build & release reproducibility** by static evidence only: build scripts,
  lockfiles, from-source instructions, release checksums and binary assets.
- Detects **obvious dangerous files** (`.env`, `*.pem`, `*.key`, `id_rsa`, …) by name
  and coarse entropy heuristics.
- Ships a **configurable YAML rule engine** (disable rules, change severity, add your own).
- Emits **JSON, colored terminal and single-file HTML** reports, plus an optional
  `--fix-preview` patch you can review (never applied automatically).
- Runs as a **GitHub Action** out of the box, uploading the HTML report as an artifact.

## What it does **NOT** do

- ❌ It does **not** lint source code, check syntax, or report style issues.
- ❌ It does **not** perform security static analysis (SAST). Use **gosec**, **semgrep**, **CodeQL**.
- ❌ It does **not** do deep secret scanning. Use **gitleaks** / **trufflehog**. We only warn
  on obvious, name-based mistakes.
- ❌ It does **not** force a single “correct” open-source style. Every rule is toggleable.
- ❌ It never **edits, commits or pushes** to your repository.
- ❌ It is **not** a SaaS and needs no server. The binary runs fully offline (`--offline`).

---

## Usage

```sh
# Local scan with all three reports
spec-guardian scan . --format all --out-dir ./report

# Offline mode (no network, links are extracted but not probed)
spec-guardian scan . --offline

# Custom rule set
spec-guardian scan . --rules specguard-rules.yml

# Fail CI from medium severity up
spec-guardian scan . --fail-on medium

# Preview suggested textual fixes as a patch (nothing is modified)
spec-guardian scan . --fix-preview fixes.patch

# Export the current rule set as a reusable template
spec-guardian export-rules --out specguard-rules.yml
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No blocking findings — all high/medium checks pass |
| `1`  | At least one **high** severity finding (fails a PR by default) |
| `2`  | Only `medium` / `low` / `info` findings — non-blocking |
| `3`  | Runtime error (bad flags, unreadable path, network failure in strict mode) |

The threshold is configurable with `--fail-on high|medium|low|none`.

### GitHub Action

```yaml
name: spec-guardian
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: wangzi5151/spec-guardian@v0.1
        with:
          rules: specguard-rules.yml      # optional
          fail-on: high                   # optional
          format: all                     # optional
```

The action writes a concise summary to the workflow step summary and uploads the
full HTML report as a build artifact named `spec-guardian-report`.

---

## Rule reference

Rules use stable IDs in the form `area.subject.aspect`, e.g.
`repo.license.exists` or `build.lockfile.exists`.

- Full rule catalogue: [`docs/rules.md`](docs/rules.md)
- Chinese docs: [`docs/zh-CN/`](docs/zh-CN/)

Run `spec-guardian rules` to list every rule ID, severity and title.

---

## Configuration

Spec-Guardian reads an optional `specguard-rules.yml` from the scanned repo root
(override with `--rules`). See [`specguard-rules.example.yml`](specguard-rules.example.yml).

```yaml
version: 1

settings:
  offline: false
  fail_on: high
  exclude:
    - vendor/**
    - node_modules/**
  link_check:
    enabled: true
    concurrency: 8
    timeout_seconds: 10

# Disable rules or change their severity.
rules:
  repo.readme.limitations:
    severity: info
  security.large_files:
    enabled: false

severity_overrides:
  docs.links.dead: high

disabled_rules:
  - community.codeowners

custom_rules:
  - id: custom.no_todo_in_docs
    severity: low
    description: No TODO markers in documentation
    message: Found a TODO marker
    remediation: Resolve the TODO or convert it to an issue.
    type: regex
    pattern: "TODO"
    files: ["**/*.md"]
```

Custom rules are the extension point for the eventual **rule marketplace**:
third parties can publish YAML rule sets without changing the binary.

---

## FAQ

**Why not scan for code vulnerabilities?**
Because that is a different, much harder problem with mature dedicated tools.
Spec-Guardian stays deliberately narrow so its findings are trustworthy and
low-noise. Deep secret scanning is explicitly delegated to gitleaks.

**Will this replace my linters?**
No. It complements them. Linters reason about *code*; Spec-Guardian reasons about
the *repository as an open-source deliverable*.

**Does it modify my files?**
Never by default. `--fix-preview` writes a `.patch` **file** for you to review and
apply manually; the tool never edits the working tree, commits or pushes.

**Do I need Docker?**
No. The released binaries are static, dependency-free single files.

---

## Known Limitations

**Product limitations**

- Heuristic rules (especially `security.*`) trade precision for recall and will
  produce false positives. Treat their findings as review prompts.
- Release checks require network access and a GitHub-hosted remote; they are
  skipped in `--offline` mode or when no token/rate budget is available.
- Language baselines currently focus on Go, Node, Python and Rust; other
  ecosystems get the generic checks only.
- Markdown link checking uses HTTP status only and does not validate content.
- The `--repo`/release/checksum features depend on `git` and on outbound HTTPS
  to `github.com` and `api.github.com`; air-gapped environments should use
  `--offline` and a local path.
- 32-bit (`386`) binaries are best-effort optional targets.
- On macOS arm64, **Go 1.23+ is required** to build or test: Go 1.22's linker
  omits the `LC_UUID` load command and dyld aborts with `signal: abort trap`
  (an upstream bug fixed in Go 1.23). Linux and Windows work with Go 1.22.

**Project status (v0.1, pre-1.0)**

This is an early release. Be aware of what has and has not been verified:

- ✅ Locally verified: build, `go vet`, `go test ./...`, self-scan, the
  good/bad example repositories, custom rules, all three report formats,
  `--fix-preview`, `export-rules`, and `--summary`.
- ✅ Cross-compilation verified for `linux/amd64`, `linux/arm64`, `linux/386`
  and `windows/amd64`; other targets are produced by CI but were not each run
  here.
- ⚠️ Implemented but **not yet exercised end-to-end** in this environment
  (no outbound network): remote shallow clone (`--repo`), live link checking
  and WayBack lookups, GitHub Release checksum/binary/commit-mapping checks,
  and the GitHub Action itself.
- ⚠️ No released binaries exist yet, so `install.sh`, the `winget` package and
  the Action's binary-download path are untested until the first tagged release.
- ℹ️ The module path, badges, `action.yml`, `install.sh` and doc links are
  configured for `github.com/wangzi5151/spec-guardian`; update them if you fork
  the project elsewhere.
- ⚠️ Release artifact hashing currently relies on `sha256sum` in CI.

---

## Contributing

Contributions are welcome — especially new rule sets and ecosystem baselines.
See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).

## Roadmap

- **v0.1 — MVP**: baseline scanning, three report formats, working GitHub Action.
- **v0.2**: better custom rules, smarter link archive suggestions, more language baselines.
- **v0.3**: diff-aware PR scanning mode, official rule contribution process.
- **v1.0**: stable API and production-ready baseline.

## License

[MIT](LICENSE)
