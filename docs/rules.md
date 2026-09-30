# Spec-Guardian rule reference

Every rule has a stable ID, a default severity (`high`, `medium`, `low`, `info`)
and a remediation hint. All rules can be disabled or re-graded in
`specguard-rules.yml`.

> Severities are review hints, not verdicts. A `high` finding means “this is
> commonly a hard blocker for strangers trying to use your project”, not “you
> have a vulnerability”.

---

## Repository root files

### repo.license.exists
- **Severity:** high
- **Checks:** a `LICENSE` / `LICENCE` (or `COPYING`) file at the repository root.
- **Fix:** add a license file and reference it from the README.

### repo.license.recognized
- **Severity:** medium
- **Checks:** whether the license text matches a known SPDX license from the
  built-in library (MIT, Apache-2.0, GPL-3.0, BSD-3-Clause, ISC, MPL-2.0, …).
- **Fix:** use an OSI-approved license text verbatim, or add an
  `SPDX-License-Identifier` header.

### repo.license.year
- **Severity:** info
- **Checks:** the copyright year range in the license is plausible (not in the
  future, not inverted). This is an informational hint only.

### repo.license.header_comments
- **Severity:** low (opt-in)
- **Checks:** what share of source files carry a copyright / SPDX header.
- **Enable with:** `settings.header_comment_check: true`. Informational.

### repo.gitignore.exists
- **Severity:** medium
- **Checks:** a `.gitignore` exists at the root.
- **Fix:** add a `.gitignore` with at least the baseline patterns.

### repo.gitignore.risk_patterns
- **Severity:** medium (varies per pattern)
- **Checks:** baseline coverage for `.env`, `*.pem`, `*.key`, `node_modules/`,
  `*.log`, `.DS_Store`, `dist/`.
- **Fix:** add the missing patterns. The report includes a copy-paste snippet.

---

## Documentation

### repo.readme.exists
- **Severity:** high — a README is the entry point for new users.

### repo.readme.quickstart
- **Severity:** high
- **Checks:** a Quick Start / Installation / Usage section containing at least one
  command a reader could try (fenced code block or `$`-style line).

### repo.readme.dependencies
- **Severity:** medium
- **Checks:** minimum dependency/toolchain versions are stated
  (e.g. `Go >= 1.22`, `Node >= 20`, `Python >= 3.11`).

### repo.readme.description
- **Severity:** medium
- **Checks:** a short paragraph near the top describing the project purpose.

### repo.readme.limitations
- **Severity:** info
- **Checks:** a Known Limitations / Notes / Caveats section exists.

### docs.links.dead
- **Severity:** medium
- **Checks:** `http(s)` links in Markdown files respond successfully. Skipped in
  `--offline` mode. Localhost, anchors and placeholder hosts are ignored.

### docs.links.archived
- **Severity:** info
- **Checks:** dead links that have a WayBack Machine snapshot are reported with
  the archived URL as a suggested replacement.

---

## Community files

| Rule | Severity | Checks |
|------|----------|--------|
| `community.contributing` | info | `CONTRIBUTING.md` present |
| `community.codeowners` | info | `CODEOWNERS` present |
| `community.security` | medium | `SECURITY.md` present |
| `community.issue_template` | info | `.github/ISSUE_TEMPLATE/` present |
| `community.pr_template` | info | `.github/PULL_REQUEST_TEMPLATE.md` present |

---

## Build & reproducibility

### build.script.exists
- **Severity:** medium
- **Checks:** a discoverable build definition (`Makefile`, `justfile`, `Taskfile`,
  `meson.build`, `package.json` scripts, `Cargo.toml`, `go.mod`, …).

### build.from_source_documented
- **Severity:** medium
- **Checks:** documentation explains how to rebuild release artifacts from source.

### build.lockfile.exists
- **Severity:** medium
- **Checks:** the lockfile for the detected ecosystem exists (`go.sum`,
  `package-lock.json`, `Cargo.lock`, `poetry.lock`, `uv.lock`, …).
- **Why:** without a lockfile, builds resolve floating versions and are not
  reproducible.

### release.checksums
- **Severity:** medium — GitHub remote mode only
- **Checks:** the latest GitHub release includes a checksum file
  (`SHA256SUMS`, `*.sha256`, `*.blake3`, …).

### release.binaries_uploaded
- **Severity:** low — GitHub remote mode only
- **Checks:** prebuilt binary artifacts are attached to the release.

### release.commit_mapping
- **Severity:** low — GitHub remote mode only
- **Checks:** the release notes map artifacts to a source commit or tag.

---

## Dangerous files & repository hygiene

### security.dangerous_files
- **Severity:** high
- **Checks:** name-based detection of likely secret carriers (`.env`, `.env.*`,
  `*.pem`, `*.key`, `*.pfx`, `*.p12`, `id_rsa`, `*.jks`, …).
- **Note:** **very high false-positive tolerance.** This is a review hint, not a
  security verdict. Use gitleaks for deep scanning.

### security.secret_assignments
- **Severity:** high
- **Checks:** tracked text files for `NAME=value`-style literal secret values,
  ignoring expressions, function calls and placeholders.
- **Note:** coarse heuristic; review before acting.

### security.large_files
- **Severity:** low
- **Checks:** oversized files in the git tree (5 MB default; 1 MB for media and
  archive extensions). Suggests Git LFS or release assets.

---

## Configuring rules

```yaml
# disable a rule
disabled_rules: [community.codeowners]

# change a severity
severity_overrides:
  docs.links.dead: high

# per-rule block form
rules:
  security.large_files:
    enabled: false
  repo.readme.limitations:
    severity: info
```

See [`specguard-rules.example.yml`](../specguard-rules.example.yml) for a full template.

## Custom rules and built-in variables

Custom rules are defined under `custom_rules:` and support two types:

- `regex` — match `pattern` line-by-line in files selected by `files`.
- `path` — flag files whose path matches `pattern` (e.g. `**/.env`).

Common fields: `id`, `severity`, `description`, `message`, `remediation`,
`doc_url`, `files`, `exclude`, `projects`.

`projects` restricts a rule using the detected project type. The engine exposes
these built-in variables to rules:

| Variable | Meaning |
|----------|---------|
| repository root | absolute path of the scanned repository |
| git branch | current branch name |
| project type | `go`, `node`, `python`, `rust` or `any` |

```yaml
custom_rules:
  - id: custom.go_no_todo
    severity: low
    description: No TODO markers in Go sources
    message: Found a TODO marker
    type: regex
    pattern: "TODO"
    projects: [go]
    files: ["**/*.go"]
```

