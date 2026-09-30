# Contributing to Spec-Guardian

Thanks for helping improve Spec-Guardian! This project audits repository health,
so we try hard to keep our own repository healthy — your PRs should keep that
green.

## Development setup

Requires **Go >= 1.22**. There are no third-party runtime dependencies by design
(the tool is a single static binary), so `git clone` + `go build` is enough.

```sh
git clone https://github.com/wangzi5151/spec-guardian
cd spec-guardian
go build ./...
go test ./...
go run ./cmd/spec-guardian scan . --offline
```

## Project layout

```
cmd/spec-guardian     CLI entry point (flags, output wiring, exit codes)
internal/scanner      file traversal, Markdown/YAML-ish parsing, heuristics
internal/rules        rule engine, default rule library, YAML config
internal/reporter     JSON, terminal and HTML renderers
internal/gitutil      git metadata + shallow clone + GitHub release lookup
internal/netcheck     link liveness checker
assets/html-template  embedded single-file HTML report
```

## Adding a rule

1. Add metadata + check function in `internal/rules/` (see `defaults.go` and
   `rules_repo.go`).
2. Give it a stable ID (`area.subject.aspect`), a default severity and a
   remediation hint.
3. Document it in `docs/rules.md`.
4. Add a unit test under `internal/rules/`.
5. Keep it **metadata-focused**. If your rule inspects program logic or hunts
   vulnerabilities, it belongs in gosec/semgrep/gitleaks, not here.

## Adding a custom rule without code

Prefer YAML custom rules where possible (see `specguard-rules.example.yml`).
They are the lower-friction, marketplace-friendly extension point.

## Pull request checklist

- [ ] `gofmt -l .` is empty
- [ ] `go vet ./...` passes
- [ ] `go test ./...` passes
- [ ] `spec-guardian scan . --offline` has no new high findings
- [ ] Docs updated (`README.md`, `docs/rules.md`, `docs/zh-CN/`)

## Commit style

Conventional-ish: `feat:`, `fix:`, `docs:`, `test:`, `chore:`. Keep commits
focused.

## Code of conduct

Be kind, assume good faith, and keep discussion technical. Harassment is not
tolerated.
