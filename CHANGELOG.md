# Changelog

All notable changes to Spec-Guardian are documented here.

## Unreleased

### Added

- Tests covering `settings.fail_on` precedence, `fail_on: none`, and invalid
  `--timeout` / `--concurrency` values.
- This changelog.

### Fixed

- `settings.fail_on` now supplies the default exit threshold. An explicit
  `--fail-on` flag still wins, while `fail_on: none` disables failure gating.
- `--timeout` and `--concurrency` now reject non-integer values with a usage
  error instead of silently falling back to the default.

### Changed

- CI self-scan is now a real gate: it runs with `--fail-on high` and no longer
  ignores the exit status with `|| true`.
- CI/release use Go 1.23 for macOS builds to avoid the Go 1.22 arm64 linker
  `LC_UUID` bug; Linux and Windows continue to test on Go 1.22 and 1.23.
- GitHub Actions updated to `actions/checkout@v5`.
- README and Chinese README document threshold precedence and integer flag
  validation.
