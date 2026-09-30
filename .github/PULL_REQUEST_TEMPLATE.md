# Pull Request

## Summary

<!-- What does this PR change and why? -->

## Type

- [ ] Bug fix
- [ ] New rule
- [ ] Report/output change
- [ ] Documentation
- [ ] CI / tooling

## Checklist

- [ ] `gofmt -l .` is empty
- [ ] `go vet ./...` passes
- [ ] `go test ./...` passes
- [ ] `spec-guardian scan . --offline` has no new high findings
- [ ] Documents updated if behavior changed
- [ ] This change stays within metadata auditing (no source-code or vulnerability scanning)

## Related issues

<!-- e.g. Closes #12 -->
