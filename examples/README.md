# Examples

- [`bad-repo/`](bad-repo/) — deliberately unhealthy repository; triggers many findings.
- [`good-repo/`](good-repo/) — passes the default rule set (offline).
- [`rules/custom-rules.yml`](rules/custom-rules.yml) — a reusable custom rule set.

Try them:

```sh
# Bad: expect high findings and exit code 1
spec-guardian scan examples/bad-repo --offline --no-color

# Good: expect exit code 0 or 2 (info-only)
spec-guardian scan examples/good-repo --offline --no-color

# Custom rule set
spec-guardian scan examples/bad-repo --offline --rules examples/rules/custom-rules.yml
```
