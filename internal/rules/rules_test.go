package rules

import (
	"testing"

	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

func TestParseYAMLSubset(t *testing.T) {
	src := `
version: 1
settings:
  offline: true
  link_check:
    concurrency: 4
    timeout_seconds: 5
exclude:
  - vendor/**
  - node_modules/**
custom_rules:
  - id: x.one
    severity: medium
    files: ["**/*.md", "**/*.go"]
`
	root, err := parseYAML(src)
	if err != nil {
		t.Fatal(err)
	}
	m := root.(map[string]any)
	if asInt(m["version"], 0) != 1 {
		t.Errorf("version = %v", m["version"])
	}
	settings := m["settings"].(map[string]any)
	if !asBool(settings["offline"], false) {
		t.Errorf("offline should be true")
	}
	lc := settings["link_check"].(map[string]any)
	if asInt(lc["concurrency"], 0) != 4 {
		t.Errorf("concurrency = %v", lc["concurrency"])
	}
	ex := asStringSlice(m["exclude"])
	if len(ex) != 2 || ex[0] != "vendor/**" {
		t.Errorf("exclude = %v", ex)
	}
	cr := m["custom_rules"].([]any)[0].(map[string]any)
	files := asStringSlice(cr["files"])
	if len(files) != 2 {
		t.Errorf("files = %v", files)
	}
}

func TestConfigOverrides(t *testing.T) {
	cfg := DefaultConfig()
	m := map[string]any{
		"rules": map[string]any{
			"repo.readme.limitations": map[string]any{"severity": "high"},
			"security.large_files":    map[string]any{"enabled": false},
		},
		"disabled_rules": []any{"community.codeowners"},
	}
	if err := cfg.apply(m); err != nil {
		t.Fatal(err)
	}
	if cfg.EffectiveSeverity("repo.readme.limitations", scanner.SeverityInfo) != scanner.SeverityHigh {
		t.Errorf("severity override not applied")
	}
	if !cfg.Disabled("security.large_files") {
		t.Errorf("security.large_files should be disabled")
	}
	if !cfg.Disabled("community.codeowners") {
		t.Errorf("community.codeowners should be disabled")
	}
}

func engineResult(t *testing.T, dir string, cfg *Config) []scanner.Finding {
	t.Helper()
	repo, err := scanner.Index(dir, scanner.IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := &Context{
		Repo:        repo,
		Config:      cfg,
		ProjectType: repo.DetectProjectType(),
	}
	return NewEngine(cfg).Run(ctx)
}

func hasFinding(fs []scanner.Finding, ruleID string, sev scanner.Severity) bool {
	for _, f := range fs {
		if f.RuleID == ruleID && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestEngineOnBadRepo(t *testing.T) {
	cfg := DefaultConfig()
	fs := engineResult(t, "../../examples/bad-repo", cfg)

	if !hasFinding(fs, "repo.license.exists", scanner.SeverityHigh) {
		t.Errorf("expected missing license high finding; got %v", ids(fs))
	}
	if !hasFinding(fs, "security.dangerous_files", scanner.SeverityHigh) {
		t.Errorf("expected dangerous file finding for .env/.pem; got %v", ids(fs))
	}
	if !hasFinding(fs, "repo.gitignore.exists", scanner.SeverityMedium) {
		t.Errorf("expected missing .gitignore finding; got %v", ids(fs))
	}
}

func TestEngineOnGoodRepo(t *testing.T) {
	cfg := DefaultConfig()
	fs := engineResult(t, "../../examples/good-repo", cfg)
	for _, f := range fs {
		if f.Severity == scanner.SeverityHigh {
			t.Errorf("unexpected high finding in good repo: %s %s", f.RuleID, f.Message)
		}
	}
}

func TestCustomRegexRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomRules = []CustomRule{{
		ID: "custom.no_todo", Severity: scanner.SeverityMedium, Type: "regex",
		Pattern: "TODO", Files: []string{"**/*.go", "**/*.md"}, Message: "TODO found", Enabled: true,
	}}
	fs := engineResult(t, "../../examples/bad-repo", cfg)
	if !hasFinding(fs, "custom.no_todo", scanner.SeverityMedium) {
		t.Errorf("expected custom TODO finding; got %v", ids(fs))
	}
}

func TestCustomPathRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomRules = []CustomRule{{
		ID: "custom.no_env", Severity: scanner.SeverityHigh, Type: "path",
		Pattern: "**/.env", Message: "env committed", Enabled: true,
	}}
	fs := engineResult(t, "../../examples/bad-repo", cfg)
	count := 0
	for _, f := range fs {
		if f.RuleID == "custom.no_env" {
			count++
			if f.File != ".env" {
				t.Errorf("path rule matched wrong file: %s", f.File)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly one .env path finding, got %d", count)
	}
}

func TestCustomRuleProjectScope(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomRules = []CustomRule{{
		ID: "custom.only_rust", Severity: scanner.SeverityInfo, Type: "regex",
		Pattern: "package", Files: []string{"**/*.go"}, Projects: []string{"rust"}, Enabled: true,
	}}
	fs := engineResult(t, "../../examples/bad-repo", cfg)
	for _, f := range fs {
		if f.RuleID == "custom.only_rust" {
			t.Fatalf("rule scoped to rust ran on a non-rust repo")
		}
	}
}

func TestDisabledRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DisabledRules = []string{"repo.license.exists"}
	fs := engineResult(t, "../../examples/bad-repo", cfg)
	if hasFinding(fs, "repo.license.exists", scanner.SeverityHigh) {
		t.Errorf("disabled rule still produced a finding")
	}
}

func TestValidateCustomRulesRejectsBadRegex(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomRules = []CustomRule{{ID: "bad", Type: "regex", Pattern: "("}}
	if err := ValidateCustomRules(cfg); err == nil {
		t.Fatalf("expected invalid regex error")
	}
}

func ids(fs []scanner.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}
