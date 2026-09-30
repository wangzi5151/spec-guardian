package rules

import (
	"fmt"
	"os"
	"strings"

	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

// Config is the fully resolved rule configuration.
type Config struct {
	Version           int
	Settings          Settings
	SeverityOverrides map[string]scanner.Severity
	DisabledRules     []string
	CustomRules       []CustomRule
}

// Settings holds global scanner behavior.
type Settings struct {
	Offline        bool
	FailOn         scanner.Severity
	Exclude        []string
	LinkCheck      LinkCheck
	MaxFileSizeKB  int
	FollowSymlinks bool
	HeaderComment  bool
	CursorlessMode bool
}

// LinkCheck configures link liveness checking.
type LinkCheck struct {
	Enabled        bool
	Concurrency    int
	TimeoutSeconds int
	Allowlist      []string
	Denylist       []string
}

// CustomRule is a user-defined rule from YAML.
type CustomRule struct {
	ID          string
	Description string
	Message     string
	Remediation string
	DocURL      string
	Severity    scanner.Severity
	Type        string // "regex" or "path"
	Pattern     string
	Files       []string
	Exclude     []string
	// Projects optionally restricts the rule to detected project types
	// (go, node, python, rust, any). Empty means all.
	Projects []string
	Enabled  bool
}

// DefaultConfig returns the built-in defaults.
func DefaultConfig() *Config {
	return &Config{
		Version:           1,
		SeverityOverrides: map[string]scanner.Severity{},
		Settings: Settings{
			Offline:       false,
			FailOn:        scanner.SeverityHigh,
			MaxFileSizeKB: 1024,
			LinkCheck: LinkCheck{
				Enabled:        true,
				Concurrency:    8,
				TimeoutSeconds: 10,
			},
		},
	}
}

// DefaultConfigPaths are searched (in order) when no explicit config is given.
var DefaultConfigPaths = []string{
	"specguard-rules.yml",
	"specguard-rules.yaml",
	".specguard/rules.yml",
	".specguard.yml",
	".specguard.yaml",
}

// LoadConfig loads and merges a YAML rule file over the defaults. A missing
// explicit path is an error; a missing default path is not (defaults apply).
func LoadConfig(path string, explicit bool) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !explicit && os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read rules file %q: %w", path, err)
	}
	root, err := parseYAML(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse rules file %q: %w", path, err)
	}
	m, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rules file %q: top level must be a mapping", path)
	}
	if err := cfg.apply(m); err != nil {
		return nil, fmt.Errorf("rules file %q: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) apply(m map[string]any) error {
	if v, ok := m["version"]; ok {
		c.Version = asInt(v, c.Version)
	}
	if v, ok := m["settings"]; ok && v != nil {
		sm, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("settings must be a mapping")
		}
		c.applySettings(sm)
	}
	// Allow settings at top level too, for convenience.
	c.applySettings(m)

	if v, ok := m["disabled_rules"]; ok {
		c.DisabledRules = append(c.DisabledRules, asStringSlice(v)...)
	}
	if v, ok := m["disable"]; ok {
		c.DisabledRules = append(c.DisabledRules, asStringSlice(v)...)
	}
	if v, ok := m["rules"]; ok && v != nil {
		rm, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("rules must be a mapping of ruleId to settings")
		}
		for id, rv := range rm {
			rmm, ok := rv.(map[string]any)
			if !ok {
				// Support the shorthand "rules: { id: false }".
				if !asBool(rv, true) {
					c.DisabledRules = append(c.DisabledRules, id)
				}
				continue
			}
			if e, ok := rmm["enabled"]; ok && !asBool(e, true) {
				c.DisabledRules = append(c.DisabledRules, id)
			}
			if s, ok := rmm["severity"]; ok {
				if sev, ok := scanner.ParseSeverity(asString(s)); ok {
					c.SeverityOverrides[id] = sev
				}
			}
		}
	}
	if v, ok := m["severity_overrides"]; ok {
		if om, ok := v.(map[string]any); ok {
			for k, sv := range om {
				if sev, ok := scanner.ParseSeverity(asString(sv)); ok {
					c.SeverityOverrides[k] = sev
				}
			}
		}
	}
	if v, ok := m["custom_rules"]; ok && v != nil {
		list, ok := v.([]any)
		if !ok {
			return fmt.Errorf("custom_rules must be a sequence")
		}
		for idx, item := range list {
			im, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("custom_rules[%d] must be a mapping", idx)
			}
			cr, err := parseCustomRule(im)
			if err != nil {
				return fmt.Errorf("custom_rules[%d]: %w", idx, err)
			}
			c.CustomRules = append(c.CustomRules, cr)
		}
	}
	return nil
}

func (c *Config) applySettings(m map[string]any) {
	if v, ok := m["offline"]; ok {
		c.Settings.Offline = asBool(v, c.Settings.Offline)
	}
	if v, ok := m["fail_on"]; ok {
		if sev, ok := scanner.ParseSeverity(asString(v)); ok {
			c.Settings.FailOn = sev
		}
	}
	if v, ok := m["exclude"]; ok {
		c.Settings.Exclude = append(c.Settings.Exclude, asStringSlice(v)...)
	}
	if v, ok := m["max_file_size_kb"]; ok {
		c.Settings.MaxFileSizeKB = asInt(v, c.Settings.MaxFileSizeKB)
	}
	if v, ok := m["follow_symlinks"]; ok {
		c.Settings.FollowSymlinks = asBool(v, c.Settings.FollowSymlinks)
	}
	if v, ok := m["header_comment_check"]; ok {
		c.Settings.HeaderComment = asBool(v, c.Settings.HeaderComment)
	}
	if v, ok := m["link_check"]; ok {
		if lm, ok := v.(map[string]any); ok {
			if e, ok := lm["enabled"]; ok {
				c.Settings.LinkCheck.Enabled = asBool(e, c.Settings.LinkCheck.Enabled)
			}
			if e, ok := lm["concurrency"]; ok {
				c.Settings.LinkCheck.Concurrency = asInt(e, c.Settings.LinkCheck.Concurrency)
			}
			if e, ok := lm["timeout_seconds"]; ok {
				c.Settings.LinkCheck.TimeoutSeconds = asInt(e, c.Settings.LinkCheck.TimeoutSeconds)
			}
			if e, ok := lm["allowlist"]; ok {
				c.Settings.LinkCheck.Allowlist = asStringSlice(e)
			}
			if e, ok := lm["denylist"]; ok {
				c.Settings.LinkCheck.Denylist = asStringSlice(e)
			}
		}
	}
}

func parseCustomRule(m map[string]any) (CustomRule, error) {
	cr := CustomRule{Enabled: true, Severity: scanner.SeverityLow, Type: "regex"}
	if v, ok := m["id"]; ok {
		cr.ID = asString(v)
	}
	if cr.ID == "" {
		return cr, fmt.Errorf("missing required field \"id\"")
	}
	if v, ok := m["enabled"]; ok {
		cr.Enabled = asBool(v, true)
	}
	if v, ok := m["severity"]; ok {
		sev, ok := scanner.ParseSeverity(asString(v))
		if !ok {
			return cr, fmt.Errorf("invalid severity %q", asString(v))
		}
		cr.Severity = sev
	}
	if v, ok := m["description"]; ok {
		cr.Description = asString(v)
	}
	if v, ok := m["message"]; ok {
		cr.Message = asString(v)
	}
	if v, ok := m["remediation"]; ok {
		cr.Remediation = asString(v)
	}
	if v, ok := m["doc_url"]; ok {
		cr.DocURL = asString(v)
	}
	if v, ok := m["type"]; ok {
		cr.Type = asString(v)
	}
	if v, ok := m["pattern"]; ok {
		cr.Pattern = asString(v)
	}
	if v, ok := m["files"]; ok {
		cr.Files = asStringSlice(v)
	}
	if v, ok := m["exclude"]; ok {
		cr.Exclude = asStringSlice(v)
	}
	if v, ok := m["projects"]; ok {
		cr.Projects = asStringSlice(v)
	}
	if cr.Type == "regex" && cr.Pattern == "" {
		return cr, fmt.Errorf("regex rule requires a \"pattern\"")
	}
	return cr, nil
}

// Disabled reports whether a rule is disabled by configuration.
func (c *Config) Disabled(id string) bool {
	for _, d := range c.DisabledRules {
		if strings.EqualFold(d, id) {
			return true
		}
	}
	return false
}

// EffectiveSeverity applies any configured override to a default severity.
func (c *Config) EffectiveSeverity(id string, def scanner.Severity) scanner.Severity {
	if s, ok := c.SeverityOverrides[id]; ok {
		return s
	}
	return def
}

// --- conversion helpers ---

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%g", t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func asBool(v any, def bool) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "yes", "on", "1":
			return true
		case "false", "no", "off", "0":
			return false
		}
	}
	return def
}

func asInt(v any, def int) int {
	switch t := v.(type) {
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err == nil {
			return n
		}
	}
	return def
}

func asStringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s := asString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		if strings.Contains(t, ",") {
			var out []string
			for _, p := range strings.Split(t, ",") {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}
			return out
		}
		return []string{t}
	default:
		return nil
	}
}
