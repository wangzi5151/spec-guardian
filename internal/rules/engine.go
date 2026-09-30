package rules

import (
	"sort"

	"github.com/wangzi5151/spec-guardian/internal/gitutil"
	"github.com/wangzi5151/spec-guardian/internal/netcheck"
	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

// Context is the shared, read-only input handed to every rule check.
type Context struct {
	Repo        *scanner.Repo
	Config      *Config
	Git         *gitutil.Info
	Branch      string
	ProjectType scanner.ProjectType

	// LinkResults is precomputed by the CLI so that multiple link rules share
	// a single network pass. Keys are the raw URLs.
	LinkResults map[string]netcheck.Result
	// Links is the ordered list of extracted links (with file/line), sharing
	// keys with LinkResults.
	Links []scanner.Link
	// LinkEnabled is false in offline mode, causing link rules to no-op.
	LinkEnabled bool

	// Logf receives optional progress messages.
	Logf func(format string, args ...any)
}

// CheckFunc evaluates a rule against the context and returns findings.
type CheckFunc func(*Context) []scanner.Finding

// RuleMeta is static rule metadata surfaced in reports and documentation.
type RuleMeta struct {
	ID              string
	Title           string
	Description     string
	DefaultSeverity scanner.Severity
	Remediation     string
	DocURL          string
	Category        string
	RemoteOnly      bool
	// OptIn rules are disabled unless explicitly enabled in configuration.
	OptIn bool
}

// Rule pairs metadata with its check implementation.
type Rule struct {
	Meta  RuleMeta
	Check CheckFunc
}

// Engine runs the configured rule set.
type Engine struct {
	rules  []Rule
	Config *Config
}

// NewEngine builds an engine with all built-in rules plus any custom rules
// declared in configuration.
func NewEngine(cfg *Config) *Engine {
	e := &Engine{Config: cfg}
	e.rules = append(e.rules, builtinRules()...)
	e.rules = append(e.rules, customRules(cfg)...)
	return e
}

// Rules returns metadata for all registered rules, sorted by ID.
func (e *Engine) Rules() []RuleMeta {
	out := make([]RuleMeta, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r.Meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Run executes every enabled rule and returns the aggregated, sorted findings.
func (e *Engine) Run(ctx *Context) []scanner.Finding {
	var findings []scanner.Finding
	for _, r := range e.rules {
		if e.Config.Disabled(r.Meta.ID) {
			continue
		}
		if r.Meta.OptIn && !e.optInEnabled(r.Meta.ID) {
			continue
		}
		if r.Meta.RemoteOnly && ctx.Git != nil && !ctx.Git.IsRepo {
			continue
		}
		got := r.Check(ctx)
		for i := range got {
			f := got[i]
			f.RuleID = r.Meta.ID
			f.Severity = e.resolveSeverity(r.Meta, f.Severity)
			if f.Remediation == "" {
				f.Remediation = r.Meta.Remediation
			}
			if f.DocURL == "" {
				f.DocURL = r.Meta.DocURL
			}
			findings = append(findings, f)
		}
	}
	sortFindings(findings)
	return findings
}

func (e *Engine) resolveSeverity(meta RuleMeta, got scanner.Severity) scanner.Severity {
	if ov, ok := e.Config.SeverityOverrides[meta.ID]; ok {
		return ov
	}
	if got == "" {
		return meta.DefaultSeverity
	}
	return got
}

func (e *Engine) optInEnabled(id string) bool {
	switch id {
	case "repo.license.header_comments":
		return e.Config.Settings.HeaderComment
	default:
		return true
	}
}

func sortFindings(fs []scanner.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

// applyRemediationDefaults is used by checks that return multiple findings.
func withRemediation(f scanner.Finding, meta RuleMeta) scanner.Finding {
	if f.Remediation == "" {
		f.Remediation = meta.Remediation
	}
	if f.DocURL == "" {
		f.DocURL = meta.DocURL
	}
	return f
}
