package rules

import (
	"regexp"
	"strings"

	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

// customRules converts configured custom rules into executable engine rules.
func customRules(cfg *Config) []Rule {
	var out []Rule
	for _, cr := range cfg.CustomRules {
		if !cr.Enabled {
			continue
		}
		cr := cr
		var re *regexp.Regexp
		if cr.Type == "regex" {
			compiled, err := regexp.Compile(cr.Pattern)
			if err != nil {
				// Invalid custom regex is reported at load validation time; skip
				// here to keep the engine usable.
				continue
			}
			re = compiled
		}
		out = append(out, Rule{
			Meta: RuleMeta{
				ID:              cr.ID,
				Title:           firstNonEmpty(cr.Description, cr.ID),
				Description:     cr.Description,
				DefaultSeverity: cr.Severity,
				Remediation:     cr.Remediation,
				DocURL:          cr.DocURL,
				Category:        "custom",
			},
			Check: func(ctx *Context) []scanner.Finding {
				return runCustomRule(ctx, cr, re)
			},
		})
	}
	return out
}

func runCustomRule(ctx *Context, cr CustomRule, re *regexp.Regexp) []scanner.Finding {
	if !customProjectMatches(cr, ctx.ProjectType) {
		return nil
	}
	msg := cr.Message
	if msg == "" {
		msg = firstNonEmpty(cr.Description, "Custom rule "+cr.ID+" matched.")
	}
	var findings []scanner.Finding
	const capLimit = 200

	for _, f := range ctx.Repo.Files {
		if !customFileMatches(cr, f.Path) {
			continue
		}
		if cr.Type == "path" {
			findings = append(findings, scanner.Finding{File: f.Path, Message: msg})
			if len(findings) >= capLimit {
				break
			}
			continue
		}
		if re == nil || f.Size > 1024*1024 {
			continue
		}
		content, ok := ctx.Repo.ReadFileString(f.Path, 1024*1024)
		if !ok {
			continue
		}
		lineNo := 0
		for _, line := range strings.Split(content, "\n") {
			lineNo++
			if re.MatchString(line) {
				findings = append(findings, scanner.Finding{File: f.Path, Line: lineNo, Message: msg})
				if len(findings) >= capLimit {
					return findings
				}
			}
		}
	}
	return findings
}

func customProjectMatches(cr CustomRule, pt scanner.ProjectType) bool {
	if len(cr.Projects) == 0 {
		return true
	}
	for _, p := range cr.Projects {
		lp := strings.ToLower(strings.TrimSpace(p))
		if lp == "any" || lp == "all" || lp == string(pt) {
			return true
		}
	}
	return false
}

func customFileMatches(cr CustomRule, p string) bool {
	for _, ex := range cr.Exclude {
		if scanner.MatchPath(ex, p) {
			return false
		}
	}
	if cr.Type == "path" {
		if cr.Pattern == "" || !scanner.MatchPath(cr.Pattern, p) {
			return false
		}
	}
	if len(cr.Files) == 0 {
		return true
	}
	for _, pat := range cr.Files {
		if scanner.MatchPath(pat, p) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ValidateCustomRules ensures custom rule regexes compile. It is called by the
// CLI so users get a clear error for bad configuration.
func ValidateCustomRules(cfg *Config) error {
	for _, cr := range cfg.CustomRules {
		if cr.Type == "regex" {
			if _, err := regexp.Compile(cr.Pattern); err != nil {
				return &customRuleError{ID: cr.ID, err: err}
			}
		}
	}
	return nil
}

type customRuleError struct {
	ID  string
	err error
}

func (e *customRuleError) Error() string {
	return "custom rule " + e.ID + ": invalid regex: " + e.err.Error()
}
