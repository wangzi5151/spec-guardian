package scanner

import (
	"regexp"
	"strings"
)

// GitignorePattern is a single meaningful line from a .gitignore file.
type GitignorePattern struct {
	Line    int
	Raw     string
	Pattern string
	Negated bool
}

// GitignoreRisk describes a recommended baseline pattern.
type GitignoreRisk struct {
	Pattern  string
	Label    string
	Severity Severity
	Reason   string
}

// BaselineGitignoreRisks is the minimal safety baseline: submission of these
// artifacts is a common cause of leaked secrets or bloated repositories.
var BaselineGitignoreRisks = []GitignoreRisk{
	{Pattern: ".env", Label: ".env", Severity: SeverityHigh, Reason: "environment files frequently contain secrets"},
	{Pattern: "*.pem", Label: "*.pem", Severity: SeverityHigh, Reason: "PEM files are private keys or certificates"},
	{Pattern: "*.key", Label: "*.key", Severity: SeverityHigh, Reason: "key files are usually private material"},
	{Pattern: "node_modules/", Label: "node_modules", Severity: SeverityMedium, Reason: "dependency trees should not be committed"},
	{Pattern: "*.log", Label: "*.log", Severity: SeverityLow, Reason: "log files are build/run artifacts"},
	{Pattern: ".DS_Store", Label: ".DS_Store", Severity: SeverityLow, Reason: "macOS metadata noise"},
	{Pattern: "dist/", Label: "dist/", Severity: SeverityLow, Reason: "build output is reproducible, not source"},
}

// ParseGitignore parses the meaningful patterns of a .gitignore file.
func ParseGitignore(content string) []GitignorePattern {
	var out []GitignorePattern
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := GitignorePattern{Line: i + 1, Raw: raw}
		if strings.HasPrefix(line, "!") {
			p.Negated = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "!"))
		}
		p.Pattern = line
		out = append(out, p)
	}
	return out
}

// Covered reports whether pattern p (a gitignore entry) plausibly covers the
// risk target. Matching is intentionally loose because gitignore semantics are
// nuanced and we only warn.
func (p GitignorePattern) Covered(target string) bool {
	t := strings.Trim(target, "/")
	pat := strings.Trim(p.Pattern, "/")
	if pat == "" {
		return false
	}
	if pat == t {
		return true
	}
	// *.ext style
	if strings.HasPrefix(pat, "*.") {
		return strings.HasSuffix(t, strings.TrimPrefix(pat, "*"))
	}
	// bare name matches basename
	if !strings.Contains(pat, "/") && !strings.ContainsAny(pat, "*?") {
		return pat == t || strings.HasSuffix(t, "/"+pat)
	}
	if matchSegments(strings.Split(pat, "/"), strings.Split(t, "/")) {
		return true
	}
	return false
}

// MissingGitignoreRisks returns the baseline risks not covered by the patterns.
func MissingGitignoreRisks(patterns []GitignorePattern) []GitignoreRisk {
	var missing []GitignoreRisk
	for _, risk := range BaselineGitignoreRisks {
		covered := false
		for _, p := range patterns {
			if p.Negated {
				continue
			}
			if p.Covered(risk.Pattern) {
				covered = true
				break
			}
		}
		if !covered {
			missing = append(missing, risk)
		}
	}
	return missing
}

// GitignoreSuggestion builds a copy-pasteable .gitignore snippet for the
// supplied risks.
func GitignoreSuggestion(risks []GitignoreRisk) string {
	var b strings.Builder
	b.WriteString("# Added by Spec-Guardian (review before committing)\n")
	for _, r := range risks {
		b.WriteString(r.Pattern)
		b.WriteString("\n")
	}
	return b.String()
}

var reSecretKey = regexp.MustCompile(`(?i)^[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDENTIAL)[A-Z0-9_]*$`)

// LooksLikeSecretAssignment reports whether a line looks like an assigned
// secret value (e.g. API_KEY=abcdef...). It is a coarse heuristic with a very
// high false-positive tolerance: it deliberately favors suggesting a review
// over staying silent. Assignments whose right-hand side is an expression,
// function call or variable reference are ignored.
func LooksLikeSecretAssignment(line string) (string, bool) {
	s := strings.TrimSpace(line)
	// Strip a trailing inline comment for NAME=value # comment style.
	if idx := strings.Index(s, " #"); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	i := strings.IndexByte(s, '=')
	if i < 0 {
		return "", false
	}
	// Reject compound operators: ==, :=, !=, <=, >=.
	if i+1 < len(s) && s[i+1] == '=' {
		return "", false
	}
	if i > 0 && strings.ContainsRune(":!<>", rune(s[i-1])) {
		return "", false
	}
	key := strings.TrimSpace(s[:i])
	val := strings.TrimSpace(s[i+1:])
	key = strings.TrimPrefix(key, "export ")
	key = strings.TrimSpace(key)
	if j := strings.LastIndexAny(key, " \t"); j >= 0 {
		key = key[j+1:]
	}
	key = strings.Trim(key, `"'`)
	if !reSecretKey.MatchString(key) {
		return "", false
	}
	val = strings.Trim(val, `"'`+"`")
	if len(val) < 12 {
		return "", false
	}
	if isPlaceholder(val) || isNonLiteralValue(val) {
		return "", false
	}
	return key, true
}

var (
	reDottedRef = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)
	reConstName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

func isNonLiteralValue(v string) bool {
	if strings.ContainsAny(v, "()[]{};") {
		return true
	}
	if strings.HasPrefix(v, "$") || strings.HasPrefix(v, "%") || strings.HasPrefix(v, "${") {
		return true
	}
	if strings.Contains(v, "process.env") || strings.Contains(v, "os.Getenv") ||
		strings.Contains(v, "getenv") || strings.Contains(v, "System.getenv") {
		return true
	}
	if strings.ContainsAny(v, " /\\") {
		return true
	}
	// Variable/reference chains such as var.secret_key, local.x, data.a.b.
	if reDottedRef.MatchString(v) {
		return true
	}
	// ALL_CAPS constants such as "ALICLOUD_SECRET_KEY" are names, not secrets.
	if reConstName.MatchString(v) {
		return true
	}
	return false
}

func isPlaceholder(v string) bool {
	lv := strings.ToLower(v)
	for _, p := range []string{"changeme", "your_", "your-", "example", "placeholder", "xxxx", "<", "${", "todo", "dummy", "test"} {
		if strings.Contains(lv, p) {
			return true
		}
	}
	return false
}
