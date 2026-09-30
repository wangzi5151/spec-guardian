package reporter

import (
	"time"

	"github.com/wangzi5151/spec-guardian/internal/rules"
	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

// Summary holds finding counts by severity.
type Summary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// Report is the complete audit result, ready for any renderer.
type Report struct {
	Tool        string            `json:"tool"`
	Version     string            `json:"version"`
	GeneratedAt time.Time         `json:"generatedAt"`
	Root        string            `json:"root"`
	Branch      string            `json:"branch,omitempty"`
	Commit      string            `json:"commit,omitempty"`
	Origin      string            `json:"origin,omitempty"`
	ProjectType string            `json:"projectType"`
	Offline     bool              `json:"offline"`
	FileCount   int               `json:"fileCount"`
	Summary     Summary           `json:"summary"`
	Findings    []scanner.Finding `json:"findings"`
	Rules       []rules.RuleMeta  `json:"rules"`
}

// NewReport builds a report and computes the summary.
func NewReport(findings []scanner.Finding, ruleMetas []rules.RuleMeta) *Report {
	if findings == nil {
		findings = []scanner.Finding{}
	}
	if ruleMetas == nil {
		ruleMetas = []rules.RuleMeta{}
	}
	r := &Report{
		Tool:        "spec-guardian",
		Version:     "dev",
		GeneratedAt: time.Now().UTC(),
		Findings:    findings,
		Rules:       ruleMetas,
	}
	r.Summary = Summarize(findings)
	return r
}

// Summarize counts findings by severity.
func Summarize(findings []scanner.Finding) Summary {
	s := Summary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case scanner.SeverityHigh:
			s.High++
		case scanner.SeverityMedium:
			s.Medium++
		case scanner.SeverityLow:
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}

// ExitCode computes the process exit code from findings and a failure
// threshold.
//
//	0 -> no blocking findings
//	1 -> at least one finding at or above the failure threshold
//	2 -> only non-blocking findings (low/info)
//	3 -> reserved for runtime errors (handled by the caller)
func ExitCode(findings []scanner.Finding, failOn scanner.Severity) int {
	if len(findings) == 0 {
		return 0
	}
	blocking := false
	for _, f := range findings {
		if f.Severity.Rank() >= failOn.Rank() {
			blocking = true
			break
		}
	}
	if blocking {
		return 1
	}
	return 2
}
