package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

func paint(color bool, code, s string) string {
	if !color {
		return s
	}
	return code + s + ansiReset
}

func severityColor(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityHigh:
		return ansiRed
	case scanner.SeverityMedium:
		return ansiYellow
	case scanner.SeverityLow:
		return ansiCyan
	default:
		return ansiGray
	}
}

// RenderTerminal writes a human-friendly, optionally colored report.
func RenderTerminal(w io.Writer, r *Report, color bool) {
	fmt.Fprintln(w, paint(color, ansiBold, "Spec-Guardian "+r.Version)+"  ·  repository health report")
	fmt.Fprintln(w)

	loc := r.Root
	if r.Branch != "" {
		loc += " (branch " + r.Branch
		if r.Commit != "" {
			loc += ", commit " + shortSHA(r.Commit)
		}
		loc += ")"
	}
	fmt.Fprintf(w, "%-11s %s\n", "Repository:", loc)
	if r.Origin != "" {
		fmt.Fprintf(w, "%-11s %s\n", "Origin:", r.Origin)
	}
	fmt.Fprintf(w, "%-11s %s\n", "Project:", r.ProjectType)
	fmt.Fprintf(w, "%-11s %d\n", "Files:", r.FileCount)
	fmt.Fprintf(w, "%-11s %v\n", "Offline:", r.Offline)
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, paint(color, ansiGreen, "No findings. Repository metadata looks healthy."))
		fmt.Fprintln(w)
		fmt.Fprintln(w, paint(color, ansiGray, "Result: PASS"))
		return
	}

	fmt.Fprintln(w, paint(color, ansiBold, "Findings"))
	fmt.Fprintln(w, paint(color, ansiGray, strings.Repeat("-", 72)))
	for _, f := range r.Findings {
		label := strings.ToUpper(string(f.Severity))
		head := fmt.Sprintf("%-6s %-32s", label, f.RuleID)
		if f.File != "" {
			loc := f.File
			if f.Line > 0 {
				loc += fmt.Sprintf(":%d", f.Line)
			}
			head += " " + loc
		}
		fmt.Fprintln(w, paint(color, severityColor(f.Severity), head))
		fmt.Fprintf(w, "       %s\n", f.Message)
		if f.Remediation != "" {
			fmt.Fprintln(w, paint(color, ansiGray, "       fix: "+firstLine(f.Remediation)))
		}
		if f.DocURL != "" {
			fmt.Fprintln(w, paint(color, ansiGray, "       doc: "+f.DocURL))
		}
	}
	fmt.Fprintln(w)

	s := r.Summary
	fmt.Fprintf(w, "Summary: %s, %s, %s, %s (%d total)\n",
		paint(color, ansiRed, fmt.Sprintf("%d high", s.High)),
		paint(color, ansiYellow, fmt.Sprintf("%d medium", s.Medium)),
		paint(color, ansiCyan, fmt.Sprintf("%d low", s.Low)),
		paint(color, ansiGray, fmt.Sprintf("%d info", s.Info)),
		s.Total,
	)
	if s.High > 0 {
		fmt.Fprintln(w, paint(color, ansiRed, "Result: FAIL (high severity findings)"))
	} else if s.Total > 0 {
		fmt.Fprintln(w, paint(color, ansiYellow, "Result: WARN (no blocking high severity findings)"))
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}
