package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

// WriteMarkdownSummary writes a concise Markdown summary suitable for a GitHub
// Actions step summary ($GITHUB_STEP_SUMMARY).
func WriteMarkdownSummary(w io.Writer, r *Report) error {
	s := r.Summary
	var b strings.Builder
	b.WriteString("## Spec-Guardian repository health report\n\n")
	if s.Total == 0 {
		b.WriteString("✅ **No findings.** Repository metadata looks healthy.\n")
		writeFooter(&b, r)
		_, err := io.WriteString(w, b.String())
		return err
	}
	fmt.Fprintf(&b, "**%d findings** — ", s.Total)
	fmt.Fprintf(&b, "🔴 %d high · 🟡 %d medium · 🔵 %d low · ⚪ %d info\n\n", s.High, s.Medium, s.Low, s.Info)

	if s.High > 0 {
		b.WriteString("> ❌ Blocking high severity findings were detected.\n\n")
	} else {
		b.WriteString("> ⚠️ No blocking high severity findings.\n\n")
	}

	b.WriteString("| Severity | Rule | Location | Message |\n")
	b.WriteString("|----------|------|----------|---------|\n")
	shown := 0
	const maxRows = 25
	for _, f := range r.Findings {
		if shown >= maxRows {
			break
		}
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n",
			severityEmoji(f.Severity), f.RuleID, mdEscape(loc), mdEscape(f.Message))
		shown++
	}
	if len(r.Findings) > shown {
		fmt.Fprintf(&b, "\n_…and %d more. See the uploaded HTML report._\n", len(r.Findings)-shown)
	}
	writeFooter(&b, r)
	_, err := io.WriteString(w, b.String())
	return err
}

func writeFooter(b *strings.Builder, r *Report) {
	fmt.Fprintf(b, "\n<sub>Spec-Guardian %s · %s · %d files · project: %s</sub>\n",
		r.Version, r.GeneratedAt.Format("2006-01-02 15:04 MST"), r.FileCount, r.ProjectType)
}

func severityEmoji(s scanner.Severity) string {
	switch s {
	case scanner.SeverityHigh:
		return "🔴 high"
	case scanner.SeverityMedium:
		return "🟡 medium"
	case scanner.SeverityLow:
		return "🔵 low"
	default:
		return "⚪ info"
	}
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 120 {
		s = s[:119] + "…"
	}
	return s
}
