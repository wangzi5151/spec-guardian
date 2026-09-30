package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

func sampleReport() *Report {
	findings := []scanner.Finding{
		{RuleID: "repo.license.exists", Severity: scanner.SeverityHigh, File: "LICENSE", Message: "missing", Patchable: true, Patch: "+ LICENSE"},
		{RuleID: "community.codeowners", Severity: scanner.SeverityInfo, Message: "no codeowners"},
	}
	r := NewReport(findings, nil)
	r.Version = "test"
	r.Root = "/tmp/repo"
	r.ProjectType = "go"
	r.FileCount = 3
	return r
}

func TestSummarizeAndExitCode(t *testing.T) {
	r := sampleReport()
	if r.Summary.Total != 2 || r.Summary.High != 1 || r.Summary.Info != 1 {
		t.Fatalf("bad summary: %+v", r.Summary)
	}
	if got := ExitCode(r.Findings, scanner.SeverityHigh); got != 1 {
		t.Errorf("expected exit 1, got %d", got)
	}
	onlyInfo := []scanner.Finding{{RuleID: "x", Severity: scanner.SeverityInfo}}
	if got := ExitCode(onlyInfo, scanner.SeverityHigh); got != 2 {
		t.Errorf("expected exit 2, got %d", got)
	}
	if got := ExitCode(nil, scanner.SeverityHigh); got != 0 {
		t.Errorf("expected exit 0, got %d", got)
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if decoded["tool"] != "spec-guardian" {
		t.Errorf("unexpected tool field: %v", decoded["tool"])
	}
}

func TestWriteHTMLReplacesPlaceholder(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "__SPECGUARDIAN_DATA__") {
		t.Fatalf("placeholder was not replaced")
	}
	if !strings.Contains(out, "repo.license.exists") {
		t.Fatalf("report data missing from HTML")
	}
	// Ensure JSON characters that could break out of <script> are escaped.
	if strings.Contains(out, "</script><script>") {
		t.Fatalf("unescaped script payload")
	}
}

func TestWriteMarkdownSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdownSummary(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Spec-Guardian") || !strings.Contains(out, "repo.license.exists") {
		t.Fatalf("unexpected summary: %s", out)
	}
}
