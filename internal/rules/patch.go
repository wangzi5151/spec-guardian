package rules

import (
	"strconv"
	"strings"
)

// suggestionPatch renders a unified-diff preview that would create a new file
// with the given content. It never writes to disk; callers may choose to save
// the returned text as a .patch file.
func suggestionPatch(path, content string) string {
	lines := splitLines(content)
	var b strings.Builder
	b.WriteString("--- /dev/null\n")
	b.WriteString("+++ b/" + path + "\n")
	b.WriteString("@@ -0,0 +1," + strconv.Itoa(len(lines)) + " @@\n")
	for _, l := range lines {
		b.WriteString("+" + l + "\n")
	}
	return b.String()
}

// appendPatch renders a unified-diff preview that appends lines to an existing
// file. Because the current file content is not re-read here, the hunk header
// is intentionally generic; the patch is meant as a reviewable suggestion.
func appendPatch(path, content string) string {
	lines := splitLines(content)
	var b strings.Builder
	b.WriteString("--- a/" + path + "\n")
	b.WriteString("+++ b/" + path + "\n")
	b.WriteString("@@ -0,0 +1," + strconv.Itoa(len(lines)) + " @@\n")
	for _, l := range lines {
		b.WriteString("+" + l + "\n")
	}
	return b.String()
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string { return strconv.Itoa(n) }
