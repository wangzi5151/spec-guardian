package rules

import (
	"strings"

	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

const repoBase = "https://github.com/wangzi5151/spec-guardian"

// docURL returns the documentation anchor for a rule ID.
func docURL(id string) string {
	anchor := strings.ReplaceAll(strings.ToLower(id), ".", "-")
	return repoBase + "/blob/main/docs/rules.md#" + anchor
}

// findFile searches the given directories (relative to repo root) for a file
// whose basename matches one of names, case-insensitively. "." means the root.
func findFile(r *scanner.Repo, dirs []string, names ...string) (string, bool) {
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	for _, d := range dirs {
		d = strings.Trim(d, "/")
		if d == "" {
			d = "."
		}
		for _, f := range r.Files {
			if f.Dir() == d && want[strings.ToLower(f.Base())] {
				return f.Path, true
			}
		}
	}
	return "", false
}

// dirHasAnyFile reports whether a directory contains any file (ignoring empty
// placeholder files commonly named .gitkeep).
func dirHasAnyFile(r *scanner.Repo, dir string) bool {
	dir = strings.Trim(dir, "/")
	for _, f := range r.Files {
		if f.Dir() != dir {
			continue
		}
		base := strings.ToLower(f.Base())
		if base == ".gitkeep" || base == ".keep" {
			continue
		}
		return true
	}
	return false
}
