// Package scanner provides repository data acquisition and low-level
// parsing helpers used by the Spec-Guardian rule engine.
//
// It intentionally does NOT judge rules; it only indexes files and offers
// streaming helpers so that very large repositories can be audited without
// loading everything into memory. It also owns the small set of shared model
// types (Severity, Finding) so that other packages can depend on them without
// creating import cycles.
package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// Severity is the impact level of a finding.
type Severity string

// Canonical severities, ordered from most to least severe.
const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
	SeverityInfo   Severity = "info"
)

// Rank returns a sortable rank for the severity (higher == more severe).
func (s Severity) Rank() int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 0
	default:
		return -1
	}
}

// ParseSeverity parses a user supplied severity string.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "error", "critical":
		return SeverityHigh, true
	case "medium", "med", "warn", "warning":
		return SeverityMedium, true
	case "low":
		return SeverityLow, true
	case "info", "note", "none":
		return SeverityInfo, true
	default:
		return "", false
	}
}

// AllSeverities lists the canonical severities in descending order.
var AllSeverities = []Severity{SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

// Finding is a single rule violation or observation.
type Finding struct {
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
	DocURL      string   `json:"docUrl,omitempty"`
	Patchable   bool     `json:"patchable"`
	Patch       string   `json:"patch,omitempty"`
}

// FileEntry describes a single file discovered during indexing.
type FileEntry struct {
	// Path is relative to the repository root, slash-separated.
	Path string
	// Abs is the absolute filesystem path.
	Abs string
	// Size is the file size in bytes.
	Size int64
}

// IsMarkdown reports whether the entry has a Markdown extension.
func (f FileEntry) IsMarkdown() bool {
	lower := strings.ToLower(f.Path)
	return strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".markdown")
}

// Base returns the final path element.
func (f FileEntry) Base() string { return pathBase(f.Path) }

// Dir returns the directory portion (without trailing slash), or ".".
func (f FileEntry) Dir() string { return pathDir(f.Path) }

// Repo is an indexed view of a repository working tree.
type Repo struct {
	Root  string
	Files []FileEntry

	byPath map[string]FileEntry
	dirs   map[string]bool
}

// IndexOptions controls filesystem traversal.
type IndexOptions struct {
	// Excludes are glob patterns (supporting *, ** and bare directory names)
	// describing files that should be skipped entirely.
	Excludes []string
	// FollowSymlinks enables traversal through symlinked directories.
	FollowSymlinks bool
	// SkipDirs are directory basenames always skipped (e.g. vendor, .git).
	SkipDirs []string
	// MaxFiles guards against pathological trees (0 == unlimited).
	MaxFiles int
}

// DefaultSkipDirs are directories that are almost never part of the audited
// source and are skipped by default for performance and correctness.
var DefaultSkipDirs = []string{".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", ".idea", ".vscode"}

// Index walks the working tree rooted at root and records file metadata.
// File contents are never retained here, keeping memory bounded.
func Index(root string, opts IndexOptions) (*Repo, error) {
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 200000
	}
	skip := map[string]bool{".git": true}
	for _, d := range DefaultSkipDirs {
		skip[d] = true
	}
	for _, d := range opts.SkipDirs {
		skip[d] = true
	}

	r := &Repo{
		Root:   root,
		byPath: map[string]FileEntry{},
		dirs:   map[string]bool{".": true},
	}

	err := walk(root, "", opts, skip, func(entry FileEntry) error {
		if r.matchExcludes(entry.Path, opts.Excludes) {
			return nil
		}
		r.Files = append(r.Files, entry)
		r.byPath[entry.Path] = entry
		r.recordDirs(entry.Path)
		if len(r.Files) > opts.MaxFiles {
			return fmt.Errorf("too many files (limit %d); use --exclude to narrow the scan", opts.MaxFiles)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(r.Files, func(i, j int) bool { return r.Files[i].Path < r.Files[j].Path })
	return r, nil
}

func (r *Repo) matchExcludes(p string, excludes []string) bool {
	for _, ex := range excludes {
		if MatchPath(ex, p) {
			return true
		}
	}
	return false
}

// recordDirs registers every ancestor directory of a file path.
func (r *Repo) recordDirs(p string) {
	dir := pathDir(p)
	for dir != "." && dir != "" {
		r.dirs[dir] = true
		dir = pathDir(dir)
	}
}

// Exists reports whether a repo-relative file exists (case-sensitive).
func (r *Repo) Exists(rel string) bool {
	_, ok := r.byPath[normalizeRel(rel)]
	return ok
}

// ExistsDir reports whether a repo-relative directory exists.
func (r *Repo) ExistsDir(rel string) bool {
	return r.dirs[normalizeRel(rel)]
}

// DirHasFile reports whether a directory contains at least one file matching
// any of the provided basenames (case-insensitive).
func (r *Repo) DirHasFile(dir string, names ...string) bool {
	dir = normalizeRel(dir)
	if dir == "" {
		dir = "."
	}
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	for _, f := range r.Files {
		if f.Dir() == dir && want[strings.ToLower(f.Base())] {
			return true
		}
	}
	return false
}

// RootFile returns the path of the first repository-root file whose basename
// matches one of names (case-insensitive). It returns ok=false when none exist.
func (r *Repo) RootFile(names ...string) (string, bool) {
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	for _, f := range r.Files {
		if f.Dir() == "." && want[strings.ToLower(f.Base())] {
			return f.Path, true
		}
	}
	return "", false
}

// RootFilesMatching returns all root-level files whose basename matches the
// predicate.
func (r *Repo) RootFilesMatching(pred func(base string) bool) []FileEntry {
	var out []FileEntry
	for _, f := range r.Files {
		if f.Dir() == "." && pred(f.Base()) {
			out = append(out, f)
		}
	}
	return out
}

// Glob returns all files matching a path glob (supporting ** and *).
func (r *Repo) Glob(pattern string) []FileEntry {
	var out []FileEntry
	for _, f := range r.Files {
		if MatchPath(pattern, f.Path) {
			out = append(out, f)
		}
	}
	return out
}

// MarkdownFiles returns all Markdown files.
func (r *Repo) MarkdownFiles() []FileEntry {
	var out []FileEntry
	for _, f := range r.Files {
		if f.IsMarkdown() {
			out = append(out, f)
		}
	}
	return out
}

// Count returns the number of indexed files.
func (r *Repo) Count() int { return len(r.Files) }

// Dirs returns an unsorted copy of known directories.
func (r *Repo) Dirs() []string {
	out := make([]string, 0, len(r.dirs))
	for d := range r.dirs {
		out = append(out, d)
	}
	return out
}
