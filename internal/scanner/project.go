package scanner

import (
	"path"
	"strconv"
	"strings"
)

// ProjectType is the detected primary ecosystem of a repository.
type ProjectType string

// Known project types.
const (
	ProjectGo     ProjectType = "go"
	ProjectNode   ProjectType = "node"
	ProjectPython ProjectType = "python"
	ProjectRust   ProjectType = "rust"
	ProjectAny    ProjectType = "any"
)

// DetectProjectType infers the repository's primary project type from marker
// files at the repository root, checked in a deterministic order.
func (r *Repo) DetectProjectType() ProjectType {
	switch {
	case r.Exists("go.mod"):
		return ProjectGo
	case r.Exists("Cargo.toml"):
		return ProjectRust
	case r.Exists("package.json"):
		return ProjectNode
	case r.Exists("pyproject.toml"), r.Exists("setup.py"), r.Exists("requirements.txt"), r.Exists("Pipfile"):
		return ProjectPython
	default:
		return ProjectAny
	}
}

// lockfileCandidates lists accepted lockfiles per project type.
var lockfileCandidates = map[ProjectType][]string{
	ProjectGo:     {"go.sum"},
	ProjectNode:   {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"},
	ProjectPython: {"poetry.lock", "Pipfile.lock", "uv.lock", "requirements.txt"},
	ProjectRust:   {"Cargo.lock"},
}

// LockfileFor returns the accepted lockfiles and whether at least one exists.
func (r *Repo) LockfileFor(t ProjectType) (candidates []string, found string, ok bool) {
	candidates = lockfileCandidates[t]
	for _, c := range candidates {
		if r.Exists(c) {
			return candidates, c, true
		}
	}
	return candidates, "", false
}

// BuildFile describes an executable build entry point.
type BuildFile struct {
	Path string
	Kind string
}

// buildFileNames are build definitions recognized at the repository root.
var buildFileNames = []BuildFile{
	{"Makefile", "Make"},
	{"makefile", "Make"},
	{"GNUmakefile", "Make"},
	{"justfile", "Just"},
	{"Justfile", "Just"},
	{"Taskfile.yml", "Task"},
	{"Taskfile.yaml", "Task"},
	{"meson.build", "Meson"},
	{"CMakeLists.txt", "CMake"},
	{"build.gradle", "Gradle"},
	{"build.gradle.kts", "Gradle"},
	{"pom.xml", "Maven"},
	{"configure", "Autotools"},
	{"configure.ac", "Autotools"},
}

// DetectBuildFiles returns recognized root-level build definitions. It also
// treats ecosystem manifests with build metadata as build files.
func (r *Repo) DetectBuildFiles() []BuildFile {
	var out []BuildFile
	for _, bf := range buildFileNames {
		if r.Exists(bf.Path) {
			out = append(out, bf)
		}
	}
	if r.Exists("package.json") {
		out = append(out, BuildFile{"package.json", "npm scripts"})
	}
	if r.Exists("Cargo.toml") {
		out = append(out, BuildFile{"Cargo.toml", "Cargo"})
	}
	if r.Exists("go.mod") {
		out = append(out, BuildFile{"go.mod", "Go modules"})
	}
	if r.Exists("pyproject.toml") {
		out = append(out, BuildFile{"pyproject.toml", "Python build"})
	}
	return out
}

// sourceExtensions are file extensions considered source code for the
// (optional) copyright header heuristic. The check is informational only.
var sourceExtensions = map[string]bool{
	".go": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".jsx": true,
	".py": true, ".rs": true, ".c": true, ".h": true, ".cc": true, ".cpp": true, ".hpp": true,
	".java": true, ".kt": true, ".kts": true, ".rb": true, ".sh": true, ".bash": true, ".zsh": true,
	".swift": true, ".cs": true, ".php": true, ".scala": true, ".ex": true, ".exs": true,
	".lua": true, ".dart": true, ".m": true, ".mm": true, ".pl": true, ".r": true, ".jl": true,
}

// IsSourceFile reports whether a path looks like a source file.
func IsSourceFile(p string) bool {
	return sourceExtensions[strings.ToLower(path.Ext(p))]
}

// mediaOrArchiveExtensions are file types that should generally live in a
// release or Git LFS rather than the main tree.
var mediaOrArchiveExtensions = map[string]bool{
	".zip": true, ".tar": true, ".gz": true, ".tgz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true,
	".mp4": true, ".mov": true, ".avi": true, ".mkv": true, ".webm": true,
	".mp3": true, ".wav": true, ".flac": true, ".ogg": true,
	".psd": true, ".ai": true, ".iso": true, ".dmg": true, ".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".jar": true, ".war": true, ".pdf": true,
}

// IsMediaOrArchive reports whether an extension is likely inappropriate for
// the main git tree.
func IsMediaOrArchive(p string) bool {
	return mediaOrArchiveExtensions[strings.ToLower(path.Ext(p))]
}

// ByteSize renders a human-friendly size string.
func ByteSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB"}
	return strconv.FormatFloat(float64(n)/float64(div), 'f', 1, 64) + " " + units[exp]
}
