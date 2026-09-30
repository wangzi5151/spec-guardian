package rules

import (
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/wangzi5151/spec-guardian/internal/gitutil"
	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

// --- Build & reproducibility ---

func checkBuildScript(ctx *Context) []scanner.Finding {
	builds := ctx.Repo.DetectBuildFiles()
	if len(builds) > 0 {
		return nil
	}
	return []scanner.Finding{{
		Message: "No executable build definition found (Makefile, justfile, Taskfile, package.json scripts, meson.build, Cargo.toml, go.mod …).",
	}}
}

var fromSourceKeywords = []string{
	"build from source", "from source", "building from source", "compile from source",
	"build instructions", "how to build", "make release", "make build", "go build",
	"cargo build", "npm run build", "mvn package", "gradle build", "构建", "从源码", "从源代码", "编译",
}

func checkFromSourceDocumented(ctx *Context) []scanner.Finding {
	docs := []string{}
	if p, ok := findReadme(ctx.Repo); ok {
		docs = append(docs, p)
	}
	if p, ok := findFile(ctx.Repo, []string{".", ".github", "docs"}, "CONTRIBUTING.md", "CONTRIBUTING.rst", "BUILDING.md", "DEVELOPMENT.md"); ok {
		docs = append(docs, p)
	}
	for _, p := range docs {
		content, ok := ctx.Repo.ReadFileString(p, 1024*1024)
		if !ok {
			continue
		}
		low := strings.ToLower(content)
		for _, kw := range fromSourceKeywords {
			if strings.Contains(low, kw) {
				return nil
			}
		}
	}
	return []scanner.Finding{{
		Message: "Could not find documentation describing how to rebuild release artifacts from source.",
	}}
}

func checkLockfile(ctx *Context) []scanner.Finding {
	t := ctx.ProjectType
	candidates, _, ok := ctx.Repo.LockfileFor(t)
	if len(candidates) == 0 {
		return nil // unknown ecosystem; not our business
	}
	if ok {
		return nil
	}
	// A dependency-free Go module legitimately has no go.sum.
	if t == scanner.ProjectGo && !goModuleHasRequires(ctx) {
		return nil
	}
	return []scanner.Finding{{
		Message: "No dependency lockfile found for " + string(t) + " project (expected one of: " + strings.Join(candidates, ", ") + "). Dependency versions may float, hurting reproducibility.",
	}}
}

// goModuleHasRequires reports whether go.mod declares any dependency.
func goModuleHasRequires(ctx *Context) bool {
	content, ok := ctx.Repo.ReadFileString("go.mod", 256*1024)
	if !ok {
		return true
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require ") || strings.HasPrefix(line, "require(") || line == "require (" {
			return true
		}
	}
	return false
}

// --- Release checks (GitHub remote mode only) ---

func latestRelease(ctx *Context) *gitutil.Release {
	if ctx.Git == nil || !ctx.Git.IsRepo || !ctx.LinkEnabled {
		return nil
	}
	if !strings.EqualFold(ctx.Git.Host, "github.com") {
		return nil
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	c, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	rel, err := gitutil.LatestRelease(c, ctx.Git.Owner, ctx.Git.Repo, token, 10*time.Second)
	if err != nil {
		return nil
	}
	return rel
}

var checksumAssetRe = regexp.MustCompile(`(?i)(checksum|sha256|sha-256|sha512|blake3|hashes|SHA256SUMS|SHA512SUMS)`)

func checkReleaseChecksums(ctx *Context) []scanner.Finding {
	rel := latestRelease(ctx)
	if rel == nil {
		return nil
	}
	for _, a := range rel.Assets {
		if checksumAssetRe.MatchString(a.Name) {
			return nil
		}
	}
	return []scanner.Finding{{
		Message: "Latest release " + rel.TagName + " does not appear to include a checksum file (e.g. SHA256SUMS).",
	}}
}

var binaryAssetRe = regexp.MustCompile(`(?i)\.(exe|zip|tar\.gz|tgz|deb|rpm|apk|dmg|msi|pkg|AppImage)$`)

func checkReleaseBinaries(ctx *Context) []scanner.Finding {
	rel := latestRelease(ctx)
	if rel == nil {
		return nil
	}
	for _, a := range rel.Assets {
		if binaryAssetRe.MatchString(a.Name) && !checksumAssetRe.MatchString(a.Name) {
			return nil
		}
	}
	return []scanner.Finding{{
		Message: "Latest release " + rel.TagName + " has no prebuilt binary assets; users must build from source.",
	}}
}

func checkReleaseCommitMapping(ctx *Context) []scanner.Finding {
	rel := latestRelease(ctx)
	if rel == nil {
		return nil
	}
	body := strings.ToLower(rel.Body)
	if strings.Contains(body, "commit") || strings.Contains(body, "built from") || strings.Contains(body, "source") {
		return nil
	}
	if ctx.Git != nil && ctx.Git.CommitShort != "" && strings.Contains(rel.Body, ctx.Git.CommitShort) {
		return nil
	}
	return []scanner.Finding{{
		Message: "Release " + rel.TagName + " notes do not clearly map the artifacts to a source commit or tag.",
	}}
}

// --- Dangerous files / secrets / large files ---

func checkDangerousFiles(ctx *Context) []scanner.Finding {
	var findings []scanner.Finding
	const capLimit = 100
	for _, f := range ctx.Repo.Files {
		reason, sev, ok := scanner.ClassifySensitiveFile(f.Path)
		if !ok {
			continue
		}
		findings = append(findings, scanner.Finding{
			File:     f.Path,
			Severity: sev,
			Message:  "Sensitive file committed (" + reason + "). Name-based heuristic with high false-positive tolerance; review manually.",
		})
		if len(findings) >= capLimit {
			break
		}
	}
	return findings
}

// textExtensions are scanned for secret-looking assignments.
var textExtensions = map[string]bool{
	".env": true, ".txt": true, ".json": true, ".yml": true, ".yaml": true, ".toml": true,
	".ini": true, ".cfg": true, ".conf": true, ".properties": true, ".sh": true, ".bash": true,
	".md": true, ".ts": true, ".tsx": true, ".js": true, ".jsx": true, ".go": true, ".py": true,
	".rb": true, ".php": true, ".java": true, ".kt": true, ".rs": true, ".tf": true, ".tfvars": true,
}

func checkSecretAssignments(ctx *Context) []scanner.Finding {
	var findings []scanner.Finding
	const capLimit = 50
	// .env files are always inspected even without a recognized extension.
	for _, f := range ctx.Repo.Files {
		if f.Size > 256*1024 {
			continue
		}
		base := strings.ToLower(f.Base())
		isEnv := strings.HasPrefix(base, ".env")
		if !isEnv && !textExtensions[strings.ToLower(ext(f.Path))] {
			continue
		}
		if !isEnv && scanner.IsMediaOrArchive(f.Path) {
			continue
		}
		content, ok := ctx.Repo.ReadFileString(f.Path, 256*1024)
		if !ok {
			continue
		}
		for _, hit := range scanner.ScanSecretAssignments(content) {
			findings = append(findings, scanner.Finding{
				File:    f.Path,
				Line:    hit.Line,
				Message: "Possible literal secret assigned to " + hit.Name + ". Coarse heuristic; review before acting.",
			})
			if len(findings) >= capLimit {
				return findings
			}
		}
	}
	return findings
}

// largeFileThreshold is the size above which any file is flagged.
const largeFileThreshold = 5 * 1024 * 1024

func checkLargeFiles(ctx *Context) []scanner.Finding {
	var findings []scanner.Finding
	const capLimit = 50
	for _, f := range ctx.Repo.Files {
		threshold := int64(largeFileThreshold)
		if scanner.IsMediaOrArchive(f.Path) {
			threshold = 1 * 1024 * 1024
		}
		if f.Size < threshold {
			continue
		}
		findings = append(findings, scanner.Finding{
			File:     f.Path,
			Severity: scanner.SeverityLow,
			Message:  "Large file in git tree (" + scanner.ByteSize(f.Size) + "). Consider Git LFS or a release asset.",
		})
		if len(findings) >= capLimit {
			break
		}
	}
	return findings
}

func ext(p string) string {
	i := strings.LastIndexByte(p, '.')
	if i < 0 {
		return ""
	}
	return p[i:]
}
