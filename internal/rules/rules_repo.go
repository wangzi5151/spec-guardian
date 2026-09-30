package rules

import (
	"regexp"
	"strings"

	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

// --- LICENSE ---

func findLicenseFile(r *scanner.Repo) (string, bool) {
	best := ""
	for _, f := range r.Files {
		if f.Dir() != "." {
			continue
		}
		up := strings.ToUpper(f.Base())
		if strings.HasPrefix(up, "LICEN") || strings.HasPrefix(up, "COPYING") || up == "UNLICENSE" {
			// Prefer the plain LICENSE file over variants.
			if best == "" || len(f.Path) < len(best) {
				best = f.Path
			}
		}
	}
	return best, best != ""
}

func checkLicenseExists(ctx *Context) []scanner.Finding {
	if _, ok := findLicenseFile(ctx.Repo); ok {
		return nil
	}
	return []scanner.Finding{{
		File:    "LICENSE",
		Message: "No LICENSE or LICENCE file found at the repository root.",
	}}
}

func checkLicenseRecognized(ctx *Context) []scanner.Finding {
	p, ok := findLicenseFile(ctx.Repo)
	if !ok {
		return nil // covered by repo.license.exists
	}
	content, ok := ctx.Repo.ReadFileString(p, 256*1024)
	if !ok {
		return nil
	}
	_, recognized := scanner.DetectLicense(content)
	if recognized {
		return nil
	}
	return []scanner.Finding{{
		File:    p,
		Message: "Could not recognize the license text against the built-in SPDX library. Downstream users may be unable to determine the terms.",
	}}
}

func checkLicenseYear(ctx *Context) []scanner.Finding {
	p, ok := findLicenseFile(ctx.Repo)
	if !ok {
		return nil
	}
	content, ok := ctx.Repo.ReadFileString(p, 256*1024)
	if !ok {
		return nil
	}
	years, reasonable := scanner.LicenseYears(content)
	if reasonable {
		return nil
	}
	return []scanner.Finding{{
		File:    p,
		Message: "Copyright year range looks implausible: " + joinInts(years) + ". This is an informational hint only.",
	}}
}

func checkLicenseHeaders(ctx *Context) []scanner.Finding {
	var total, missing int
	const maxScan = 300
	for _, f := range ctx.Repo.Files {
		if !scanner.IsSourceFile(f.Path) {
			continue
		}
		total++
		if total > maxScan {
			break
		}
		head, ok := ctx.Repo.ReadFileString(f.Path, 4096)
		if !ok {
			continue
		}
		if scanner.HasCopyrightNotice(head) || scanner.HasSPDXHeader(head) {
			continue
		}
		missing++
	}
	if total == 0 || missing == 0 {
		return nil
	}
	if float64(missing)/float64(total) < 0.5 {
		return nil
	}
	return []scanner.Finding{{
		Message: "Header comment coverage is low: " + itoa(missing) + " of " + itoa(total) + " scanned source files lack a copyright/SPDX header. Informational only.",
	}}
}

// --- .gitignore ---

func findGitignore(r *scanner.Repo) (string, bool) {
	return findFile(r, []string{"."}, ".gitignore")
}

func checkGitignoreExists(ctx *Context) []scanner.Finding {
	if _, ok := findGitignore(ctx.Repo); ok {
		return nil
	}
	return []scanner.Finding{{
		File:      ".gitignore",
		Message:   "No .gitignore found. Without one, secrets and build artifacts are easily committed by accident.",
		Patchable: true,
		Patch:     suggestionPatch(".gitignore", scanner.GitignoreSuggestion(scanner.BaselineGitignoreRisks)),
	}}
}

func checkGitignoreRisks(ctx *Context) []scanner.Finding {
	p, ok := findGitignore(ctx.Repo)
	if !ok {
		return nil // covered by repo.gitignore.exists
	}
	content, ok := ctx.Repo.ReadFileString(p, 128*1024)
	if !ok {
		return nil
	}
	patterns := scanner.ParseGitignore(content)
	missing := scanner.MissingGitignoreRisks(patterns)
	if len(missing) == 0 {
		return nil
	}
	snippet := scanner.GitignoreSuggestion(missing)
	var findings []scanner.Finding
	for _, risk := range missing {
		findings = append(findings, scanner.Finding{
			File:      p,
			Severity:  risk.Severity,
			Message:   "Missing baseline pattern " + risk.Label + ": " + risk.Reason + ".",
			Patchable: true,
			Patch:     appendPatch(p, snippet),
		})
	}
	return findings
}

// --- README ---

func findReadme(r *scanner.Repo) (string, bool) {
	best := ""
	bestRank := 99
	for _, f := range r.Files {
		if f.Dir() != "." {
			continue
		}
		low := strings.ToLower(f.Base())
		if !strings.HasPrefix(low, "readme") {
			continue
		}
		rank := 5
		switch {
		case strings.HasSuffix(low, ".md"):
			rank = 0
		case strings.HasSuffix(low, ".markdown"):
			rank = 1
		case strings.HasSuffix(low, ".rst"):
			rank = 2
		case strings.HasSuffix(low, ".txt"):
			rank = 3
		default:
			rank = 4
		}
		if rank < bestRank {
			bestRank = rank
			best = f.Path
		}
	}
	return best, best != ""
}

func readReadme(ctx *Context) (string, string, bool) {
	p, ok := findReadme(ctx.Repo)
	if !ok {
		return "", "", false
	}
	content, ok := ctx.Repo.ReadFileString(p, 2*1024*1024)
	if !ok {
		return p, "", false
	}
	return p, content, true
}

func checkReadmeExists(ctx *Context) []scanner.Finding {
	if _, ok := findReadme(ctx.Repo); ok {
		return nil
	}
	return []scanner.Finding{{
		File:      "README.md",
		Message:   "No README file found at the repository root.",
		Patchable: true,
		Patch: suggestionPatch("README.md",
			"# Project Name\n\nOne-line description of what this project does and who it is for.\n\n## Quick Start\n\n```sh\ngo install example.com/you/project@latest\n```\n\n## Requirements\n\n- Go >= 1.22\n\n## Known Limitations\n\n- Describe current limitations here.\n"),
	}}
}

func checkReadmeQuickstart(ctx *Context) []scanner.Finding {
	p, content, ok := readReadme(ctx)
	if !ok {
		return nil
	}
	section, found := scanner.FindSection(content,
		"quick start", "quickstart", "getting started", "installation", "install", "usage",
		"快速开始", "快速上手", "安装", "使用方法")
	if found {
		if sectionHasCommand(section.Body) {
			return nil
		}
		return []scanner.Finding{{
			File:    p,
			Line:    section.Line,
			Message: "Found a \"" + section.Heading + "\" section but no command a reader could try.",
		}}
	}
	if sectionHasCommand(content) {
		return nil
	}
	return []scanner.Finding{{
		File:    p,
		Message: "No Quick Start / Installation / Usage section with a runnable command was found.",
	}}
}

func sectionHasCommand(body string) bool {
	if scanner.CountFencedCodeBlocks(body) > 0 {
		return true
	}
	for _, line := range strings.Split(body, "\n") {
		if scanner.LooksLikeCommand(line) {
			return true
		}
	}
	return false
}

var reVersionReq = regexp.MustCompile(`(?i)\b(go|golang|node|node\.?js|python|rust|rustc|java|jdk|ruby|php|deno|bun|cmake|make)\b[^\n]{0,24}?(\d+(?:\.\d+){0,2})`)

func checkReadmeDependencies(ctx *Context) []scanner.Finding {
	p, content, ok := readReadme(ctx)
	if !ok {
		return nil
	}
	low := strings.ToLower(content)
	hasKeyword := strings.Contains(low, "requirement") || strings.Contains(low, "prerequisite") ||
		strings.Contains(low, "minimum") || strings.Contains(low, "依赖") || strings.Contains(low, "要求")
	hasVersion := reVersionReq.MatchString(content) || regexp.MustCompile(`(?i)(>=|≥|>)\s*\d+(\.\d+)+`).MatchString(content)
	if hasKeyword || hasVersion {
		return nil
	}
	return []scanner.Finding{{
		File:    p,
		Message: "No minimum dependency/toolchain versions stated (e.g. \"Go >= 1.22\", \"Node >= 20\", \"Python >= 3.11\").",
	}}
}

var reBadgeOrImage = regexp.MustCompile(`^\s*(\[!\[|!\[|<img|<a |\[|<!--|\|)`)

func checkReadmeDescription(ctx *Context) []scanner.Finding {
	p, content, ok := readReadme(ctx)
	if !ok {
		return nil
	}
	lines := strings.Split(content, "\n")
	limit := 40
	if len(lines) < limit {
		limit = len(lines)
	}
	for i := 0; i < limit; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") || reBadgeOrImage.MatchString(line) {
			continue
		}
		if len(line) < 15 {
			continue
		}
		return nil
	}
	return []scanner.Finding{{
		File:    p,
		Message: "Could not find a short paragraph describing the project's purpose near the top of the README.",
	}}
}

func checkReadmeLimitations(ctx *Context) []scanner.Finding {
	p, content, ok := readReadme(ctx)
	if !ok {
		return nil
	}
	if _, found := scanner.HasHeadingMatching(content,
		"limitation", "known issue", "caveat", "notes", "disclaimer", "not supported",
		"限制", "已知限制", "注意事项", "说明"); found {
		return nil
	}
	return []scanner.Finding{{
		File:    p,
		Message: "No Known Limitations / Notes section found. Informational only.",
	}}
}

// --- Community files ---

func checkContributing(ctx *Context) []scanner.Finding {
	if _, ok := findFile(ctx.Repo, []string{".", ".github", "docs"}, "CONTRIBUTING.md", "CONTRIBUTING.rst", "CONTRIBUTING", "CONTRIBUTING.txt"); ok {
		return nil
	}
	return []scanner.Finding{{Message: "No CONTRIBUTING guide found."}}
}

func checkCodeowners(ctx *Context) []scanner.Finding {
	if _, ok := findFile(ctx.Repo, []string{".github", ".", "docs"}, "CODEOWNERS"); ok {
		return nil
	}
	return []scanner.Finding{{Message: "No CODEOWNERS file found."}}
}

func checkSecurityPolicy(ctx *Context) []scanner.Finding {
	if _, ok := findFile(ctx.Repo, []string{".", ".github", "docs"}, "SECURITY.md", "SECURITY.rst", "SECURITY.txt", "SECURITY"); ok {
		return nil
	}
	return []scanner.Finding{{Message: "No SECURITY.md policy found."}}
}

func checkIssueTemplate(ctx *Context) []scanner.Finding {
	if dirHasAnyFile(ctx.Repo, ".github/ISSUE_TEMPLATE") {
		return nil
	}
	if _, ok := findFile(ctx.Repo, []string{".github", "."}, "ISSUE_TEMPLATE.md", "ISSUE_TEMPLATE", "ISSUE_TEMPLATE.yml", "ISSUE_TEMPLATE.yaml", "config.yml"); ok {
		return nil
	}
	return []scanner.Finding{{Message: "No issue template found under .github/."}}
}

func checkPRTemplate(ctx *Context) []scanner.Finding {
	if dirHasAnyFile(ctx.Repo, ".github/PULL_REQUEST_TEMPLATE") {
		return nil
	}
	if _, ok := findFile(ctx.Repo, []string{".github", ".", "docs"},
		"PULL_REQUEST_TEMPLATE.md", "pull_request_template.md", "PULL_REQUEST_TEMPLATE", "PULL_REQUEST_TEMPLATE.txt"); ok {
		return nil
	}
	return []scanner.Finding{{Message: "No pull request template found under .github/."}}
}
