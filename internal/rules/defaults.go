package rules

import "github.com/wangzi5151/spec-guardian/internal/scanner"

// builtinRules returns the full default rule set. Every rule is individually
// configurable (disable / severity override) via specguard-rules.yml.
func builtinRules() []Rule {
	return []Rule{
		// --- Module A: repository root files ---
		{
			Meta: RuleMeta{
				ID: "repo.license.exists", Title: "License file present",
				Description:     "A repository should contain a LICENSE/LICENCE file so that others know the terms under which it may be used.",
				DefaultSeverity: scanner.SeverityHigh, Category: "repository",
				Remediation: "Add a LICENSE file at the repository root (for example the MIT license) and reference it from the README.",
				DocURL:      docURL("repo.license.exists"),
			},
			Check: checkLicenseExists,
		},
		{
			Meta: RuleMeta{
				ID: "repo.license.recognized", Title: "License is a recognized SPDX license",
				Description:     "The license text could not be matched against the built-in SPDX license library, which makes downstream reuse harder.",
				DefaultSeverity: scanner.SeverityMedium, Category: "repository",
				Remediation: "Use an OSI-approved license text verbatim from https://spdx.org/licenses/ or add an SPDX-License-Identifier header.",
				DocURL:      docURL("repo.license.recognized"),
			},
			Check: checkLicenseRecognized,
		},
		{
			Meta: RuleMeta{
				ID: "repo.license.year", Title: "Copyright year range looks reasonable",
				Description:     "The copyright year in the license looks implausible (for example in the future or inverted). This is an informational hint only.",
				DefaultSeverity: scanner.SeverityInfo, Category: "repository",
				Remediation: "Review the copyright year(s) in the LICENSE file; no hard requirement is enforced.",
				DocURL:      docURL("repo.license.year"),
			},
			Check: checkLicenseYear,
		},
		{
			Meta: RuleMeta{
				ID: "repo.license.header_comments", Title: "Source files carry license headers",
				Description:     "A large share of source files lack a copyright/SPDX header comment. This is an optional, informational check.",
				DefaultSeverity: scanner.SeverityLow, Category: "repository", OptIn: true,
				Remediation: "Consider adding SPDX-License-Identifier headers to source files. Enable with settings.header_comment_check: true.",
				DocURL:      docURL("repo.license.header_comments"),
			},
			Check: checkLicenseHeaders,
		},
		{
			Meta: RuleMeta{
				ID: "repo.gitignore.exists", Title: "Baseline .gitignore present",
				Description:     "A .gitignore file reduces the risk of committing secrets, dependencies and build artifacts.",
				DefaultSeverity: scanner.SeverityMedium, Category: "repository",
				Remediation: "Add a .gitignore with at least the baseline patterns (.env, *.pem, node_modules/, *.log, .DS_Store).",
				DocURL:      docURL("repo.gitignore.exists"),
			},
			Check: checkGitignoreExists,
		},
		{
			Meta: RuleMeta{
				ID: "repo.gitignore.risk_patterns", Title: ".gitignore covers common risk patterns",
				Description:     "The .gitignore is missing patterns for files that commonly leak secrets or bloat the repository.",
				DefaultSeverity: scanner.SeverityMedium, Category: "repository",
				Remediation: "Add the missing patterns to .gitignore (a ready-to-copy snippet is included in the report).",
				DocURL:      docURL("repo.gitignore.risk_patterns"),
			},
			Check: checkGitignoreRisks,
		},
		{
			Meta: RuleMeta{
				ID: "repo.readme.exists", Title: "README present",
				Description:     "A README is the entry point for new users and contributors.",
				DefaultSeverity: scanner.SeverityHigh, Category: "documentation",
				Remediation: "Add a README.md describing what the project is, how to run it, and its requirements.",
				DocURL:      docURL("repo.readme.exists"),
			},
			Check: checkReadmeExists,
		},
		{
			Meta: RuleMeta{
				ID: "repo.readme.quickstart", Title: "README has a quick-start with a runnable command",
				Description:     "A quick-start / installation section with at least one command a reader can try makes a project reproducible.",
				DefaultSeverity: scanner.SeverityHigh, Category: "documentation",
				Remediation: "Add a \"Quick Start\"/\"Installation\" section containing a fenced code block with an install or run command.",
				DocURL:      docURL("repo.readme.quickstart"),
			},
			Check: checkReadmeQuickstart,
		},
		{
			Meta: RuleMeta{
				ID: "repo.readme.dependencies", Title: "README documents minimum dependency versions",
				Description:     "Stating minimum runtime/toolchain versions prevents \"works on my machine\" reports.",
				DefaultSeverity: scanner.SeverityMedium, Category: "documentation",
				Remediation: "Add a Requirements section, e.g. \"Go >= 1.22\", \"Node >= 20\" or \"Python >= 3.11\".",
				DocURL:      docURL("repo.readme.dependencies"),
			},
			Check: checkReadmeDependencies,
		},
		{
			Meta: RuleMeta{
				ID: "repo.readme.description", Title: "README states the project purpose",
				Description:     "A one-line description of what the project does should appear near the top of the README.",
				DefaultSeverity: scanner.SeverityMedium, Category: "documentation",
				Remediation: "Add a short paragraph right after the title explaining what the project is and who it is for.",
				DocURL:      docURL("repo.readme.description"),
			},
			Check: checkReadmeDescription,
		},
		{
			Meta: RuleMeta{
				ID: "repo.readme.limitations", Title: "README mentions known limitations",
				Description:     "Documenting known limitations or caveats sets honest expectations. Informational only.",
				DefaultSeverity: scanner.SeverityInfo, Category: "documentation",
				Remediation: "Consider adding a Known Limitations / Notes section.",
				DocURL:      docURL("repo.readme.limitations"),
			},
			Check: checkReadmeLimitations,
		},
		// --- Module A: documentation links ---
		{
			Meta: RuleMeta{
				ID: "docs.links.dead", Title: "No dead documentation links",
				Description:     "One or more http/https links in Markdown files did not respond successfully.",
				DefaultSeverity: scanner.SeverityMedium, Category: "documentation",
				Remediation: "Fix or remove the dead link, or point it to a WayBack Machine snapshot.",
				DocURL:      docURL("docs.links.dead"),
			},
			Check: checkDeadLinks,
		},
		{
			Meta: RuleMeta{
				ID: "docs.links.archived", Title: "Dead links have archive fallbacks",
				Description:     "Dead links that are available in the WayBack Machine are reported with a suggested snapshot URL.",
				DefaultSeverity: scanner.SeverityInfo, Category: "documentation",
				Remediation: "Replace the dead link with the suggested archived snapshot, or find a current replacement.",
				DocURL:      docURL("docs.links.archived"),
			},
			Check: checkArchivedLinks,
		},
		// --- Module A: community files ---
		{
			Meta: RuleMeta{
				ID: "community.contributing", Title: "CONTRIBUTING guide present",
				Description:     "A CONTRIBUTING file tells contributors how to participate.",
				DefaultSeverity: scanner.SeverityInfo, Category: "community",
				Remediation: "Add CONTRIBUTING.md describing setup, coding and PR expectations.",
				DocURL:      docURL("community.contributing"),
			},
			Check: checkContributing,
		},
		{
			Meta: RuleMeta{
				ID: "community.codeowners", Title: "CODEOWNERS present",
				Description:     "A CODEOWNERS file helps route review requests. Informational for solo projects.",
				DefaultSeverity: scanner.SeverityInfo, Category: "community",
				Remediation: "Add .github/CODEOWNERS if the project has maintainers who should review changes.",
				DocURL:      docURL("community.codeowners"),
			},
			Check: checkCodeowners,
		},
		{
			Meta: RuleMeta{
				ID: "community.security", Title: "Security policy present",
				Description:     "A SECURITY.md explains how to report vulnerabilities responsibly.",
				DefaultSeverity: scanner.SeverityMedium, Category: "community",
				Remediation: "Add SECURITY.md with a private disclosure channel.",
				DocURL:      docURL("community.security"),
			},
			Check: checkSecurityPolicy,
		},
		{
			Meta: RuleMeta{
				ID: "community.issue_template", Title: "Issue template present",
				Description:     "Issue templates improve the quality of bug reports.",
				DefaultSeverity: scanner.SeverityInfo, Category: "community",
				Remediation: "Add .github/ISSUE_TEMPLATE/ templates (bug report, feature request).",
				DocURL:      docURL("community.issue_template"),
			},
			Check: checkIssueTemplate,
		},
		{
			Meta: RuleMeta{
				ID: "community.pr_template", Title: "Pull request template present",
				Description:     "A PR template reminds contributors to include tests and context.",
				DefaultSeverity: scanner.SeverityInfo, Category: "community",
				Remediation: "Add .github/PULL_REQUEST_TEMPLATE.md.",
				DocURL:      docURL("community.pr_template"),
			},
			Check: checkPRTemplate,
		},
		// --- Module B: build & reproducibility ---
		{
			Meta: RuleMeta{
				ID: "build.script.exists", Title: "Executable build definition present",
				Description:     "A Makefile/justfile/task runner or ecosystem manifest makes the build discoverable.",
				DefaultSeverity: scanner.SeverityMedium, Category: "build",
				Remediation: "Add a Makefile, justfile, Taskfile or document the build command in the manifest.",
				DocURL:      docURL("build.script.exists"),
			},
			Check: checkBuildScript,
		},
		{
			Meta: RuleMeta{
				ID: "build.from_source_documented", Title: "Rebuilding from source is documented",
				Description:     "Users should be able to reproduce release artifacts from source using documented steps.",
				DefaultSeverity: scanner.SeverityMedium, Category: "build",
				Remediation: "Document the from-source build in README/CONTRIBUTING (e.g. \"make release\").",
				DocURL:      docURL("build.from_source_documented"),
			},
			Check: checkFromSourceDocumented,
		},
		{
			Meta: RuleMeta{
				ID: "build.lockfile.exists", Title: "Dependency lockfile present",
				Description:     "Without a lockfile, builds resolve floating dependency versions and are not reproducible.",
				DefaultSeverity: scanner.SeverityMedium, Category: "build",
				Remediation: "Commit the lockfile for the detected ecosystem (go.sum, package-lock.json, Cargo.lock, poetry.lock …).",
				DocURL:      docURL("build.lockfile.exists"),
			},
			Check: checkLockfile,
		},
		{
			Meta: RuleMeta{
				ID: "release.checksums", Title: "Release assets include checksums",
				Description:     "Recent releases should publish SHA-256/BLAKE3 checksum files so downloads can be verified.",
				DefaultSeverity: scanner.SeverityMedium, Category: "release", RemoteOnly: true,
				Remediation: "Attach a checksums file (e.g. SHA256SUMS) to each release and reference it in the README.",
				DocURL:      docURL("release.checksums"),
			},
			Check: checkReleaseChecksums,
		},
		{
			Meta: RuleMeta{
				ID: "release.binaries_uploaded", Title: "Prebuilt binaries are attached to releases",
				Description:     "Distributing compiled binaries as release assets (not in the git tree) helps users without toolchains.",
				DefaultSeverity: scanner.SeverityLow, Category: "release", RemoteOnly: true,
				Remediation: "Attach cross-platform binaries to GitHub Releases instead of committing them.",
				DocURL:      docURL("release.binaries_uploaded"),
			},
			Check: checkReleaseBinaries,
		},
		{
			Meta: RuleMeta{
				ID: "release.commit_mapping", Title: "Release notes map artifacts to a commit",
				Description:     "Release notes should state the exact commit/tag the artifacts were built from.",
				DefaultSeverity: scanner.SeverityLow, Category: "release", RemoteOnly: true,
				Remediation: "Mention the source commit or tag in the release body, or link to the tag.",
				DocURL:      docURL("release.commit_mapping"),
			},
			Check: checkReleaseCommitMapping,
		},
		{
			Meta: RuleMeta{
				ID: "security.dangerous_files", Title: "No likely secret-bearing files committed",
				Description:     "Files such as .env, *.pem, *.key or id_rsa are frequently committed by mistake. This is a name-based heuristic with high false-positive tolerance.",
				DefaultSeverity: scanner.SeverityHigh, Category: "security",
				Remediation: "Remove the file from git, add it to .gitignore, and rotate any exposed credential. Use gitleaks for deep secret scanning.",
				DocURL:      docURL("security.dangerous_files"),
			},
			Check: checkDangerousFiles,
		},
		{
			Meta: RuleMeta{
				ID: "security.secret_assignments", Title: "No obvious secret assignments in tracked text",
				Description:     "A tracked text file appears to assign a literal secret (NAME=value). Coarse heuristic; review before acting.",
				DefaultSeverity: scanner.SeverityHigh, Category: "security",
				Remediation: "Move the value to an environment variable, remove it from history, and rotate the secret.",
				DocURL:      docURL("security.secret_assignments"),
			},
			Check: checkSecretAssignments,
		},
		{
			Meta: RuleMeta{
				ID: "security.large_files", Title: "No oversized binary/media files in the tree",
				Description:     "Large binaries and media bloat clones; they belong in Releases or Git LFS.",
				DefaultSeverity: scanner.SeverityLow, Category: "security",
				Remediation: "Move large files to Git LFS, a release asset, or an external store.",
				DocURL:      docURL("security.large_files"),
			},
			Check: checkLargeFiles,
		},
	}
}
