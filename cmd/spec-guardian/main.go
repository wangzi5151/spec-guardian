// Command spec-guardian audits open-source repository metadata and engineering
// health. It deliberately does not lint or statically analyze source code.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/wangzi5151/spec-guardian/internal/gitutil"
	"github.com/wangzi5151/spec-guardian/internal/netcheck"
	"github.com/wangzi5151/spec-guardian/internal/reporter"
	"github.com/wangzi5151/spec-guardian/internal/rules"
	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spec-guardian: "+err.Error())
		fmt.Fprintln(os.Stderr, "Run 'spec-guardian --help' for usage.")
		return 3
	}
	if opts.showHelp {
		printUsage(os.Stdout)
		return 0
	}
	if opts.showVersion {
		fmt.Println("spec-guardian " + version)
		return 0
	}

	switch opts.command {
	case "export-rules":
		return runExportRules(opts)
	case "rules":
		return runListRules(opts)
	default:
		return runScan(opts)
	}
}

func runScan(opts *options) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	root := opts.path
	cleanup := func() {}
	if opts.repoURL != "" {
		fmt.Fprintln(os.Stderr, "Cloning "+opts.repoURL+" …")
		dir, c, err := gitutil.CloneRemote(ctx, opts.repoURL, opts.branch, 1)
		if err != nil {
			fmt.Fprintln(os.Stderr, "spec-guardian: "+err.Error())
			return 3
		}
		root = dir
		cleanup = c
	}
	defer cleanup()

	absRoot, err := gitutil.EnsureAbs(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spec-guardian: "+err.Error())
		return 3
	}
	if fi, err := os.Stat(absRoot); err != nil || !fi.IsDir() {
		fmt.Fprintln(os.Stderr, "spec-guardian: not a directory: "+absRoot)
		return 3
	}

	cfg, err := loadConfig(absRoot, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spec-guardian: "+err.Error())
		return 3
	}
	if err := rules.ValidateCustomRules(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "spec-guardian: "+err.Error())
		return 3
	}

	repo, err := scanner.Index(absRoot, scanner.IndexOptions{
		Excludes:       cfg.Settings.Exclude,
		FollowSymlinks: cfg.Settings.FollowSymlinks,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "spec-guardian: "+err.Error())
		return 3
	}

	gitInfo := gitutil.ReadInfo(absRoot)

	scanCtx := &rules.Context{
		Repo:        repo,
		Config:      cfg,
		Git:         gitInfo,
		Branch:      firstNonEmpty(gitInfo.Branch, opts.branch),
		ProjectType: repo.DetectProjectType(),
		LinkEnabled: !cfg.Settings.Offline && !opts.noLinks,
		Logf: func(format string, a ...any) {
			if opts.verbose {
				fmt.Fprintf(os.Stderr, "[spec-guardian] "+format+"\n", a...)
			}
		},
	}

	if scanCtx.LinkEnabled && cfg.Settings.LinkCheck.Enabled {
		links, checkResults := collectLinks(scanCtx, opts)
		scanCtx.Links = links
		scanCtx.LinkResults = checkResults
		scanCtx.Logf("checked %d links", len(checkResults))
	} else if cfg.Settings.LinkCheck.Enabled {
		scanCtx.Logf("link checking disabled (offline)")
	}

	engine := rules.NewEngine(cfg)
	findings := engine.Run(scanCtx)

	report := reporter.NewReport(findings, engine.Rules())
	report.Version = version
	report.Root = absRoot
	report.Branch = scanCtx.Branch
	report.Offline = cfg.Settings.Offline
	report.ProjectType = string(scanCtx.ProjectType)
	report.FileCount = repo.Count()
	if gitInfo != nil {
		report.Commit = gitInfo.CommitSHA
		report.Origin = gitInfo.OriginURL
	}

	if opts.fixPreview != "" {
		if err := writeFixPreview(opts.fixPreview, findings); err != nil {
			fmt.Fprintln(os.Stderr, "spec-guardian: "+err.Error())
			return 3
		}
		fmt.Fprintln(os.Stderr, "Wrote fix preview to "+opts.fixPreview+" (nothing was modified).")
	}

	if err := renderOutputs(opts, report); err != nil {
		fmt.Fprintln(os.Stderr, "spec-guardian: "+err.Error())
		return 3
	}
	if opts.summaryFile != "" {
		if err := appendSummary(opts.summaryFile, report); err != nil {
			fmt.Fprintln(os.Stderr, "spec-guardian: "+err.Error())
			return 3
		}
	}

	if opts.failOn == "none" {
		return 0
	}
	failOn, _ := scanner.ParseSeverity(opts.failOn)
	return reporter.ExitCode(findings, failOn)
}

func collectLinks(scanCtx *rules.Context, opts *options) ([]scanner.Link, map[string]netcheck.Result) {
	var all []scanner.Link
	var urls []string
	seen := map[string]bool{}
	for _, f := range scanCtx.Repo.MarkdownFiles() {
		links, err := scanner.ExtractLinks(f)
		if err != nil {
			continue
		}
		for _, l := range links {
			all = append(all, l)
			if !seen[l.URL] {
				seen[l.URL] = true
				urls = append(urls, l.URL)
			}
		}
		if len(urls) > 5000 {
			break
		}
	}
	return all, checkLinksWithConfig(scanCtx, urls)
}
