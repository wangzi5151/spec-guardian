package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/wangzi5151/spec-guardian/internal/netcheck"
	"github.com/wangzi5151/spec-guardian/internal/reporter"
	"github.com/wangzi5151/spec-guardian/internal/rules"
	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

func loadConfig(root string, opts *options) (*rules.Config, error) {
	path := opts.rulesFile
	explicit := path != ""
	if !explicit {
		for _, cand := range rules.DefaultConfigPaths {
			p := filepath.Join(root, cand)
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	cfg, err := rules.LoadConfig(path, explicit)
	if err != nil {
		return nil, err
	}
	cfg.Settings.Offline = cfg.Settings.Offline || opts.offline
	cfg.Settings.HeaderComment = cfg.Settings.HeaderComment || opts.headerComment
	cfg.Settings.Exclude = append(cfg.Settings.Exclude, opts.excludes...)
	if opts.timeout > 0 {
		cfg.Settings.LinkCheck.TimeoutSeconds = opts.timeout
	}
	if opts.conc > 0 {
		cfg.Settings.LinkCheck.Concurrency = opts.conc
	}
	return cfg, nil
}

func checkLinksWithConfig(scanCtx *rules.Context, urls []string) map[string]netcheck.Result {
	lc := scanCtx.Config.Settings.LinkCheck
	timeout := time.Duration(lc.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	checker := netcheck.New(netcheck.Options{
		Concurrency:  lc.Concurrency,
		Timeout:      timeout,
		PerHostLimit: 2,
		Allowlist:    lc.Allowlist,
		Denylist:     lc.Denylist,
		CheckArchive: true,
	})
	return checker.CheckAll(context.Background(), urls)
}

func renderOutputs(opts *options, report *reporter.Report) error {
	color := !opts.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout)
	if opts.outDir != "" {
		if err := os.MkdirAll(opts.outDir, 0o755); err != nil {
			return err
		}
	}
	single := len(opts.formats) == 1

	for _, format := range opts.formats {
		switch format {
		case "text":
			if opts.quiet {
				continue
			}
			if opts.out != "" && single {
				f, err := os.Create(opts.out)
				if err != nil {
					return err
				}
				reporter.RenderTerminal(f, report, color)
				f.Close()
				continue
			}
			if opts.outDir != "" {
				p := filepath.Join(opts.outDir, "specguard-report.txt")
				f, err := os.Create(p)
				if err != nil {
					return err
				}
				reporter.RenderTerminal(f, report, color)
				f.Close()
				continue
			}
			reporter.RenderTerminal(os.Stdout, report, color)
		case "json":
			w, closeFn, err := pickWriter(opts, single, "specguard-report.json")
			if err != nil {
				return err
			}
			if err := reporter.WriteJSON(w, report); err != nil {
				closeFn()
				return err
			}
			closeFn()
		case "html":
			w, closeFn, err := pickWriter(opts, single, "specguard-report.html")
			if err != nil {
				return err
			}
			if err := reporter.WriteHTML(w, report); err != nil {
				closeFn()
				return err
			}
			closeFn()
			if opts.out == "" || !single {
				dest := opts.out
				if dest == "" {
					if opts.outDir != "" {
						dest = filepath.Join(opts.outDir, "specguard-report.html")
					} else {
						dest = "specguard-report.html"
					}
				}
				if !opts.quiet {
					fmt.Fprintln(os.Stderr, "HTML report written to "+dest)
				}
			}
		default:
			return fmt.Errorf("unknown format %q (use text, json, html or all)", format)
		}
	}
	return nil
}

func pickWriter(opts *options, single bool, defaultName string) (writer, func(), error) {
	if opts.out != "" && single {
		f, err := os.Create(opts.out)
		if err != nil {
			return nil, func() {}, err
		}
		return f, func() { f.Close() }, nil
	}
	if opts.outDir != "" {
		f, err := os.Create(filepath.Join(opts.outDir, defaultName))
		if err != nil {
			return nil, func() {}, err
		}
		return f, func() { f.Close() }, nil
	}
	return os.Stdout, func() {}, nil
}

type writer interface {
	Write(p []byte) (int, error)
}

func appendSummary(path string, report *reporter.Report) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return reporter.WriteMarkdownSummary(f, report)
}

func writeFixPreview(path string, findings []scanner.Finding) error {
	var b strings.Builder
	b.WriteString("# Spec-Guardian suggested fixes — REVIEW ONLY, not applied automatically.\n")
	b.WriteString("# Apply with: git apply --check " + filepath.Base(path) + " && git apply " + filepath.Base(path) + "\n\n")
	count := 0
	for _, f := range findings {
		if f.Patch == "" {
			continue
		}
		b.WriteString("# rule: " + f.RuleID + "\n")
		if f.File != "" {
			b.WriteString("# file: " + f.File + "\n")
		}
		b.WriteString(f.Patch)
		if !strings.HasSuffix(f.Patch, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("\n")
		count++
	}
	if count == 0 {
		b.WriteString("# No automatically suggestible patches were produced.\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func runExportRules(opts *options) int {
	dest := firstNonEmpty(opts.exportRules, opts.out)
	engine := rules.NewEngine(rules.DefaultConfig())
	metas := engine.Rules()
	sort.Slice(metas, func(i, j int) bool { return metas[i].ID < metas[j].ID })

	var b strings.Builder
	b.WriteString("# Spec-Guardian rule configuration template\n")
	b.WriteString("# Reuse this file in another repository via: spec-guardian scan --rules this-file.yml\n")
	b.WriteString("version: 1\n\n")
	b.WriteString("settings:\n")
	b.WriteString("  offline: false\n")
	b.WriteString("  fail_on: high            # high | medium | low | none\n")
	b.WriteString("  max_file_size_kb: 1024\n")
	b.WriteString("  exclude:\n")
	b.WriteString("    - vendor/**\n")
	b.WriteString("    - node_modules/**\n")
	b.WriteString("  link_check:\n")
	b.WriteString("    enabled: true\n")
	b.WriteString("    concurrency: 8\n")
	b.WriteString("    timeout_seconds: 10\n\n")
	b.WriteString("# Per-rule overrides. Uncomment and edit to disable a rule or change severity.\n")
	b.WriteString("rules:\n")
	for _, m := range metas {
		b.WriteString("  # " + m.ID + "  (" + string(m.DefaultSeverity) + ")  " + m.Title + "\n")
	}
	b.WriteString("\n# severity_overrides:\n")
	b.WriteString("#   repo.readme.limitations: info\n\n")
	b.WriteString("# disabled_rules:\n")
	b.WriteString("#   - security.large_files\n\n")
	b.WriteString("# custom_rules:\n")
	b.WriteString("#   - id: custom.no_todo_in_docs\n")
	b.WriteString("#     severity: low\n")
	b.WriteString("#     description: No TODO markers in docs\n")
	b.WriteString("#     message: Found TODO marker\n")
	b.WriteString("#     type: regex\n")
	b.WriteString("#     pattern: \"TODO\"\n")
	b.WriteString("#     files: [\"**/*.md\"]\n")

	out := b.String()
	if dest == "" || dest == "-" {
		fmt.Print(out)
		return 0
	}
	if err := os.WriteFile(dest, []byte(out), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "spec-guardian: "+err.Error())
		return 3
	}
	fmt.Fprintln(os.Stderr, "Rule template written to "+dest)
	return 0
}

func runListRules(opts *options) int {
	engine := rules.NewEngine(rules.DefaultConfig())
	metas := engine.Rules()
	sort.Slice(metas, func(i, j int) bool { return metas[i].ID < metas[j].ID })
	fmt.Printf("%-34s %-8s %s\n", "RULE ID", "SEVERITY", "TITLE")
	fmt.Println(strings.Repeat("-", 90))
	for _, m := range metas {
		fmt.Printf("%-34s %-8s %s\n", m.ID, m.DefaultSeverity, m.Title)
	}
	fmt.Printf("\n%d rules. Configure via specguard-rules.yml.\n", len(metas))
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
