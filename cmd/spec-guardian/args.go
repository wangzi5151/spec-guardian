package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

type options struct {
	command       string
	path          string
	repoURL       string
	branch        string
	rulesFile     string
	formats       []string
	out           string
	outDir        string
	offline       bool
	noColor       bool
	noLinks       bool
	failOn        string
	excludes      []string
	timeout       int
	conc          int
	fixPreview    string
	exportRules   string
	summaryFile   string
	quiet         bool
	verbose       bool
	headerComment bool
	showHelp      bool
	showVersion   bool
}

func defaultOptions() *options {
	return &options{
		command: "scan",
		path:    ".",
		formats: []string{"text"},
		failOn:  "high",
	}
}

var knownCommands = map[string]bool{
	"scan": true, "export-rules": true, "rules": true, "version": true, "help": true,
}

func parseArgs(args []string) (*options, error) {
	o := defaultOptions()
	i := 0
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if knownCommands[args[0]] {
			o.command = args[0]
			if args[0] == "help" {
				o.showHelp = true
			}
			if args[0] == "version" {
				o.showVersion = true
			}
			i = 1
		}
	}

	next := func(flag string) (string, error) {
		if i+1 >= len(args) {
			return "", fmt.Errorf("flag %s requires a value", flag)
		}
		i++
		return args[i], nil
	}

	for ; i < len(args); i++ {
		arg := args[i]
		name := arg
		value := ""
		hasValue := false
		if strings.HasPrefix(arg, "--") {
			if eq := strings.IndexByte(arg, '='); eq >= 0 {
				name = arg[:eq]
				value = arg[eq+1:]
				hasValue = true
			}
		}
		val := func(flag string) (string, error) {
			if hasValue {
				return value, nil
			}
			return next(flag)
		}

		switch name {
		case "-h", "--help":
			o.showHelp = true
		case "-V", "--version":
			o.showVersion = true
		case "-p", "--path":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.path = v
		case "--repo", "--repository":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.repoURL = v
		case "--branch":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.branch = v
		case "--rules", "--config":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.rulesFile = v
		case "-f", "--format":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.formats = splitFormats(v)
		case "-o", "--out", "--output":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.out = v
		case "--out-dir":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.outDir = v
		case "--offline", "--no-network":
			o.offline = true
		case "--no-color":
			o.noColor = true
		case "--no-links":
			o.noLinks = true
		case "--fail-on":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.failOn = strings.ToLower(v)
		case "--exclude":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.excludes = append(o.excludes, v)
		case "--timeout":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.timeout, _ = strconv.Atoi(v)
		case "--concurrency":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.conc, _ = strconv.Atoi(v)
		case "--fix-preview":
			if hasValue {
				o.fixPreview = value
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				o.fixPreview = args[i]
			} else {
				o.fixPreview = "specguard-fix.patch"
			}
		case "--export-rules":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.exportRules = v
		case "--summary":
			v, err := val(name)
			if err != nil {
				return nil, err
			}
			o.summaryFile = v
		case "--header-comment-check":
			o.headerComment = true
		case "--quiet", "-q":
			o.quiet = true
		case "--verbose", "-v":
			o.verbose = true
		default:
			if strings.HasPrefix(arg, "-") {
				return nil, fmt.Errorf("unknown flag %q", arg)
			}
			// Positional path (only meaningful for scan).
			o.path = arg
		}
	}
	return o, nil
}

func splitFormats(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if p == "all" {
			return []string{"text", "json", "html"}
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return []string{"text"}
	}
	return out
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Spec-Guardian — Open-Source Repository Health Auditor. Not a Code Linter.

Usage:
  spec-guardian [scan] [path] [flags]
  spec-guardian scan --repo <git-url> [flags]
  spec-guardian export-rules [--out FILE]
  spec-guardian rules
  spec-guardian version

Scan flags:
  -p, --path DIR           Local repository path to scan (default ".")
      --repo URL           Shallow-clone a remote repository and scan it
      --branch BRANCH      Branch to clone (with --repo)
      --rules, --config F  Rule configuration file (YAML)
  -f, --format LIST        Output formats: text,json,html,all (default text)
  -o, --out FILE           Output file (single format)
      --out-dir DIR        Directory for json/html outputs
      --offline            Do not perform any network requests
      --no-links           Skip link checking (keep other checks)
      --no-color           Disable ANSI colors
      --exclude GLOB       Exclude path pattern (repeatable)
      --fail-on LEVEL      Exit non-zero from this severity up: high,medium,low,none
      --timeout SECONDS    Link check timeout (default 10)
      --concurrency N      Link check concurrency (default 8)
      --header-comment-check  Enable the optional source-header rule
      --fix-preview [FILE]  Write a .patch preview of suggested textual fixes
      --summary FILE       Append a Markdown summary (for GITHUB_STEP_SUMMARY)
      --verbose            Verbose progress on stderr
  -h, --help               Show this help
  -V, --version            Show version

Exit codes:
  0  no blocking findings        1  high severity findings present
  2  only medium/low/info        3  runtime error

Spec-Guardian audits repository metadata only. It does not scan source code
logic or perform security static analysis — use gosec/semgrep/gitleaks for that.
`)
}
