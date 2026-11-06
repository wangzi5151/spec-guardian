package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "specguard-rules.yml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigUsesFailOnDefault(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "version: 1\nsettings:\n  fail_on: medium\n")

	opts := defaultOptions()
	opts.rulesFile = path
	cfg, err := loadConfig(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Settings.FailOn != scanner.SeverityMedium {
		t.Fatalf("config FailOn = %q, want medium", cfg.Settings.FailOn)
	}
	if opts.failOn != "medium" {
		t.Fatalf("effective failOn = %q, want medium", opts.failOn)
	}
}

func TestLoadConfigExplicitFailOnWins(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "version: 1\nsettings:\n  fail_on: medium\n")

	opts := defaultOptions()
	opts.rulesFile = path
	opts.failOn = "low"
	opts.failOnSet = true
	if _, err := loadConfig(dir, opts); err != nil {
		t.Fatal(err)
	}
	if opts.failOn != "low" {
		t.Fatalf("explicit failOn = %q, want low", opts.failOn)
	}
}

func TestLoadConfigFailOnNone(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "version: 1\nsettings:\n  fail_on: none\n")

	opts := defaultOptions()
	opts.rulesFile = path
	cfg, err := loadConfig(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Settings.FailOnNone {
		t.Fatal("FailOnNone not set for fail_on: none")
	}
	if opts.failOn != "none" {
		t.Fatalf("effective failOn = %q, want none", opts.failOn)
	}
}

func TestParseArgsRejectsInvalidIntegers(t *testing.T) {
	for _, args := range [][]string{
		{"--timeout", "abc"},
		{"--timeout=1.5"},
		{"--concurrency", "many"},
		{"--concurrency=nope"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("parseArgs(%v) succeeded, want error", args)
		}
	}
}

func TestParseArgsAcceptsIntegers(t *testing.T) {
	opts, err := parseArgs([]string{"--timeout", "12", "--concurrency=5", "--fail-on", "low"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.timeout != 12 || opts.conc != 5 {
		t.Fatalf("timeout=%d conc=%d", opts.timeout, opts.conc)
	}
	if opts.failOn != "low" || !opts.failOnSet {
		t.Fatalf("failOn=%q set=%v", opts.failOn, opts.failOnSet)
	}
}
