package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"vendor", "vendor/x.go", true},
		{"vendor", "a/vendor/x.go", true},
		{"vendor", "myvendor/x.go", false},
		{"vendor/**", "vendor/a/b.go", true},
		{"vendor/**", "vendor", true},
		{"vendor/**", "src/main.go", false},
		{"node_modules", "node_modules/react/index.js", true},
		{"*.md", "README.md", true},
		{"*.md", "docs/README.md", true},
		{"docs/*.md", "docs/a.md", true},
		{"docs/*.md", "docs/sub/a.md", false},
		{"**/*.md", "a/b/c.md", true},
		{"**/*.env", ".env", true},
		{"**/node_modules/**", "a/node_modules/b/c.js", true},
		{"examples/", "examples/bad-repo/README.md", true},
	}
	for _, c := range cases {
		if got := MatchPath(c.pattern, c.path); got != c.want {
			t.Errorf("MatchPath(%q,%q)=%v want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestDetectLicense(t *testing.T) {
	mit := "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy..."
	info, ok := DetectLicense(mit)
	if !ok || info.SPDX != "MIT" {
		t.Fatalf("expected MIT, got %+v ok=%v", info, ok)
	}
	apache := "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/LICENSE-2.0"
	info, ok = DetectLicense(apache)
	if !ok || info.SPDX != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0, got %+v ok=%v", info, ok)
	}
	if _, ok := DetectLicense("all rights reserved, proprietary"); ok {
		t.Fatalf("unexpected recognition of proprietary text")
	}
}

func TestLicenseYears(t *testing.T) {
	_, reasonable := LicenseYears("Copyright (c) 2024 Example")
	if !reasonable {
		t.Fatalf("2024 should be reasonable")
	}
	_, reasonable = LicenseYears("Copyright (c) 3024 Example")
	if reasonable {
		t.Fatalf("3024 should be flagged")
	}
}

func TestGitignoreRisks(t *testing.T) {
	patterns := ParseGitignore("# comment\n.env\nnode_modules/\n")
	missing := MissingGitignoreRisks(patterns)
	for _, m := range missing {
		if m.Pattern == ".env" || m.Label == "node_modules" {
			t.Errorf("risk %q should be covered", m.Pattern)
		}
	}
	if len(missing) == 0 {
		t.Fatalf("expected some missing baseline risks")
	}
}

func TestExtractLinksSkipsFences(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "README.md")
	content := "# Title\n\nSee [a](https://a.example.com/x) and https://b.example.com/y\n\n" +
		"```\n[skip](https://skip.example.com)\n```\n\n#anchor\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	links, err := ExtractLinks(FileEntry{Path: "README.md", Abs: p})
	if err != nil {
		t.Fatal(err)
	}
	var urls []string
	for _, l := range links {
		urls = append(urls, l.URL)
	}
	if len(urls) != 2 {
		t.Fatalf("expected 2 links, got %v", urls)
	}
	for _, u := range urls {
		if u == "https://skip.example.com" {
			t.Fatalf("link inside code fence should be skipped")
		}
	}
}

func TestMarkdownSections(t *testing.T) {
	content := "# Title\n\nIntro paragraph here.\n\n## Quick Start\n\n```sh\ngo run .\n```\n"
	if _, ok := HasHeadingMatching(content, "quick start"); !ok {
		t.Fatalf("expected quick start heading")
	}
	sec, ok := FindSection(content, "quick start")
	if !ok {
		t.Fatal("expected section")
	}
	if !LooksLikeCommand(sec.Body) && CountFencedCodeBlocks(sec.Body) == 0 {
		t.Fatalf("expected a command in quick start: %q", sec.Body)
	}
}

func TestHeadingsIgnoreFencedComments(t *testing.T) {
	content := "## Quick Start\n\n```sh\n# macOS note\ncurl -fsSL https://x | sh\n```\n\n## Next\n"
	heads := MarkdownHeadings(content)
	if len(heads) != 2 {
		t.Fatalf("expected 2 headings, got %d: %+v", len(heads), heads)
	}
	sec, ok := FindSection(content, "quick start")
	if !ok {
		t.Fatal("quick start section not found")
	}
	if CountFencedCodeBlocks(sec.Body) == 0 {
		t.Fatalf("code fence should be part of the section body: %q", sec.Body)
	}
}

func TestSecretAssignmentHeuristics(t *testing.T) {
	positives := []string{
		"API_KEY=" + "Kf83nZqP0rLm2XwV7tYb4HcD9sNj6Qu",
		"export DB_PASSWORD=" + `"Rp42vTsW8yBn3McX6kLzQd1fHgJm5"`,
	}
	for _, p := range positives {
		if _, ok := LooksLikeSecretAssignment(p); !ok {
			t.Errorf("expected secret detection for %q", p)
		}
	}
	negatives := []string{
		`token := os.Getenv("GITHUB_TOKEN")`,
		`password = getPassword()`,
		`API_KEY=your_key_here`,
		`SECRET=$ENV_SECRET`,
		`if x == y {`,
		`const API_KEY = "${API_KEY}"`,
		`api_key=os.environ["GITHUB_TOKEN"]`,
		`author = commit['commit']['author']['name']`,
		`secret_key = var.secret_key`,
		`secret_name = "ALICLOUD_SECRET_KEY"`,
		`passwordField = app.secureTextFields["passwordTextField"]`,
	}
	for _, n := range negatives {
		if name, ok := LooksLikeSecretAssignment(n); ok {
			t.Errorf("unexpected secret detection %q -> %s", n, name)
		}
	}
}

func TestIndexExcludes(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.go"), "package a")
	mustWrite(t, filepath.Join(dir, "vendor", "b.go"), "package b")
	mustWrite(t, filepath.Join(dir, "node_modules", "c.js"), "x")
	repo, err := Index(dir, IndexOptions{Excludes: []string{"vendor/**"}})
	if err != nil {
		t.Fatal(err)
	}
	if repo.Exists("vendor/b.go") {
		t.Errorf("vendor should be excluded")
	}
	if !repo.Exists("a.go") {
		t.Errorf("a.go should exist")
	}
	if repo.Exists("node_modules/c.js") {
		t.Errorf("node_modules is skipped by default")
	}
}

func TestClassifySensitiveFile(t *testing.T) {
	if _, _, ok := ClassifySensitiveFile(".env"); !ok {
		t.Errorf(".env should be sensitive")
	}
	if _, _, ok := ClassifySensitiveFile(".env.example"); ok {
		t.Errorf(".env.example should be ignored")
	}
	if _, _, ok := ClassifySensitiveFile("id_rsa"); !ok {
		t.Errorf("id_rsa should be sensitive")
	}
	if _, _, ok := ClassifySensitiveFile("key.pub"); ok {
		t.Errorf("key.pub should be ignored")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
