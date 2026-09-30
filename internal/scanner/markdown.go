package scanner

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// Link is an extracted hyperlink reference from a Markdown file.
type Link struct {
	URL  string
	File string
	Line int
}

// Heading is a Markdown ATX heading.
type Heading struct {
	Level int
	Text  string
	Line  int
}

var (
	reInlineLink = regexp.MustCompile(`\[[^\]]*\]\(\s*<?([^)\s>]+)>?[^)]*\)`)
	reAutoLink   = regexp.MustCompile(`<((?:https?)://[^>\s]+)>`)
	reBareURL    = regexp.MustCompile(`(?:^|[^\w("'<])((?:https?)://[^\s)<>"'\]}]+)`)
	reHeading    = regexp.MustCompile(`^(#{1,6})\s+(.*?)\s*#*\s*$`)
)

// ExtractLinks streams a Markdown file and returns the http/https links it
// contains, skipping fenced code regions. Only file metadata is retained
// between lines, so memory stays bounded even for huge documents.
func ExtractLinks(entry FileEntry) ([]Link, error) {
	f, err := os.Open(entry.Abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var links []Link
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	inFence := false
	fenceTok := ""
	for sc.Scan() {
		line++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if tok, ok := fenceOpen(trimmed); ok {
			if !inFence {
				inFence = true
				fenceTok = tok
			} else if strings.HasPrefix(trimmed, fenceTok) {
				inFence = false
				fenceTok = ""
			}
			continue
		}
		if inFence {
			continue
		}
		for _, m := range reInlineLink.FindAllStringSubmatch(raw, -1) {
			links = append(links, Link{URL: m[1], File: entry.Path, Line: line})
		}
		for _, m := range reAutoLink.FindAllStringSubmatch(raw, -1) {
			links = append(links, Link{URL: m[1], File: entry.Path, Line: line})
		}
		for _, m := range reBareURL.FindAllStringSubmatch(raw, -1) {
			links = append(links, Link{URL: m[1], File: entry.Path, Line: line})
		}
	}
	if err := sc.Err(); err != nil {
		return links, err
	}
	return links, nil
}

func fenceOpen(trimmed string) (string, bool) {
	for _, tok := range []string{"```", "~~~"} {
		if strings.HasPrefix(trimmed, tok) {
			return tok, true
		}
	}
	return "", false
}

// MarkdownHeadings returns all ATX headings in a Markdown file, ignoring any
// lines inside fenced code blocks.
func MarkdownHeadings(content string) []Heading {
	var out []Heading
	inFence := false
	fenceTok := ""
	for i, raw := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(raw)
		if tok, ok := fenceOpen(trimmed); ok {
			if !inFence {
				inFence = true
				fenceTok = tok
			} else if strings.HasPrefix(trimmed, fenceTok) {
				inFence = false
				fenceTok = ""
			}
			continue
		}
		if inFence {
			continue
		}
		m := reHeading.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		out = append(out, Heading{Level: len(m[1]), Text: strings.TrimSpace(m[2]), Line: i + 1})
	}
	return out
}

// Section describes the content belonging to a heading.
type Section struct {
	Heading string
	Level   int
	Line    int
	Body    string
}

// SplitSections splits Markdown into sections keyed by their ATX heading,
// ignoring headings that appear inside fenced code blocks so that comment
// lines such as "# macOS" inside a code sample do not split a section.
func SplitSections(content string) []Section {
	lines := strings.Split(content, "\n")
	var sections []Section
	cur := Section{Line: 1}
	var body []string
	flush := func() {
		cur.Body = strings.Join(body, "\n")
		sections = append(sections, cur)
		body = nil
	}
	inFence := false
	fenceTok := ""
	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if tok, ok := fenceOpen(trimmed); ok {
			if !inFence {
				inFence = true
				fenceTok = tok
			} else if strings.HasPrefix(trimmed, fenceTok) {
				inFence = false
				fenceTok = ""
			}
			body = append(body, raw)
			continue
		}
		if !inFence {
			if m := reHeading.FindStringSubmatch(raw); m != nil {
				if cur.Heading != "" || len(body) > 0 {
					flush()
				}
				cur = Section{Heading: strings.TrimSpace(m[2]), Level: len(m[1]), Line: i + 1}
				continue
			}
		}
		body = append(body, raw)
	}
	flush()
	return sections
}

// HasHeadingMatching reports whether any heading matches one of the given
// case-insensitive substrings.
func HasHeadingMatching(content string, needles ...string) (Heading, bool) {
	for _, h := range MarkdownHeadings(content) {
		lt := strings.ToLower(h.Text)
		for _, n := range needles {
			if strings.Contains(lt, strings.ToLower(n)) {
				return h, true
			}
		}
	}
	return Heading{}, false
}

// FindSection returns the first section whose heading matches a needle.
func FindSection(content string, needles ...string) (Section, bool) {
	for _, s := range SplitSections(content) {
		lt := strings.ToLower(s.Heading)
		for _, n := range needles {
			if strings.Contains(lt, strings.ToLower(n)) {
				return s, true
			}
		}
	}
	return Section{}, false
}

var commandHints = []string{
	"go install", "go build", "go run",
	"npm install", "npm i ", "npm ci", "npm run", "npx ",
	"yarn add", "yarn install", "pnpm ",
	"pip install", "pipx ", "poetry install", "uv ",
	"cargo install", "cargo build", "cargo run",
	"make ", "cmake ", "meson ", "./configure",
	"brew install", "apt install", "apt-get install", "winget ", "scoop ",
	"curl ", "wget ", "docker run", "docker compose",
	"git clone", "python ", "python3 ", "node ", "deno ",
}

// LooksLikeCommand heuristically reports whether a text line looks like an
// installation or execution command a reader could try.
func LooksLikeCommand(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	if strings.HasPrefix(t, "$ ") || strings.HasPrefix(t, "> ") {
		return true
	}
	lt := strings.ToLower(t)
	for _, h := range commandHints {
		if strings.Contains(lt, h) {
			return true
		}
	}
	return false
}

// CountFencedCodeBlocks counts fenced code blocks in text.
func CountFencedCodeBlocks(content string) int {
	n := 0
	inFence := false
	for _, raw := range strings.Split(content, "\n") {
		if _, ok := fenceOpen(strings.TrimSpace(raw)); ok {
			if !inFence {
				inFence = true
			} else {
				inFence = false
				n++
			}
		}
	}
	return n
}
