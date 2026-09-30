package scanner

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// walk performs an iterative (non-recursive-call) directory traversal so deep
// trees do not risk the goroutine stack, invoking fn for every regular file.
func walk(root, rel string, opts IndexOptions, skip map[string]bool, fn func(FileEntry) error) error {
	type item struct {
		abs string
		rel string
	}
	stack := []item{{abs: root, rel: rel}}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(cur.abs)
		if err != nil {
			if cur.rel == "" {
				return err
			}
			continue
		}
		for _, de := range entries {
			name := de.Name()
			childRel := joinRel(cur.rel, name)
			childAbs := filepath.Join(cur.abs, name)

			if de.IsDir() {
				if skip[name] {
					continue
				}
				stack = append(stack, item{abs: childAbs, rel: childRel})
				continue
			}
			if de.Type()&os.ModeSymlink != 0 {
				if !opts.FollowSymlinks {
					continue
				}
				fi, err := os.Stat(childAbs)
				if err != nil {
					continue
				}
				if fi.IsDir() {
					if skip[name] {
						continue
					}
					stack = append(stack, item{abs: childAbs, rel: childRel})
					continue
				}
			}
			if !de.Type().IsRegular() && de.Type()&os.ModeSymlink == 0 {
				continue
			}
			info, err := de.Info()
			if err != nil {
				continue
			}
			if err := fn(FileEntry{Path: childRel, Abs: childAbs, Size: info.Size()}); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReadFile reads a repo-relative file, capping the amount read at maxBytes
// (<= 0 means unlimited). It is the only intended way rules load file content.
func (r *Repo) ReadFile(rel string, maxBytes int64) ([]byte, error) {
	abs := filepath.Join(r.Root, filepath.FromSlash(rel))
	if maxBytes <= 0 {
		return os.ReadFile(abs)
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, err := readFull(f, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func readFull(f *os.File, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := f.Read(buf[total:])
		total += n
		if err != nil {
			if n == 0 {
				return total, nil
			}
			return total, nil
		}
	}
	return total, nil
}

// ReadFileString is a convenience wrapper around ReadFile.
func (r *Repo) ReadFileString(rel string, maxBytes int64) (string, bool) {
	b, err := r.ReadFile(rel, maxBytes)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func joinRel(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}

func pathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func pathDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		if i == 0 {
			return "."
		}
		return p[:i]
	}
	return "."
}

func normalizeRel(p string) string {
	p = strings.TrimPrefix(strings.ReplaceAll(p, "\\", "/"), "./")
	return strings.TrimSuffix(p, "/")
}

// MatchPath reports whether a slash-separated path matches a glob pattern.
//
// Supported syntax:
//   - "**" matches zero or more path segments
//   - "*"  matches within a single path segment
//   - "?"  matches a single non-separator character
//   - a bare name with no slash also matches a path segment (e.g. "vendor"
//     matches "a/vendor" and "vendor/x")
//   - a trailing slash means "this directory and everything under it"
func MatchPath(pattern, p string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	p = normalizeRel(p)

	// A trailing slash means "this directory and everything beneath it".
	if strings.HasSuffix(pattern, "/") {
		base := strings.TrimSuffix(pattern, "/")
		return MatchPath(base+"/**", p)
	}

	// A bare directory token with no glob metacharacters matches any single
	// path segment, e.g. "vendor" matches "vendor" and "a/vendor".
	if !strings.ContainsAny(pattern, "*?[") && !strings.Contains(pattern, "/") {
		for _, seg := range strings.Split(p, "/") {
			if seg == pattern {
				return true
			}
		}
		return false
	}

	// A glob without a slash (e.g. "*.md") matches the basename or any single
	// path segment, mirroring .gitignore semantics.
	if !strings.Contains(pattern, "/") {
		if ok, _ := path.Match(pattern, pathBase(p)); ok {
			return true
		}
		for _, seg := range strings.Split(p, "/") {
			if ok, _ := path.Match(pattern, seg); ok {
				return true
			}
		}
		return false
	}

	// Directory prefix patterns such as "vendor/**" should also match the
	// directory entry itself.
	if strings.HasSuffix(pattern, "/**") {
		base := strings.TrimSuffix(pattern, "/**")
		if p == base || strings.HasPrefix(p, base+"/") {
			return true
		}
	}

	return matchSegments(strings.Split(pattern, "/"), strings.Split(p, "/"))
}

func matchSegments(pat, parts []string) bool {
	if len(pat) == 0 {
		return len(parts) == 0
	}
	if pat[0] == "**" {
		// Collapse consecutive **.
		rest := pat[1:]
		for len(rest) > 0 && rest[0] == "**" {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return true
		}
		for i := 0; i <= len(parts); i++ {
			if matchSegments(rest, parts[i:]) {
				return true
			}
		}
		return false
	}
	if len(parts) == 0 {
		return false
	}
	ok, err := path.Match(pat[0], parts[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pat[1:], parts[1:])
}
