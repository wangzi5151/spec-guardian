// Package gitutil reads local Git metadata and provides shallow remote clone
// helpers. It shells out to the git binary, which is assumed to be available;
// callers must degrade gracefully when it is not.
package gitutil

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Info is a snapshot of a repository's Git metadata.
type Info struct {
	IsRepo      bool
	Root        string
	OriginURL   string
	Host        string
	Owner       string
	Repo        string
	Branch      string
	CommitSHA   string
	CommitShort string
	Tags        []string
	Dirty       bool
}

// Available reports whether a usable git binary is on PATH.
func Available() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// ReadInfo collects metadata for the working tree at root. Errors are
// non-fatal and produce a partially populated Info.
func ReadInfo(root string) *Info {
	info := &Info{Root: root}
	if !Available() {
		return info
	}
	if out, ok := git(root, "rev-parse", "--is-inside-work-tree"); ok && strings.TrimSpace(out) == "true" {
		info.IsRepo = true
	} else {
		return info
	}
	if top, ok := git(root, "rev-parse", "--show-toplevel"); ok {
		info.Root = strings.TrimSpace(top)
	}
	if b, ok := git(root, "rev-parse", "--abbrev-ref", "HEAD"); ok {
		info.Branch = strings.TrimSpace(b)
	}
	if s, ok := git(root, "rev-parse", "HEAD"); ok {
		info.CommitSHA = strings.TrimSpace(s)
		if len(info.CommitSHA) >= 7 {
			info.CommitShort = info.CommitSHA[:7]
		}
	}
	if u, ok := git(root, "config", "--get", "remote.origin.url"); ok {
		info.OriginURL = strings.TrimSpace(u)
		info.Host, info.Owner, info.Repo = ParseRemoteURL(info.OriginURL)
	}
	if tags, ok := git(root, "tag", "--sort=-creatordate"); ok {
		for _, t := range strings.Split(strings.TrimSpace(tags), "\n") {
			if t = strings.TrimSpace(t); t != "" {
				info.Tags = append(info.Tags, t)
			}
			if len(info.Tags) >= 10 {
				break
			}
		}
	}
	if st, ok := git(root, "status", "--porcelain"); ok {
		info.Dirty = strings.TrimSpace(st) != ""
	}
	return info
}

func git(root string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	full := append([]string{"-C", root}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &bytes.Buffer{}
	if err := cmd.Run(); err != nil {
		return "", false
	}
	return out.String(), true
}

var remoteRe = regexp.MustCompile(`^(?:https?://|git://|ssh://)?(?:[^@/]+@)?([^:/]+)[:/]([^/]+)/(.+?)(?:\.git)?/?$`)

// ParseRemoteURL splits a Git remote URL into host, owner and repository.
func ParseRemoteURL(url string) (host, owner, repo string) {
	url = strings.TrimSpace(url)
	if url == "" {
		return "", "", ""
	}
	m := remoteRe.FindStringSubmatch(url)
	if m == nil {
		return "", "", ""
	}
	host = m[1]
	owner = m[2]
	repo = strings.TrimSuffix(m[3], ".git")
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		repo = repo[i+1:]
	}
	return host, owner, repo
}

// CloneRemote shallow-clones url into a temporary directory and returns the
// path along with a cleanup function. depth <= 0 defaults to 1. branch may be
// empty to use the remote default branch.
func CloneRemote(ctx context.Context, url, branch string, depth int) (string, func(), error) {
	if !Available() {
		return "", func() {}, fmt.Errorf("git binary not found on PATH")
	}
	if depth <= 0 {
		depth = 1
	}
	dir, err := os.MkdirTemp("", "specguardian-clone-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	args := []string{"clone", "--depth", fmt.Sprintf("%d", depth), "--no-tags", "--single-branch"}
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	args = append(args, "--", url, dir)
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("git clone failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return dir, cleanup, nil
}

// EnsureAbs returns an absolute, cleaned path.
func EnsureAbs(p string) (string, error) {
	if p == "" {
		p = "."
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}
