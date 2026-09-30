// Package netcheck performs bounded-concurrency HTTP liveness checks for links
// discovered in documentation. It is intentionally conservative: it caps both
// global and per-host concurrency, honors allow/deny lists, never touches
// localhost, and can fall back to the Wayback Machine for dead links.
package netcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Result is the outcome of checking a single URL.
type Result struct {
	URL        string `json:"url"`
	OK         bool   `json:"ok"`
	Status     int    `json:"status,omitempty"`
	Err        string `json:"error,omitempty"`
	Skipped    bool   `json:"skipped,omitempty"`
	SkipReason string `json:"skipReason,omitempty"`
	Archived   bool   `json:"archived,omitempty"`
	ArchiveURL string `json:"archiveUrl,omitempty"`
}

// Options configures a Checker.
type Options struct {
	Concurrency  int
	Timeout      time.Duration
	PerHostLimit int
	UserAgent    string
	Allowlist    []string
	Denylist     []string
	CheckArchive bool
}

// Checker checks URLs with bounded concurrency.
type Checker struct {
	client       *http.Client
	concurrency  int
	perHostLimit int
	userAgent    string
	allowlist    []string
	denylist     []string
	checkArchive bool

	mu       sync.Mutex
	hostSems map[string]chan struct{}
}

// New creates a Checker. Offline callers should simply not invoke it.
func New(opts Options) *Checker {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.PerHostLimit <= 0 {
		opts.PerHostLimit = 2
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "Spec-Guardian-LinkChecker/1.0 (+https://github.com/wangzi5151/spec-guardian)"
	}
	return &Checker{
		client:       &http.Client{Timeout: opts.Timeout},
		concurrency:  opts.Concurrency,
		perHostLimit: opts.PerHostLimit,
		userAgent:    opts.UserAgent,
		allowlist:    opts.Allowlist,
		denylist:     opts.Denylist,
		checkArchive: opts.CheckArchive,
		hostSems:     map[string]chan struct{}{},
	}
}

// CheckAll checks a set of unique URLs and returns a result per URL.
func (c *Checker) CheckAll(ctx context.Context, urls []string) map[string]Result {
	unique := map[string]bool{}
	var list []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || unique[u] {
			continue
		}
		unique[u] = true
		list = append(list, u)
	}

	results := make(map[string]Result, len(list))
	var mu sync.Mutex
	sem := make(chan struct{}, c.concurrency)
	var wg sync.WaitGroup

	for _, u := range list {
		u := u
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res := c.Check(ctx, u)
			mu.Lock()
			results[u] = res
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

// Check probes a single URL.
func (c *Checker) Check(ctx context.Context, raw string) Result {
	if reason, skip := c.ShouldSkip(raw); skip {
		return Result{URL: raw, Skipped: true, SkipReason: reason, OK: true}
	}
	res := c.probe(ctx, raw)
	if res.Status >= 200 && res.Status < 400 {
		res.OK = true
		return res
	}
	if !res.OK && c.checkArchive && !res.Skipped {
		if arc, ok := c.wayback(ctx, raw); ok {
			res.Archived = true
			res.ArchiveURL = arc
		}
	}
	return res
}

func (c *Checker) probe(ctx context.Context, raw string) Result {
	res := Result{URL: raw}
	if err := c.acquireHost(ctx, raw); err != nil {
		res.Err = err.Error()
		return res
	}
	defer c.releaseHost(raw)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, raw, nil)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	_ = resp.Body.Close()
	res.Status = resp.StatusCode

	// Some servers reject HEAD; retry with a ranged GET.
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotImplemented {
		req2, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return res
		}
		req2.Header.Set("User-Agent", c.userAgent)
		req2.Header.Set("Range", "bytes=0-0")
		resp2, err := c.client.Do(req2)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		_ = resp2.Body.Close()
		res.Status = resp2.StatusCode
	}
	return res
}

func (c *Checker) acquireHost(ctx context.Context, raw string) error {
	host := hostOf(raw)
	key := host
	if key == "" {
		key = raw
	}
	c.mu.Lock()
	sem, ok := c.hostSems[key]
	if !ok {
		sem = make(chan struct{}, c.perHostLimit)
		c.hostSems[key] = sem
	}
	c.mu.Unlock()
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Checker) releaseHost(raw string) {
	key := hostOf(raw)
	if key == "" {
		key = raw
	}
	c.mu.Lock()
	sem := c.hostSems[key]
	c.mu.Unlock()
	if sem != nil {
		select {
		case <-sem:
		default:
		}
	}
}

// ShouldSkip reports whether a URL should not be probed, with the reason.
func (c *Checker) ShouldSkip(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "empty", true
	}
	if strings.HasPrefix(raw, "#") {
		return "anchor", true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "not an absolute URL", true
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "non-http scheme", true
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range []string{"localhost", "127.0.0.1", "0.0.0.0", "::1"} {
		if host == h || strings.HasSuffix(host, "."+h) {
			return "localhost", true
		}
	}
	if isPlaceholderHost(host) {
		return "placeholder host", true
	}
	for _, d := range c.denylist {
		if matchDomain(host, d) {
			return "denylisted", true
		}
	}
	if len(c.allowlist) > 0 {
		allowed := false
		for _, a := range c.allowlist {
			if matchDomain(host, a) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "not allowlisted", true
		}
	}
	return "", false
}

func isPlaceholderHost(host string) bool {
	placeholders := []string{
		"example.com", "example.org", "example.net", "example.edu",
		"your-domain.com", "yourdomain.com", "your-company.com",
		"foo.com", "bar.com", "test.com", "domain.com", "localhost.localdomain",
	}
	for _, p := range placeholders {
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	if strings.Contains(host, "xxxx") || strings.Contains(host, "your-") {
		return true
	}
	return false
}

func matchDomain(host, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	host = strings.ToLower(host)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

func (c *Checker) wayback(ctx context.Context, raw string) (string, bool) {
	endpoint := "https://archive.org/wayback/available?url=" + url.QueryEscape(raw)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var payload struct {
		ArchivedSnapshots struct {
			Closest struct {
				Available bool   `json:"available"`
				URL       string `json:"url"`
			} `json:"closest"`
		} `json:"archived_snapshots"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", false
	}
	if payload.ArchivedSnapshots.Closest.Available && payload.ArchivedSnapshots.Closest.URL != "" {
		return payload.ArchivedSnapshots.Closest.URL, true
	}
	return "", false
}

// FormatResult renders a concise human string.
func (r Result) FormatResult() string {
	switch {
	case r.Skipped:
		return fmt.Sprintf("skipped (%s)", r.SkipReason)
	case r.OK:
		return fmt.Sprintf("ok (%d)", r.Status)
	case r.Err != "":
		return fmt.Sprintf("error: %s", r.Err)
	default:
		return fmt.Sprintf("dead (%d)", r.Status)
	}
}
