package netcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestShouldSkip(t *testing.T) {
	c := New(Options{})
	cases := []struct {
		url  string
		skip bool
	}{
		{"#section", true},
		{"https://localhost/x", true},
		{"http://127.0.0.1:8080", true},
		{"https://example.com/foo", true},
		{"https://your-domain.com", true},
		{"mailto:a@b.com", true},
		{"https://github.com/owner/repo", false},
	}
	for _, tc := range cases {
		_, skip := c.ShouldSkip(tc.url)
		if skip != tc.skip {
			t.Errorf("ShouldSkip(%q)=%v want %v", tc.url, skip, tc.skip)
		}
	}
}

func TestProbeAliveAndDead(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(Options{Concurrency: 2, Timeout: 5 * time.Second, CheckArchive: false})
	ctx := context.Background()

	// Call probe directly because localhost URLs are intentionally skipped by Check.
	alive := c.probe(ctx, srv.URL+"/ok")
	if alive.Status != 200 || alive.Err != "" {
		t.Errorf("expected 200 alive, got %+v", alive)
	}
	dead := c.probe(ctx, srv.URL+"/missing")
	if dead.Status != 404 {
		t.Errorf("expected 404 dead, got %+v", dead)
	}
}

func TestCheckAllDeduplicates(t *testing.T) {
	c := New(Options{CheckArchive: false})
	res := c.CheckAll(context.Background(), []string{"https://example.com", "https://example.com"})
	if len(res) != 1 {
		t.Errorf("expected deduplication, got %d", len(res))
	}
}
