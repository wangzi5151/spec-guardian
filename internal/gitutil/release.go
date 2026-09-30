package gitutil

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Release is a GitHub release summary.
type Release struct {
	TagName string         `json:"tag_name"`
	Name    string         `json:"name"`
	Body    string         `json:"body"`
	HTMLURL string         `json:"html_url"`
	Assets  []ReleaseAsset `json:"assets"`
}

// ReleaseAsset is a single release asset.
type ReleaseAsset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// LatestRelease fetches the latest release of a GitHub repository. A non-nil
// error indicates the lookup failed (network, rate limit, or no releases).
func LatestRelease(ctx context.Context, owner, repo, token string, timeout time.Duration) (*Release, error) {
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("missing owner/repo")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Spec-Guardian/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned %d", resp.StatusCode)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}
