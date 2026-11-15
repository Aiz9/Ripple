package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Repo is fixed: configurable executable sources grant code execution to configuration editors,
// an inappropriate capability for this platform.
const Repo = "mhtsec/ARTEX"

// latestURL asks GitHub for the latest stable release, excluding draft/prerelease.
const latestURL = "https://api.github.com/repos/" + Repo + "/releases/latest"

// allowedHosts plus checkRedirect rejects any hop outside approved domains, guarding against
// redirected binary substitution; SHA256SUMS validation supplies the second gate.
// Enforce the host boundary across the full chain.
var allowedHosts = map[string]bool{
	"api.github.com":                       true,
	"github.com":                           true,
	"objects.githubusercontent.com":        true, // Object storage hosting actual release assets.
	"release-assets.githubusercontent.com": true,
	"raw.githubusercontent.com":            true,
}

// Release contains relevant GitHub release fields.
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Assets      []Asset   `json:"assets"`
}

// Asset represents one attached file.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// NewClient permits only GitHub domains; empty proxy means direct.
//
// Do not reuse default Transport: updates must enforce TLS/certificate validation independently
// of unrelated InsecureSkipVerify settings.
func NewClient(proxy string) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if p := strings.TrimSpace(proxy); p != "" {
		if pu, err := url.Parse(p); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Minute, // Full package downloads must not hit an overly restrictive per-request timeout.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("Too many redirects")
			}
			return checkURL(req.URL)
		},
	}
}

// checkURL enforces HTTPS and host allowlist.
func checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("Refusing non-HTTPS URL: %s", u.Scheme+"://"+u.Host)
	}
	if !allowedHosts[strings.ToLower(u.Hostname())] {
		return fmt.Errorf("Refusing non-GitHub domain: %s", u.Hostname())
	}
	return nil
}

// FetchLatest reads latest stable release.
func FetchLatest(ctx context.Context, c *http.Client) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURL, nil)
	if err != nil {
		return nil, err
	}
	if err := checkURL(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "artex-selfupdate")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub request failed (configure a global proxy in system settings if needed): %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusTooManyRequests:
		// Unauthenticated API allows 60/IP/hour, easily exhausted behind shared egress.
		return nil, fmt.Errorf("GitHub API rate limit reached (60 requests/hour); try again later")
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("Repository %s has no stable releases yet", Repo)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GitHub returned %d", resp.StatusCode)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("Failed to parse release: %w", err)
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return nil, fmt.Errorf("Release has no tag")
	}
	return &rel, nil
}

// AssetName matches build.sh package_binary naming:
// artex-<version>-<os>-<arch>.zip without a leading v in version.
func AssetName(tag, goos, goarch string) string {
	return fmt.Sprintf("artex-%s-%s-%s.zip", strings.TrimPrefix(tag, "v"), goos, goarch)
}

// FindAsset locates a release file by name.
func (r *Release) FindAsset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Asset{}, false
}
