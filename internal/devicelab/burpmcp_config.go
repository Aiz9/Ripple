package devicelab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	burpURLMu       sync.RWMutex
	burpURLOverride string // set from UI settings; takes precedence over the env var
)

// SetBurpMCPURL sets a process-wide override for the Burp MCP endpoint (used when
// the operator configures it in the UI). Empty clears the override.
func SetBurpMCPURL(url string) {
	burpURLMu.Lock()
	burpURLOverride = strings.TrimSpace(url)
	burpURLMu.Unlock()
}

// BurpMCPURL resolves the Burp Suite MCP server endpoint, preferring a UI-set
// override, then ANDROIDLAB_BURP_MCP_URL, then the default http://127.0.0.1:9876.
//
// It points the autonomous assessment at a Burp instance whose "MCP Server"
// extension is enabled. Burp's invisible proxy listener captures proxy-unaware apps
// (e.g. Flutter); this URL is how the agent reads that captured traffic and replays
// requests. No key is needed — the extension binds to loopback by default.
func BurpMCPURL() string {
	burpURLMu.RLock()
	o := burpURLOverride
	burpURLMu.RUnlock()
	if o != "" {
		return o
	}
	if v := strings.TrimSpace(os.Getenv("ANDROIDLAB_BURP_MCP_URL")); v != "" {
		return v
	}
	return "http://127.0.0.1:9876"
}

// ToolNames lists the MCP tools the server exposes (used to confirm a live, correctly
// configured Burp MCP connection).
func (c *BurpMCP) ToolNames(ctx context.Context) ([]string, error) {
	res, err := c.rpc(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(res, &payload); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(payload.Tools))
	for _, t := range payload.Tools {
		names = append(names, t.Name)
	}
	return names, nil
}

// CheckBurpMCP verifies the Burp MCP integration end to end: it connects to the
// configured URL, runs the MCP handshake, and confirms the proxy-history tool is
// present. Returns a one-line human/agent-readable status.
func CheckBurpMCP(ctx context.Context) (ok bool, detail string) {
	return CheckBurpMCPAt(ctx, BurpMCPURL())
}

// CheckBurpMCPAt verifies a specific Burp MCP endpoint (used by the UI to test a
// URL the operator typed before saving it).
func CheckBurpMCPAt(ctx context.Context, url string) (ok bool, detail string) {
	c, err := DialBurpMCP(ctx, url)
	if err != nil {
		return false, fmt.Sprintf("Burp MCP not reachable at %s: %v (is Burp running with the MCP Server extension enabled?)", url, err)
	}
	defer c.Close()
	names, err := c.ToolNames(ctx)
	if err != nil {
		return false, fmt.Sprintf("Burp MCP at %s connected but tools/list failed: %v", url, err)
	}
	hasHistory := false
	for _, n := range names {
		if n == "get_proxy_http_history" {
			hasHistory = true
			break
		}
	}
	if !hasHistory {
		return false, fmt.Sprintf("Burp MCP at %s is up (%d tools) but get_proxy_http_history is missing; update the MCP extension", url, len(names))
	}
	return true, fmt.Sprintf("Burp MCP ready at %s: %d tools, proxy history available", url, len(names))
}
