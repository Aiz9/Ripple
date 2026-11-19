package devicelab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
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

// burpToolContract is the wire contract this client depends on: each Burp MCP tool
// we invoke and the argument keys we send it (see SendRequest / ProxyHistory).
// CheckBurpMCP validates the live server's advertised schema against this, so a
// future PortSwigger argument rename surfaces as one clear capture-status error
// up front — instead of every replay failing with an opaque kotlinx "unknown key"
// that workers misread as an environment fault and give up on the tools.
var burpToolContract = map[string][]string{
	"get_proxy_http_history": {"count", "offset"},
	"send_http1_request":     {"content", "targetHostname", "targetPort", "usesHttps"},
}

// toolSchemas fetches each exposed tool's name and the property names of its input
// schema (empty set when the server advertises no schema for a tool).
func (c *BurpMCP) toolSchemas(ctx context.Context) (map[string]map[string]bool, error) {
	res, err := c.rpc(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(res, &payload); err != nil {
		return nil, err
	}
	out := make(map[string]map[string]bool, len(payload.Tools))
	for _, t := range payload.Tools {
		props := make(map[string]bool, len(t.InputSchema.Properties))
		for k := range t.InputSchema.Properties {
			props[k] = true
		}
		out[t.Name] = props
	}
	return out, nil
}

// contractProblems checks the live schema against burpToolContract and returns a
// sorted list of mismatches (empty when the contract holds). A tool that advertises
// no properties is only checked for existence, not arg names, so a server that omits
// schemas degrades to the previous presence check rather than failing spuriously.
func contractProblems(schemas map[string]map[string]bool) []string {
	var problems []string
	for tool, keys := range burpToolContract {
		props, present := schemas[tool]
		if !present {
			problems = append(problems, tool+" missing")
			continue
		}
		if len(props) == 0 {
			continue // server advertises no schema for this tool; can't validate args
		}
		for _, k := range keys {
			if !props[k] {
				problems = append(problems, fmt.Sprintf("%s lacks arg %q", tool, k))
			}
		}
	}
	sort.Strings(problems)
	return problems
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
	schemas, err := c.toolSchemas(ctx)
	if err != nil {
		return false, fmt.Sprintf("Burp MCP at %s connected but tools/list failed: %v", url, err)
	}
	if problems := contractProblems(schemas); len(problems) > 0 {
		return false, fmt.Sprintf("Burp MCP at %s is up (%d tools) but its schema does not match what this client sends (%s) — update Burp's MCP Server extension (or this client); history/replay will fail until it matches", url, len(schemas), strings.Join(problems, "; "))
	}
	return true, fmt.Sprintf("Burp MCP ready at %s: %d tools, history + replay schema verified", url, len(schemas))
}
