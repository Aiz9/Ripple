package devicelab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// BurpMCP is a client for PortSwigger's Burp Suite MCP Server extension (SSE
// transport, default http://127.0.0.1:9876). It gives the autonomous agent the
// traffic-analysis surface used during manual testing — reading decrypted proxy
// history and replaying requests — without a human in Burp. Burp (invisible
// listener) handles proxy-unaware apps; this client reads what it captured.
type BurpMCP struct {
	base    string
	http    *http.Client
	postURL string

	mu      sync.Mutex
	nextID  int
	pending map[int]chan json.RawMessage
	cancel  context.CancelFunc
	closed  bool
}

// Exchange is one captured HTTP message pair, normalized from the proxy history.
type Exchange struct {
	Host     string `json:"host"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	TLS      bool   `json:"tls"`
	Request  string `json:"request"`
	Response string `json:"response"`
}

// DialBurpMCP opens the SSE stream, learns the message-post endpoint, and runs the
// MCP initialize handshake. base is the server root, e.g. "http://127.0.0.1:9876".
func DialBurpMCP(ctx context.Context, base string) (*BurpMCP, error) {
	base = strings.TrimRight(base, "/")
	streamCtx, cancel := context.WithCancel(context.Background())
	c := &BurpMCP{
		base:    base,
		http:    &http.Client{},
		pending: map[int]chan json.RawMessage{},
		cancel:  cancel,
	}
	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, base+"/", nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("connect Burp MCP SSE: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("Burp MCP SSE status %d", resp.StatusCode)
	}
	endpoint := make(chan string, 1)
	go c.readSSE(resp, endpoint)

	select {
	case ep := <-endpoint:
		u, err := url.Parse(ep)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("bad MCP endpoint %q: %w", ep, err)
		}
		c.postURL = (&url.URL{Scheme: mustScheme(base), Host: mustHost(base)}).ResolveReference(u).String()
	case <-time.After(10 * time.Second):
		c.Close()
		return nil, fmt.Errorf("Burp MCP: no endpoint event within 10s")
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	}

	if _, err := c.rpc(ctx, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "artex", "version": "1"},
	}); err != nil {
		c.Close()
		return nil, err
	}
	c.notify("notifications/initialized", nil)
	return c, nil
}

func (c *BurpMCP) readSSE(resp *http.Response, endpoint chan<- string) {
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var event, data string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "data:"):
			data = strings.TrimSpace(line[5:])
		case line == "":
			if event == "endpoint" && data != "" {
				select {
				case endpoint <- data:
				default:
				}
			} else if data != "" {
				var msg struct {
					ID *int `json:"id"`
				}
				raw := json.RawMessage(data)
				if json.Unmarshal(raw, &msg) == nil && msg.ID != nil {
					c.deliver(*msg.ID, raw)
				}
			}
			event, data = "", ""
		}
	}
}

func (c *BurpMCP) deliver(id int, raw json.RawMessage) {
	c.mu.Lock()
	ch := c.pending[id]
	delete(c.pending, id)
	c.mu.Unlock()
	if ch != nil {
		ch <- raw
	}
}

func (c *BurpMCP) rpc(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("Burp MCP closed")
	}
	c.nextID++
	id := c.nextID
	ch := make(chan json.RawMessage, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.postURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	select {
	case raw := <-ch:
		var r struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		if r.Error != nil {
			return nil, fmt.Errorf("Burp MCP %s: %s", method, r.Error.Message)
		}
		return r.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("Burp MCP %s: timeout", method)
	}
}

func (c *BurpMCP) notify(method string, params any) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	req, _ := http.NewRequest(http.MethodPost, c.postURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := c.http.Do(req); err == nil {
		resp.Body.Close()
	}
}

// Call invokes an MCP tool and returns the concatenated text content.
func (c *BurpMCP) Call(ctx context.Context, tool string, args map[string]any) (string, error) {
	if args == nil {
		args = map[string]any{}
	}
	res, err := c.rpc(ctx, "tools/call", map[string]any{"name": tool, "arguments": args})
	if err != nil {
		return "", err
	}
	var payload struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(res, &payload); err != nil {
		return string(res), nil
	}
	var sb strings.Builder
	for _, p := range payload.Content {
		if p.Type == "text" {
			sb.WriteString(p.Text)
			sb.WriteByte('\n')
		}
	}
	return sb.String(), nil
}

// ProxyHistory reads captured proxy items and normalizes them to Exchanges.
func (c *BurpMCP) ProxyHistory(ctx context.Context, offset, count int) ([]Exchange, error) {
	text, err := c.Call(ctx, "get_proxy_http_history", map[string]any{"offset": offset, "count": count})
	if err != nil {
		return nil, err
	}
	return parseBurpHistory(text), nil
}

// SendRequest replays/issues a raw HTTP/1.1 request through Burp (for authz/IDOR
// checks — e.g. swapping an identity's token). Returns the raw response text.
func (c *BurpMCP) SendRequest(ctx context.Context, host string, port int, tls bool, raw string) (string, error) {
	// Wire names come from PortSwigger's SendHttp1Request (Tools.kt): content,
	// targetHostname, targetPort, usesHttps. The server rejects unknown keys, so
	// host/port/request would fail with "unknown 'host' key".
	return c.Call(ctx, "send_http1_request", map[string]any{
		"targetHostname": host, "targetPort": port, "usesHttps": tls, "content": raw,
	})
}

func (c *BurpMCP) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	return nil
}

// parseBurpHistory extracts Exchanges from the MCP text payload. Each item is a
// JSON object with "request"/"response" raw strings; hosts use the HTTP/2 lower-case
// "host:" header as well as "Host:", so matching is case-insensitive.
func parseBurpHistory(text string) []Exchange {
	var out []Exchange
	dec := json.NewDecoder(strings.NewReader(text))
	for {
		var item struct {
			Request  json.RawMessage `json:"request"`
			Response json.RawMessage `json:"response"`
		}
		if err := dec.Decode(&item); err != nil {
			break
		}
		req := decodeMaybeRaw(item.Request)
		resp := decodeMaybeRaw(item.Response)
		if req == "" {
			continue
		}
		ex := Exchange{Request: req, Response: resp}
		lines := strings.SplitN(req, "\r\n", 2)
		if parts := strings.SplitN(lines[0], " ", 3); len(parts) >= 2 {
			ex.Method = parts[0]
			ex.Path = parts[1]
		}
		for _, ln := range strings.Split(req, "\r\n") {
			if strings.HasPrefix(strings.ToLower(ln), "host:") {
				ex.Host = strings.TrimSpace(ln[len("host:"):])
				break
			}
		}
		out = append(out, ex)
	}
	return out
}

// decodeMaybeRaw accepts either a JSON string or an object like {"base64": "..."}.
func decodeMaybeRaw(r json.RawMessage) string {
	if len(r) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(r, &s) == nil {
		return s
	}
	var obj struct {
		Base64 string `json:"base64"`
	}
	if json.Unmarshal(r, &obj) == nil && obj.Base64 != "" {
		if b, err := base64.StdEncoding.DecodeString(obj.Base64); err == nil {
			return string(b)
		}
	}
	return ""
}

func mustScheme(base string) string {
	if u, err := url.Parse(base); err == nil {
		return u.Scheme
	}
	return "http"
}
func mustHost(base string) string {
	if u, err := url.Parse(base); err == nil {
		return u.Host
	}
	return base
}
