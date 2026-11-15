package devicelab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMCP emulates the Burp MCP SSE transport: GET "/" opens an event stream and
// announces the post endpoint; POSTs carry JSON-RPC and their responses are pushed
// back on the SSE stream, matched by id.
type fakeMCP struct {
	mu   sync.Mutex
	push chan string
}

func (f *fakeMCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flush", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		f.mu.Lock()
		f.push = make(chan string, 16)
		ch := f.push
		f.mu.Unlock()
		fmt.Fprint(w, "event: endpoint\ndata: /msg?sessionId=test\n\n")
		fl.Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case msg := <-ch:
				fmt.Fprintf(w, "data: %s\n\n", msg)
				fl.Flush()
			}
		}
	}
	// POST /msg: JSON-RPC request.
	body, _ := io.ReadAll(r.Body)
	var req struct {
		ID     *int   `json:"id"`
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	json.Unmarshal(body, &req)
	w.WriteHeader(202)
	if req.ID == nil {
		return // notification
	}
	var result string
	switch req.Method {
	case "initialize":
		result = `{"protocolVersion":"2024-11-05","serverInfo":{"name":"burp-suite","version":"1.1.2"}}`
	case "tools/call":
		if req.Params.Name == "get_proxy_http_history" {
			item := `{"request":"GET /webbackend/v2/initial/data HTTP/1.1\r\nhost: bankxp.example.com\r\nauthorization: Bearer XYZ\r\n\r\n","response":"HTTP/2 200 OK\r\n\r\n{}"}`
			result = fmt.Sprintf(`{"content":[{"type":"text","text":%q}]}`, item)
		} else {
			result = `{"content":[{"type":"text","text":"ok"}]}`
		}
	}
	resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":%s}`, *req.ID, result)
	f.mu.Lock()
	ch := f.push
	f.mu.Unlock()
	if ch != nil {
		ch <- resp
	}
}

func TestBurpMCPDialAndHistory(t *testing.T) {
	srv := httptest.NewServer(&fakeMCP{})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialBurpMCP(ctx, srv.URL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	ex, err := c.ProxyHistory(ctx, 0, 10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(ex) != 1 {
		t.Fatalf("want 1 exchange, got %d", len(ex))
	}
	if ex[0].Host != "bankxp.example.com" {
		t.Fatalf("host=%q (case-insensitive HTTP/2 host: header not parsed)", ex[0].Host)
	}
	if ex[0].Method != "GET" || !strings.HasPrefix(ex[0].Path, "/webbackend") {
		t.Fatalf("method/path=%q %q", ex[0].Method, ex[0].Path)
	}
	if !strings.Contains(ex[0].Request, "Bearer XYZ") {
		t.Fatal("request body not captured")
	}
}
