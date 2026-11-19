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
	mu            sync.Mutex
	push          chan string
	renameSendArg bool // when true, tools/list advertises send_http1_request with a wrong key
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
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
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
	case "tools/list":
		// Advertise the two tools this client depends on, with the real PortSwigger
		// argument names. renameSendArg flips one key to simulate a schema drift.
		sendProps := `"content":{},"targetHostname":{},"targetPort":{},"usesHttps":{}`
		if f.renameSendArg {
			sendProps = `"content":{},"host":{},"targetPort":{},"usesHttps":{}`
		}
		result = fmt.Sprintf(`{"tools":[`+
			`{"name":"get_proxy_http_history","inputSchema":{"properties":{"count":{},"offset":{}}}},`+
			`{"name":"send_http1_request","inputSchema":{"properties":{%s}}}`+
			`]}`, sendProps)
	case "tools/call":
		switch req.Params.Name {
		case "get_proxy_http_history":
			item := `{"request":"GET /webbackend/v2/initial/data HTTP/1.1\r\nhost: bankxp.example.com\r\nauthorization: Bearer XYZ\r\n\r\n","response":"HTTP/2 200 OK\r\n\r\n{}"}`
			result = fmt.Sprintf(`{"content":[{"type":"text","text":%q}]}`, item)
		case "send_http1_request":
			// The real PortSwigger server rejects unknown keys; mirror its schema
			// (content/targetHostname/targetPort/usesHttps) so wrong keys fail here.
			for _, k := range []string{"content", "targetHostname", "targetPort", "usesHttps"} {
				if _, ok := req.Params.Arguments[k]; !ok {
					result = fmt.Sprintf(`{"content":[{"type":"text","text":"Encountered an unknown argument; expected %q"}],"isError":true}`, k)
					break
				}
			}
			if result == "" {
				result = `{"content":[{"type":"text","text":"ok"}]}`
			}
		default:
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

	// SendRequest must use PortSwigger's wire names; the fake rejects any other key.
	resp, err := c.SendRequest(ctx, "bankxp.example.com", 443, true, "GET / HTTP/1.1\r\n\r\n")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if strings.Contains(resp, "unknown argument") {
		t.Fatalf("send_http1_request sent wrong argument keys: %s", resp)
	}
}

// TestCheckBurpMCPValidatesSchema proves the capture-status preflight verifies our
// argument contract against Burp's advertised schema: it passes on the real names
// and fails with a precise message if PortSwigger ever renames an arg we send.
func TestCheckBurpMCPValidatesSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	good := httptest.NewServer(&fakeMCP{})
	defer good.Close()
	if ok, detail := CheckBurpMCPAt(ctx, good.URL); !ok {
		t.Fatalf("expected ready on matching schema, got: %s", detail)
	}

	drift := httptest.NewServer(&fakeMCP{renameSendArg: true})
	defer drift.Close()
	ok, detail := CheckBurpMCPAt(ctx, drift.URL)
	if ok {
		t.Fatal("expected failure when send_http1_request schema drifts")
	}
	if !strings.Contains(detail, `send_http1_request lacks arg "targetHostname"`) {
		t.Fatalf("detail should name the missing arg, got: %s", detail)
	}
}
