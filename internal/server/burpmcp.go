package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/internal/devicelab"
)

const settingBurpMCPURL = "burp_mcp_url"

// LoadBurpMCPSetting applies the persisted Burp MCP URL (if any) to the process
// override, so the autonomous agent uses the operator-configured endpoint.
func (s *Server) LoadBurpMCPSetting() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	if v, ok, _ := s.m.pg.GetSetting(settingBurpMCPURL); ok && strings.TrimSpace(v) != "" {
		devicelab.SetBurpMCPURL(strings.TrimSpace(v))
	}
}

func (s *Server) registerBurpMCP(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/burp-mcp", s.getBurpMCP)
	mux.HandleFunc("PUT /api/burp-mcp", s.putBurpMCP)
	mux.HandleFunc("POST /api/burp-mcp/test", s.testBurpMCP)
}

func (s *Server) burpMCPPayload(ctx context.Context, probe bool) map[string]any {
	u := devicelab.BurpMCPURL()
	out := map[string]any{"url": u, "default": "http://127.0.0.1:9876"}
	if probe {
		cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		ok, detail := devicelab.CheckBurpMCPAt(cctx, u)
		out["ready"] = ok
		out["detail"] = detail
	}
	return out
}

func (s *Server) getBurpMCP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.burpMCPPayload(r.Context(), true))
}

func validBurpURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	return strings.TrimRight(raw, "/"), true
}

func (s *Server) putBurpMCP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, 400, "bad request body")
		return
	}
	u, ok := validBurpURL(body.URL)
	if !ok {
		writeErr(w, 400, "URL must be an http(s) origin without credentials, query or fragment")
		return
	}
	if s.m != nil && s.m.pg != nil {
		if err := s.m.pg.SetSetting(settingBurpMCPURL, u); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	devicelab.SetBurpMCPURL(u)
	writeJSON(w, 200, s.burpMCPPayload(r.Context(), true))
}

func (s *Server) testBurpMCP(w http.ResponseWriter, r *http.Request) {
	u := devicelab.BurpMCPURL()
	if r.Body != nil {
		var body struct {
			URL string `json:"url"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body) == nil {
			if cand, ok := validBurpURL(body.URL); ok {
				u = cand
			}
		}
	}
	cctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	ok, detail := devicelab.CheckBurpMCPAt(cctx, u)
	writeJSON(w, 200, map[string]any{"url": u, "ready": ok, "detail": detail})
}
