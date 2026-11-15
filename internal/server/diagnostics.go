package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var logSecrets = struct {
	sync.RWMutex
	values map[string]struct{}
}{values: map[string]struct{}{}}
var logQuotedSecret = regexp.MustCompile(`(?i)((?:"|')?(?:password|passwd|api[_-]?key|secret|access[_-]?token|refresh[_-]?token|token|cookie|set-cookie)(?:"|')?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`)
var logAuthorization = regexp.MustCompile(`(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
var logURL = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>"']+`)

func RegisterLogSecret(secret string) {
	if len(secret) < 4 {
		return
	}
	logSecrets.Lock()
	logSecrets.values[secret] = struct{}{}
	logSecrets.Unlock()
}
func RedactLogText(value string) string {
	value = logAuthorization.ReplaceAllString(value, "[REDACTED authorization]")
	value = logQuotedSecret.ReplaceAllString(value, "${1}[REDACTED]")
	value = logURL.ReplaceAllStringFunc(value, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		if u.User != nil {
			u.User = url.User("REDACTED")
		}
		u.RawQuery = ""
		u.Fragment = ""
		return u.String()
	})
	logSecrets.RLock()
	defer logSecrets.RUnlock()
	for secret := range logSecrets.values {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

// Capture only error metadata; never inspect request headers or request bodies.
type diagnosticResponse struct {
	http.ResponseWriter
	status   int
	message  string
	writeErr error
}

func (w *diagnosticResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *diagnosticResponse) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *diagnosticResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(p)
	if err != nil {
		w.writeErr = err
	}
	return n, err
}
func (w *diagnosticResponse) Flush() {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *diagnosticResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking unsupported")
	}
	return h.Hijack()
}
func (w *diagnosticResponse) captureError(message string) { w.message = message }

func (s *Server) diagnosticMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewString()
		w.Header().Set("X-Request-ID", id)
		response := &diagnosticResponse{ResponseWriter: w}
		started := time.Now()
		defer func() {
			route := r.Pattern
			if route == "" {
				route = r.URL.EscapedPath()
			}
			if cause := recover(); cause != nil {
				log.Printf("[http] ERROR request_id=%s method=%s route=%s panic=%v\n%s", id, r.Method, route, cause, debug.Stack())
				if cause == http.ErrAbortHandler {
					panic(cause)
				}
				if response.status == 0 {
					writeErr(response, 500, "Internal server error; see Logs using request ID "+id)
				}
				return
			}
			if response.status >= 400 || response.writeErr != nil {
				message := response.message
				if message == "" {
					message = http.StatusText(response.status)
				}
				log.Printf("[http] ERROR request_id=%s method=%s route=%s status=%d duration=%s: %s", id, r.Method, route, response.status, time.Since(started), message)
				if response.writeErr != nil {
					log.Printf("[http] ERROR request_id=%s response write failed: %v", id, response.writeErr)
				}
			}
		}()
		next.ServeHTTP(response, r)
	})
}

func (s *Server) clientDiagnostic(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source  string `json:"source"`
		Message string `json:"message"`
		Stack   string `json:"stack"`
		Page    string `json:"page"`
		TS      string `json:"ts"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	if json.NewDecoder(r.Body).Decode(&req) != nil || strings.TrimSpace(req.Message) == "" {
		writeErr(w, 400, "Invalid browser diagnostic")
		return
	}
	switch req.Source {
	case "browser", "unhandledrejection", "console", "network":
	default:
		writeErr(w, 400, "Unknown browser diagnostic source")
		return
	}
	log.Printf("[browser] ERROR source=%s page=%s observed=%s: %s\n%s", req.Source, req.Page, req.TS, req.Message, req.Stack)
	w.WriteHeader(http.StatusNoContent)
}
