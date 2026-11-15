package server

import (
	"net/http"
	"os"
	"strings"
)

func legacyExecutionEnabled() bool { return os.Getenv("ANDROIDLAB_ENABLE_LEGACY_AGENTS") == "1" }

// A controlled assessment cannot be routed into the inherited shell-capable
// agent execution path. Enabling that separate advanced mode is a server-side
// deployment choice, never a model request or an editable assessment policy.
func (s *Server) controlledExecutionBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !legacyExecutionEnabled() && r.Method != "GET" && r.Method != "OPTIONS" && r.Method != "HEAD" {
			p := r.URL.Path
			// Allow deleting/cleaning up legacy tasks even when legacy execution is disabled.
			if r.Method == http.MethodDelete && strings.HasPrefix(p, "/api/tasks") {
				next.ServeHTTP(w, r)
				return
			}
			blocked := strings.HasPrefix(p, "/api/tasks") || strings.HasPrefix(p, "/api/chat") || strings.HasPrefix(p, "/api/conversations") || p == "/api/tools/custom/test" || strings.HasPrefix(p, "/api/findings") || (strings.HasPrefix(p, "/api/android/apps/") && strings.HasSuffix(p, "/assessments"))
			if blocked {
				writeErr(w, 409, "Legacy shell-capable agent execution is disabled. Use Android → Assessments and its policy-enforced dispatcher.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
