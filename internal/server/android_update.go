package server

import (
	"net/http"
	"runtime"
)

// This fork must be rebuilt from its own source. Upstream binaries do not
// contain Ripple's APK inspector, endpoints, or interface.
func (s *Server) androidUpdateCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"current": BuildVersion, "mode": "binary", "os": runtime.GOOS, "arch": runtime.GOARCH,
		"has_update": false, "has_backup": false, "comparable": false, "repo": "",
		"reason": "Ripple is a separate platform. Update by rebuilding this Android source tree; upstream ARTEX binaries do not include Android testing features.",
	})
}

func (s *Server) androidUpdateDisabled(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusConflict, "Upstream binary updates and rollback are disabled for Ripple. Rebuild this Android source tree.")
}
