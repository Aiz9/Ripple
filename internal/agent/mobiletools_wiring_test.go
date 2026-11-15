package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMobileToolsWiring locks the tools a New APK task's worker must carry so the
// runtime-APK + runtime-API asks stay triggered end to end.
func TestMobileToolsWiring(t *testing.T) {
	ts := &ToolSet{}
	byName := map[string]map[string]any{}
	for _, tool := range ts.mobileTools() {
		byName[tool.Name()] = tool.InputSchema()
	}
	for _, name := range []string{
		"mobile_capture_status", "mobile_traffic_history", "mobile_traffic_replay",
		"mobile_discover_runtime_apis", "mobile_identity_set", "mobile_identity_list",
		"mobile_launch_app", "mobile_ui_dump",
	} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("worker is missing tool %q", name)
		}
	}
	// Response bodies and identity-aware replay must be reachable via schema.
	hist, _ := json.Marshal(byName["mobile_traffic_history"])
	if !strings.Contains(string(hist), "include_bodies") {
		t.Fatalf("mobile_traffic_history lacks include_bodies: %s", hist)
	}
	replay, _ := json.Marshal(byName["mobile_traffic_replay"])
	for _, want := range []string{"as_role", "history_index"} {
		if !strings.Contains(string(replay), want) {
			t.Fatalf("mobile_traffic_replay lacks %q: %s", want, replay)
		}
	}
}
