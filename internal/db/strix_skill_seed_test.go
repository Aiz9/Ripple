package db

import "testing"

// Imported strix skills are bound to the worker so add_intent(skills=…) can name them.
func TestStrixSkillsBoundToWorker(t *testing.T) {
	for _, name := range []string{"idor", "sql_injection", "ssrf", "business_logic", "firebase"} {
		agents, ok := builtinSkillVisibility[name]
		if !ok {
			t.Fatalf("%s missing from builtinSkillVisibility", name)
		}
		found := false
		for _, a := range agents {
			if a == "worker" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s not bound to worker: %v", name, agents)
		}
	}
}
