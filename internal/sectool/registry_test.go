package sectool

import (
	"context"
	"testing"
)

func TestToolRegistryRegistration(t *testing.T) {
	r := NewRegistry()

	// Verify all default tools registered
	tools := []string{
		"apk_inspector",
		"flutter_analyzer",
		"adb_device_runner",
		"frida_observer",
		"api_security_prober",
		"finding_validator",
	}

	for _, name := range tools {
		tool, ok := r.Lookup(name)
		if !ok {
			t.Errorf("tool %q not found in registry", name)
			continue
		}
		if tool.Descriptor().Name != name {
			t.Errorf("expected tool name %q, got %q", name, tool.Descriptor().Name)
		}
	}
}

func TestToolRegistryCapabilities(t *testing.T) {
	r := NewRegistry()

	apkTools := r.ForCapability("apk_static")
	if len(apkTools) == 0 {
		t.Errorf("expected at least one tool for capability 'apk_static'")
	}

	flutterTools := r.ForCapability("flutter_analysis")
	if len(flutterTools) == 0 {
		t.Errorf("expected at least one tool for capability 'flutter_analysis'")
	}
}

func TestToolHealthChecks(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	summary := r.HealthSummary(ctx)
	if len(summary) != 6 {
		t.Errorf("expected health summary for 6 tools, got %d", len(summary))
	}

	apkHealth := summary["apk_inspector"]
	if apkHealth.Status != StatusAvailable {
		t.Errorf("expected apk_inspector to be available, got %v", apkHealth.Status)
	}

	flutterHealth := summary["flutter_analyzer"]
	if flutterHealth.Status != StatusAvailable && flutterHealth.Status != StatusDegraded {
		t.Errorf("expected flutter_analyzer to be available or degraded, got %v", flutterHealth.Status)
	}
}
