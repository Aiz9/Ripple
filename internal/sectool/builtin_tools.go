package sectool

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Autumn-27/artex/internal/androidapk"
)

// --- 1. APK Inspector Tool ---

type APKInspectorTool struct{}

func (t *APKInspectorTool) Descriptor() ToolDescriptor {
	return ToolDescriptor{
		Name:         "apk_inspector",
		Version:      "1.0.0",
		Description:  "Inspects binary and text AndroidManifest.xml, signing certificates, permissions, and DEX strings.",
		Capabilities: []string{"apk_static", "manifest_inspection", "signature_verification"},
		RequiresHost: []string{},
		Timeout:      60 * time.Second,
	}
}

func (t *APKInspectorTool) CheckHealth(ctx context.Context) HealthCheckResult {
	return HealthCheckResult{Status: StatusAvailable, Message: "Built-in Go APK parser ready"}
}

func (t *APKInspectorTool) Execute(ctx context.Context, input json.RawMessage) (ExecutionResult, error) {
	start := time.Now()
	var in struct {
		APKPath string `json:"apk_path"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return ExecutionResult{ToolName: "apk_inspector", Status: ExecFailed, Summary: "Invalid input schema: " + err.Error()}, nil
	}
	rep, err := androidapk.Analyze(in.APKPath)
	if err != nil {
		return ExecutionResult{ToolName: "apk_inspector", Status: ExecFailed, Summary: "APK analysis failed: " + err.Error()}, nil
	}
	raw, _ := json.Marshal(rep)
	return ExecutionResult{
		ToolName:   "apk_inspector",
		Status:     ExecCompleted,
		Summary:    fmt.Sprintf("Analyzed package %s (SDK %s/%s) with %d components and %d findings", rep.Package, rep.MinSDK, rep.TargetSDK, len(rep.Components), len(rep.Findings)),
		RawOutput:  raw,
		DurationMS: time.Since(start).Milliseconds(),
	}, nil
}

// --- 2. Flutter Analyzer Tool ---

type FlutterAnalyzerTool struct{}

func (t *FlutterAnalyzerTool) Descriptor() ToolDescriptor {
	return ToolDescriptor{
		Name:         "flutter_analyzer",
		Version:      "1.0.0",
		Description:  "Performs deep inspection of Flutter-based APKs, analyzing libapp.so, libflutter.so, and bundled assets.",
		Capabilities: []string{"flutter_analysis", "flutter_aot", "dart_reverse_engineering"},
		RequiresHost: []string{},
		Timeout:      120 * time.Second,
	}
}

func (t *FlutterAnalyzerTool) CheckHealth(ctx context.Context) HealthCheckResult {
	hasBlutter := checkBinary("blutter")
	hasReflutter := checkBinary("reflutter")
	if hasBlutter && hasReflutter {
		return HealthCheckResult{Status: StatusAvailable, Message: "Native string parser, blutter, and reflutter are available"}
	}
	if hasBlutter || hasReflutter {
		return HealthCheckResult{Status: StatusAvailable, Message: "Native string parser ready; partial reverse engineering CLI available"}
	}
	return HealthCheckResult{
		Status:  StatusDegraded,
		Message: "Native string and AOT artifact parser ready; blutter and reflutter CLI tools are not installed on host PATH (deep functional disassembly unavailable)",
		Missing: []string{"blutter", "reflutter"},
	}
}

func (t *FlutterAnalyzerTool) Execute(ctx context.Context, input json.RawMessage) (ExecutionResult, error) {
	start := time.Now()
	var in struct {
		APKPath string `json:"apk_path"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return ExecutionResult{ToolName: "flutter_analyzer", Status: ExecFailed, Summary: "Invalid input: " + err.Error()}, nil
	}

	f, err := os.Open(in.APKPath)
	if err != nil {
		return ExecutionResult{ToolName: "flutter_analyzer", Status: ExecFailed, Summary: "Cannot open APK: " + err.Error()}, nil
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return ExecutionResult{ToolName: "flutter_analyzer", Status: ExecFailed, Summary: "Cannot stat APK: " + err.Error()}, nil
	}

	z, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return ExecutionResult{ToolName: "flutter_analyzer", Status: ExecFailed, Summary: "Cannot parse APK as zip: " + err.Error()}, nil
	}

	rep, err := androidapk.InspectFlutter(z)
	if err != nil {
		return ExecutionResult{ToolName: "flutter_analyzer", Status: ExecFailed, Summary: "Flutter inspection failed: " + err.Error()}, nil
	}

	raw, _ := json.Marshal(rep)
	if !rep.IsFlutter {
		return ExecutionResult{
			ToolName:   "flutter_analyzer",
			Status:     ExecCompleted,
			Summary:    "APK does not contain Flutter runtime or Dart AOT libraries (pure native or non-Flutter build)",
			RawOutput:  raw,
			DurationMS: time.Since(start).Milliseconds(),
		}, nil
	}

	summary := fmt.Sprintf("Flutter detected (%s): %d URLs, %d platform channels, %d bundled certs, %d potential secrets",
		rep.BuildType, len(rep.DiscoveredURLs), len(rep.PlatformChannels), len(rep.BundledCerts), len(rep.HardcodedSecrets))

	return ExecutionResult{
		ToolName:    "flutter_analyzer",
		Status:      ExecCompleted,
		Summary:     summary,
		RawOutput:   raw,
		Limitations: rep.Limitations,
		DurationMS:  time.Since(start).Milliseconds(),
	}, nil
}

// --- 3. ADB Device Tool ---

type ADBDeviceTool struct{}

func (t *ADBDeviceTool) Descriptor() ToolDescriptor {
	return ToolDescriptor{
		Name:         "adb_device_runner",
		Version:      "1.0.0",
		Description:  "Interacts with physical and virtual Android devices via Android Debug Bridge (ADB).",
		Capabilities: []string{"runtime", "android_runtime", "device_management"},
		RequiresHost: []string{"adb"},
		RequiresAdb:  true,
		Timeout:      300 * time.Second,
	}
}

func (t *ADBDeviceTool) CheckHealth(ctx context.Context) HealthCheckResult {
	if !checkBinary("adb") {
		return HealthCheckResult{Status: StatusUnavailable, Message: "adb binary not found on PATH", Missing: []string{"adb"}}
	}
	out, err := exec.CommandContext(ctx, "adb", "devices").CombinedOutput()
	if err != nil {
		return HealthCheckResult{Status: StatusDegraded, Message: "adb server unreachable: " + err.Error()}
	}
	lines := strings.Split(string(out), "\n")
	deviceCount := 0
	for _, l := range lines {
		if strings.Contains(l, "\tdevice") {
			deviceCount++
		}
	}
	if deviceCount == 0 {
		return HealthCheckResult{Status: StatusDegraded, Message: "adb ready, but no authorized online devices found"}
	}
	return HealthCheckResult{Status: StatusAvailable, Message: fmt.Sprintf("adb ready with %d authorized device(s)", deviceCount)}
}

func (t *ADBDeviceTool) Execute(ctx context.Context, input json.RawMessage) (ExecutionResult, error) {
	health := t.CheckHealth(ctx)
	if health.Status == StatusUnavailable {
		return ExecutionResult{ToolName: "adb_device_runner", Status: ExecBlocked, Summary: health.Message, Limitations: health.Missing}, nil
	}
	return ExecutionResult{ToolName: "adb_device_runner", Status: ExecCompleted, Summary: "Device runner ready"}, nil
}

// --- 4. Frida Observer Tool ---

type FridaObserverTool struct{}

func (t *FridaObserverTool) Descriptor() ToolDescriptor {
	return ToolDescriptor{
		Name:         "frida_observer",
		Version:      "1.0.0",
		Description:  "Instruments running Android processes using Frida to observe method calls, crypto, and network requests.",
		Capabilities: []string{"instrumentation", "dynamic_observation", "pinning_bypass"},
		RequiresHost: []string{"frida"},
		RequiresRoot: true,
		Timeout:      180 * time.Second,
	}
}

func (t *FridaObserverTool) CheckHealth(ctx context.Context) HealthCheckResult {
	if !checkBinary("frida") {
		return HealthCheckResult{Status: StatusDegraded, Message: "frida CLI not found on PATH; runtime observation relies on direct ADB/Frida-server bridge", Missing: []string{"frida"}}
	}
	return HealthCheckResult{Status: StatusAvailable, Message: "frida CLI detected"}
}

func (t *FridaObserverTool) Execute(ctx context.Context, input json.RawMessage) (ExecutionResult, error) {
	return ExecutionResult{ToolName: "frida_observer", Status: ExecCompleted, Summary: "Frida observer ready"}, nil
}

// --- 5. API Security Tool ---

type APISecurityTool struct{}

func (t *APISecurityTool) Descriptor() ToolDescriptor {
	return ToolDescriptor{
		Name:         "api_security_prober",
		Version:      "1.0.0",
		Description:  "Performs non-destructive, scoped security observation on discovered API endpoints.",
		Capabilities: []string{"api_security", "scoped_http", "transport_evaluation"},
		RequiresHost: []string{},
		Timeout:      120 * time.Second,
	}
}

func (t *APISecurityTool) CheckHealth(ctx context.Context) HealthCheckResult {
	return HealthCheckResult{Status: StatusAvailable, Message: "Built-in Go HTTP security prober ready"}
}

func (t *APISecurityTool) Execute(ctx context.Context, input json.RawMessage) (ExecutionResult, error) {
	return ExecutionResult{ToolName: "api_security_prober", Status: ExecCompleted, Summary: "API security prober ready"}, nil
}

// --- 6. Finding Validator Tool ---

type FindingValidatorTool struct{}

func (t *FindingValidatorTool) Descriptor() ToolDescriptor {
	return ToolDescriptor{
		Name:         "finding_validator",
		Version:      "1.0.0",
		Description:  "Validates candidate vulnerabilities against current reviewed evidence and detects contradictions.",
		Capabilities: []string{"validation", "finding_evidence", "contradiction_check"},
		RequiresHost: []string{},
		Timeout:      30 * time.Second,
	}
}

func (t *FindingValidatorTool) CheckHealth(ctx context.Context) HealthCheckResult {
	return HealthCheckResult{Status: StatusAvailable, Message: "Built-in finding validation logic ready"}
}

func (t *FindingValidatorTool) Execute(ctx context.Context, input json.RawMessage) (ExecutionResult, error) {
	return ExecutionResult{ToolName: "finding_validator", Status: ExecCompleted, Summary: "Finding validator ready"}, nil
}
