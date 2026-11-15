package sectool

import (
	"context"
	"encoding/json"
	"os/exec"
	"sync"
	"time"
)

// Status represents the operational readiness of a tool.
type Status string

const (
	StatusAvailable   Status = "available"
	StatusUnavailable Status = "unavailable"
	StatusDegraded    Status = "degraded"
)

// ExecutionStatus represents the outcome of a tool execution.
type ExecutionStatus string

const (
	ExecCompleted ExecutionStatus = "completed"
	ExecFailed    ExecutionStatus = "failed"
	ExecBlocked   ExecutionStatus = "blocked"
	ExecTimeout   ExecutionStatus = "timeout"
)

// ToolDescriptor describes a security tool's capabilities, requirements, and bounds.
type ToolDescriptor struct {
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Description  string        `json:"description"`
	Capabilities []string      `json:"capabilities"`
	RequiresHost []string      `json:"requires_host"`
	RequiresAdb  bool          `json:"requires_adb"`
	RequiresRoot bool          `json:"requires_root"`
	Timeout      time.Duration `json:"timeout"`
}

// HealthCheckResult reports whether a tool can run in the current host environment.
type HealthCheckResult struct {
	Status  Status   `json:"status"`
	Message string   `json:"message,omitempty"`
	Missing []string `json:"missing,omitempty"`
}

// ExecutionResult is the structured return value from any executed tool.
type ExecutionResult struct {
	ToolName    string          `json:"tool_name"`
	Status      ExecutionStatus `json:"status"`
	Summary     string          `json:"summary"`
	EvidenceIDs []string        `json:"evidence_ids,omitempty"`
	RawOutput   json.RawMessage `json:"raw_output,omitempty"`
	Limitations []string        `json:"limitations,omitempty"`
	DurationMS  int64           `json:"duration_ms"`
}

// Tool represents a registered, isolated security tool capability.
type Tool interface {
	Descriptor() ToolDescriptor
	CheckHealth(ctx context.Context) HealthCheckResult
	Execute(ctx context.Context, input json.RawMessage) (ExecutionResult, error)
}

// Registry maintains the suite of available security tools.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// NewRegistry creates a new, populated security tool registry.
func NewRegistry() *Registry {
	r := &Registry{
		tools: make(map[string]Tool),
	}
	r.RegisterDefaults()
	return r
}

// Register registers a tool in the registry.
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Descriptor().Name] = t
}

// Lookup retrieves a tool by name.
func (r *Registry) Lookup(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// ForCapability returns all tools that provide a given capability.
func (r *Registry) ForCapability(cap string) []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Tool
	for _, t := range r.tools {
		for _, c := range t.Descriptor().Capabilities {
			if c == cap {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// HealthSummary checks the health of all registered tools.
func (r *Registry) HealthSummary(ctx context.Context) map[string]HealthCheckResult {
	r.mu.RLock()
	defer r.mu.RUnlock()
	summary := make(map[string]HealthCheckResult)
	for name, t := range r.tools {
		summary[name] = t.CheckHealth(ctx)
	}
	return summary
}

// Helper to check if external CLI binary is available on PATH.
func checkBinary(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// RegisterDefaults initializes the built-in tool suite.
func (r *Registry) RegisterDefaults() {
	r.Register(&APKInspectorTool{})
	r.Register(&FlutterAnalyzerTool{})
	r.Register(&ADBDeviceTool{})
	r.Register(&FridaObserverTool{})
	r.Register(&APISecurityTool{})
	r.Register(&FindingValidatorTool{})
}
