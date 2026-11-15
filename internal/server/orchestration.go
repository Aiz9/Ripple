package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/internal/agent"
	"github.com/Autumn-27/artex/internal/db"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// jsonResult marshals v to a JSON tool result.
func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// P2 cross-task orchestration host tools require Manager stores, Engine pause, and task creation,
// so they live in server.
// Read tools construct a temporary ToolSet for the destination task and call its existing tools,
// reusing identical logic. spawn/pause directly invoke Manager/Engine.
// Seed into tools and bind per agent like traffic tools; only bound orchestration agents see them.

// hostTools is the runtime host-tool provider fed to ToolAugment: traffic tools
// (gated by capture) + cross-task orchestration tools + user-defined custom tools.
// The second return is the names of custom tools flagged `deferred` (schema
// withheld, routed via SearchExtraTools/ExecuteExtraTool). Per-agent binding still
// decides who actually sees any of them.
//
//nolint:unused // used as the hostTools provider in wireAgentAugment
func (s *Server) hostTools() ([]actool.CoreTool, map[string][]string) {
	tools := append(s.m.HostTools(), s.orchestrationTools()...)
	tools = append(tools, s.findingRetestTools()...)
	tools = append(tools, s.platformTools()...) // Auto platform tools for skills/custom tools/MCP creation and editing.
	custom, err := s.customTools()
	if err != nil {
		log.Printf("[custom-tool] loading failed: %v", err)
		return tools, nil
	}
	tools = append(tools, custom...)
	// deferred custom tools → name -> its bound agent keys. ToolAugment turns a
	// name into a deferred entry only for agents it's actually bound to (so we don't
	// advertise a tool the per-agent binding will drop from the callable set).
	deferred := map[string][]string{}
	rows, _ := s.m.pg.ListCustomTools()
	for _, t := range rows {
		if t.Deferred && t.Enabled {
			deferred[t.Key] = t.Agents
		}
	}
	return tools, deferred
}

// orchestrationTools returns the cross-task tool set. Bound per-agent via the
// tools table (default: no binding — opt-in for orchestration agents).
func (s *Server) orchestrationTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolListTasks(),
		s.toolListLLMProfiles(),
		s.toolSpawnTask(),
		s.toolPauseTask(),
		s.toolGetTaskGraph(),
		s.toolListTaskFindings(),
		s.toolAddHint(),
		s.toolGetWorkerTrace(),
		s.toolListWorkerTraces(),
		s.toolSearchWorkerTraces(),
		s.toolGetTaskNodeDetail(),
		s.toolUpdateFindingReport(),
		s.toolGetFindingTraffic(),
		s.toolBindFindingTraffic(),
	}
}

// --- schema helpers ---

func strParam(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// parseProfileID reads an LLM profile id from a tool arg that may arrive as a JSON
// number (5) or a numeric string ("5"); returns 0 when absent/unparseable.
func parseProfileID(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(str), 10, 64)
		return v
	}
	return 0
}

func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		m["required"] = req
	}
	return m
}

func roTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func wrTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

// normalizeTaskID strips decorations the model sometimes wraps around a task id
// ("task_772", "task: #772", "#772") so a cross-task read still resolves. Used
// only as a fallback after an exact-id miss, so it never remaps a valid id.
func normalizeTaskID(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(s), "task") {
		s = s[len("task"):]
	}
	return strings.TrimSpace(strings.TrimLeft(s, " _:#"))
}

// resolveModelTask looks up a task by a model-supplied id, falling back to a
// decoration-stripped form after an exact miss so tool calls still resolve.
func (s *Server) resolveModelTask(raw string) (*Task, bool) {
	id := strings.TrimSpace(raw)
	if t, ok := s.m.Task(id); ok {
		return t, true
	}
	if norm := normalizeTaskID(id); norm != "" && norm != id {
		return s.m.Task(norm)
	}
	return nil, false
}

// delegateToTask resolves the `task_id` in the input, builds a ToolSet bound to
// that task's store, strips task_id, and calls the chosen per-task tool — so the
// cross-task read reuses the exact in-task logic against another task.
func (s *Server) delegateToTask(ctx context.Context, in json.RawMessage, pick func(*agent.ToolSet) actool.CoreTool) (actool.Result, error) {
	var head struct {
		TaskID string `json:"task_id"`
	}
	_ = json.Unmarshal(in, &head)
	if strings.TrimSpace(head.TaskID) == "" {
		return actool.Errorf("task_id is required"), nil
	}
	t, ok := s.resolveModelTask(head.TaskID)
	if !ok {
		return actool.Errorf("Task not found: " + head.TaskID + " (pass the bare numeric task id, e.g. 772)"), nil
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(in, &m)
	delete(m, "task_id")
	inner, _ := json.Marshal(m)
	tsx := agent.NewToolSet(t.Store, "orchestrator")
	if s.m.Assets() != nil {
		tsx.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
	}
	tsx.SetNotify(t.Notify)         // General debounced wake for writes lacking dedicated callbacks; reads do nothing.
	tsx.SetNotifyHint(t.NotifyHint) // add_hint records human-added-hints trigger and wakes planning.
	return pick(tsx).Call(ctx, inner, nil)
}

// --- tools ---

func (s *Server) toolListTasks() actool.CoreTool {
	return roTool("list_tasks",
		"List all tasks (id/description/goals/state/duration/parent/LLM profile) so the orchestration agent can assess progress, stalls, and model choices. Duration in seconds: active task creation to now, terminal task creation to last activity. llm_profile is the planner/worker profile name; (active profile) follows the global selection.",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			lastAct, _ := s.m.PG().LastActivityAll()
			// id -> name to resolve each task's pinned LLM profile.
			profName := map[int64]string{}
			if profs, err := s.m.pg.ListProfiles(); err == nil {
				for _, p := range profs {
					profName[p.ID] = p.Name
				}
			}
			out := make([]map[string]any, 0)
			for _, t := range s.m.List() {
				status := s.deriveTaskStatus(t)
				end := lastAct[t.ExpID]
				if live := s.engine.LastActivity(t.ID); live > end {
					end = live
				}
				dur := int64(0)
				if status == "running" {
					dur = time.Now().Unix() - t.CreatedAt
				} else if end > t.CreatedAt {
					dur = end - t.CreatedAt
				}
				row := map[string]any{"id": t.ID, "description": t.Description, "goal": t.Goal, "status": status, "run_seconds": dur}
				if t.ParentRef != "" {
					row["parent_ref"] = t.ParentRef
				}
				llmState := t.llmStateSnapshot()
				if llmState.ProfileID == nil {
					row["llm_profile"] = "(active profile)"
				} else if n, ok := profName[*llmState.ProfileID]; ok {
					row["llm_profile"] = n
				} else {
					row["llm_profile"] = fmt.Sprintf("#%d (deleted)", *llmState.ProfileID)
				}
				out = append(out, row)
			}
			return jsonResult(out)
		})
}

// toolListLLMProfiles lists the available LLM profiles (name/model/active) so an
// orchestration agent can pick one for spawn_task's llm_profile. Never leaks keys.
func (s *Server) toolListLLMProfiles() actool.CoreTool {
	return roTool("list_llm_profiles",
		"List available LLM profiles: id/name/model/format/currently active. Use id as spawn_task.llm_profile_id to choose a child's LLM (for example inexpensive reconnaissance, stronger exploitation). Excludes API keys.",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			profs, err := s.m.pg.ListProfiles()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(profs))
			for _, p := range profs {
				out = append(out, map[string]any{
					"id": p.ID, "name": p.Name, "model": p.Model, "format": p.Format, "is_active": p.IsDefault,
				})
			}
			return jsonResult(map[string]any{"profiles": out})
		})
}

func (s *Server) toolSpawnTask() actool.CoreTool {
	return wrTool("spawn_task",
		"Create a child task and start its exploration engine; returns task_id. Delegate one problem/goal as an independent task. Optional parent_ref associates it with the current orchestration parent task ID.",
		objSchema(map[string]any{
			"description":            strParam("Task description (short title)"),
			"goal":                   strParam("Task goal (desired outcome)"),
			"parent_ref":             strParam("Optional parent task ID"),
			"source_task_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": fmt.Sprintf("Optional source task IDs for read-only inheritance (max %d). The child can start from those tasks' established assets/conclusions. Unlike parent_ref's parent pointer, this inherits content.", db.MaxTaskSourceCount)},
			"llm_profile_id":         map[string]any{"type": "integer", "description": "Optional LLM profile ID for this child's planner/worker (list_llm_profiles); defaults to parent's profile, then global active profile"},
			"timeout_seconds":        map[string]any{"type": "integer", "description": "Optional task timeout in seconds. On expiry, graceful cleanup leads to terminal timeout state. Omitted/0 means no time limit"},
			"plan_heartbeat_seconds": map[string]any{"type": "integer", "description": "Optional planner heartbeat seconds: after this interval since planning ended/task began without another trigger, wake planning to avoid deadlock and supervise active Workers. Omitted/0 defaults to 600 (10min);"},
			"seed_first_intent":      map[string]any{"type": "boolean", "description": "Optional simple-task shortcut: create a seed intent (description+goals) so a Worker starts without waiting for initial planning. Default false uses planning before execution."},
		}, "description", "goal"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Description          string          `json:"description"`
				Goal                 string          `json:"goal"`
				ParentRef            string          `json:"parent_ref"`
				SourceTaskIDs        []string        `json:"source_task_ids"`
				LLMProfileID         json.RawMessage `json:"llm_profile_id"`
				TimeoutSeconds       int             `json:"timeout_seconds"`
				PlanHeartbeatSeconds int             `json:"plan_heartbeat_seconds"`
				SeedFirstIntent      bool            `json:"seed_first_intent"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Description) == "" {
				a.Description = "Unnamed task"
			}
			if strings.TrimSpace(a.Goal) == "" {
				return actool.Errorf("goal is required"), nil
			}
			if a.TimeoutSeconds < 0 {
				a.TimeoutSeconds = 0
			}
			// Validate inherited source tasks: count, valid unique IDs, existence, like HTTP task creation.
			if len(a.SourceTaskIDs) > db.MaxTaskSourceCount {
				return actool.Errorf(fmt.Sprintf("Select at most %d related tasks", db.MaxTaskSourceCount)), nil
			}
			sourceIDs := make([]int64, 0, len(a.SourceTaskIDs))
			seenSources := map[int64]bool{}
			for _, raw := range a.SourceTaskIDs {
				id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
				if err != nil || id <= 0 || seenSources[id] {
					return actool.Errorf("Invalid or duplicate related task ID"), nil
				}
				if _, ok := s.m.Task(strconv.FormatInt(id, 10)); !ok {
					return actool.Errorf(fmt.Sprintf("Related task #%d not found", id)), nil
				}
				seenSources[id] = true
				sourceIDs = append(sourceIDs, id)
			}
			// LLM profile resolution: explicit id > inherit parent's pin > active(nil).
			var pin *int64
			if id := parseProfileID(a.LLMProfileID); id > 0 {
				if _, ok := s.loadProfileConfig(id); !ok {
					return actool.Errorf(fmt.Sprintf("LLM profile #%d not found or has no API key", id)), nil
				}
				pin = &id
			} else if a.ParentRef != "" {
				if pt, ok := s.m.Task(a.ParentRef); ok {
					pin = pt.LLMProfileID
				}
			}
			var llmIDs []int64
			if pin != nil {
				llmIDs = []int64{*pin}
			}
			t, err := s.m.CreateTaskWithOptions(a.Description, a.Goal, db.TaskCreateOptions{
				SourceTaskIDs:        sourceIDs,
				LLMProfileIDs:        llmIDs,
				TimeoutSeconds:       a.TimeoutSeconds,
				PlanHeartbeatSeconds: a.PlanHeartbeatSeconds,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.ParentRef != "" {
				t.ParentRef = a.ParentRef
				if id, e := strconv.ParseInt(t.ID, 10, 64); e == nil {
					_ = s.m.PG().SetParentRef(id, a.ParentRef)
				}
			}
			// Share launchTask with HTTP createTask: seed, visible background goal decomposition
			// (round 0, LLM steps, individual goals), then engine.Run.
			// seed_first_intent defaults false; simple tasks may start one Worker before normal planning.
			s.launchTask(t, a.Description+" "+a.Goal, a.SeedFirstIntent)
			return actool.Text(fmt.Sprintf("task created: %s", t.ID)), nil
		})
}

func (s *Server) toolPauseTask() actool.CoreTool {
	return wrTool("pause_task", "Pause a task and stop its planner/worker loops.",
		objSchema(map[string]any{"task_id": strParam("Task ID to pause")}, "task_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			_ = json.Unmarshal(in, &a)
			t, ok := s.resolveModelTask(a.TaskID)
			if !ok {
				return actool.Errorf("Task not found: " + a.TaskID + " (pass the bare numeric task id, e.g. 772)"), nil
			}
			if _, err := s.applyTaskControlWithCause(t, "pause", agent.AbortPausedByOrchestrator); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("task paused: " + a.TaskID), nil
		})
}

func (s *Server) toolGetTaskGraph() actool.CoreTool {
	return roTool("get_task_graph", "Read task graph overview by task_id (same as graph_overview: assets/frontier/findings/coverage).",
		objSchema(map[string]any{"task_id": strParam("Task ID")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GraphOverviewTool)
		})
}

func (s *Server) toolListTaskFindings() actool.CoreTool {
	return roTool("list_task_findings", "Read confirmed findings by task_id, including flag/PoC and id/task_id/intent_id/vulnclass/severity/summary/state.",
		objSchema(map[string]any{"task_id": strParam("Task ID")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListFindingsTool)
		})
}

func (s *Server) toolAddHint() actool.CoreTool {
	return wrTool("add_task_hint", "Inject strategic hints for a task's next planner round.\n"+
		"Prefer batching in hints; returned ids match length/order, with id=0 for failures. For a single hint omit hints and provide top-level text.",
		objSchema(map[string]any{
			"task_id":      strParam("Task ID"),
			"hints":        map[string]any{"type": "array", "description": "Preferred hints array; item fields match top-level text/asset_ids/traffic_refs.", "items": objSchema(map[string]any{"text": strParam("Hint content"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": agent.HintTrafficSchema()})},
			"text":         strParam("[Single] Hint content"),
			"traffic_refs": agent.HintTrafficSchema(),
			"asset_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Optional anchored asset IDs in that task (zero/one/many)"},
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).AddHintTool)
		})
}

func (s *Server) toolGetWorkerTrace() actool.CoreTool {
	return roTool("get_task_worker_trace",
		"Read task work trace: get_task_worker_trace(task_id,intent_id) for summaries, then step_ids=[...] for full content (max 5 per call; excess omitted).",
		objSchema(map[string]any{
			"task_id":   strParam("Task ID"),
			"intent_id": map[string]any{"type": "integer", "description": "Intent ID (worker in this task)"},
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Optional step IDs to read fully (max 5 per call; excess listed in omitted_step_ids)"},
		}, "task_id", "intent_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).GetWorkerTraceTool)
		})
}

func (s *Server) toolListWorkerTraces() actool.CoreTool {
	return roTool("list_task_worker_traces", "List work already executed in a task with step counts to identify traces worth reading through get_task_worker_trace.",
		objSchema(map[string]any{"task_id": strParam("Task ID")}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).ListWorkerTracesTool)
		})
}

func (s *Server) toolSearchWorkerTraces() actool.CoreTool {
	return roTool("search_task_worker_traces", "Search all work traces in a task by keyword; returns matching step summaries and intent_id.",
		objSchema(map[string]any{"task_id": strParam("Task ID"), "q": strParam("Search keyword")}, "task_id", "q"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).SearchWorkerTracesTool)
		})
}

func (s *Server) toolGetTaskNodeDetail() actool.CoreTool {
	return roTool("get_task_node_detail",
		"Read a task's full exploration node (finding/fact/intent/goal: summary+details/evidence/PoC). id is an exploration node ID from report_finding or list_task_findings.id. Use to obtain full finding evidence before reporting.",
		objSchema(map[string]any{
			"task_id": strParam("Task ID"),
			"id":      map[string]any{"type": "integer", "description": "Exploration node ID (not asset ID)"},
		}, "task_id", "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			return s.delegateToTask(ctx, in, (*agent.ToolSet).NodeDetailTool)
		})
}

// toolUpdateFindingReport writes/overwrites a finding's detailed Markdown report.
// finding_id is the id report_finding returned ("finding recorded: <id>", the
// finding node id). The write (SetFindingReportByNodeID) is keyed by node_id and
// task-agnostic, so this host tool needs no task_id / exploration store.
func (s *Server) toolUpdateFindingReport() actool.CoreTool {
	return wrTool("update_finding_report",
		"Write/update an existing finding's detailed Markdown report, replacing the entire prior report. finding_id takes report_finding's node ID (the number in \"finding recorded: <id>\"). Suggested sections: overview, impact, reproduction steps, evidence/PoC, and remediation.",
		objSchema(map[string]any{
			"finding_id":       map[string]any{"type": "integer", "description": "Finding ID returned by report_finding"},
			"report":           strParam("Complete report in Markdown"),
			"evidence_version": map[string]any{"type": "integer", "description": "Evidence version returned by get_finding_traffic; prevents overwriting newer evidence changes"},
		}, "finding_id", "report"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				EvidenceVersion *int64          `json:"evidence_version"`
				FindingID       json.RawMessage `json:"finding_id"`
				Report          string          `json:"report"`
			}
			_ = json.Unmarshal(in, &a)
			nodeID := parseProfileID(a.FindingID) // Reuse number-or-numeric-string parsing.
			if nodeID <= 0 {
				return actool.Errorf("Invalid finding_id"), nil
			}
			n, err := s.m.pg.SetFindingReportVersionByNodeID(ctx, nodeID, a.Report, a.EvidenceVersion)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == 0 {
				return actool.Errorf(fmt.Sprintf("No finding for finding_id=%d (register it with report_finding first)", nodeID)), nil
			}
			return actool.Text(fmt.Sprintf("finding %d report updated (%d chars)", nodeID, len(a.Report))), nil
		})
}

// deriveTaskStatus mirrors listTasks' status derivation for the list_tasks tool.
func (s *Server) deriveTaskStatus(t *Task) string {
	lifecycle := t.lifecycleSnapshot()
	switch {
	case isTerminalStatus(lifecycle.Status):
		return lifecycle.Status
	case lifecycle.Paused || s.engine.IsPaused(t.ID):
		return "paused"
	case s.engine.ReadyFor(t) && s.engine.Started(t.ID):
		return "running"
	}
	return "created"
}

// orchestrationToolSeeds seeds the cross-task tools into the tools table so they
// are bindable per-agent (default: bound to nobody — opt-in for orchestration
// agents). First-insert only, like the traffic seeds.
func (s *Server) seedOrchestrationTools() {
	// Task/platform tools default-bind Auto, the built-in platform operator. SeedTool applies only
	// on first insertion; existing rows gain bindings through seedAutoDefaultBindings.
	autoAgents, _ := json.Marshal([]string{"auto"})
	for _, t := range s.orchestrationTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings := autoAgents
		if t.Name() == "bind_finding_traffic" {
			bindings = json.RawMessage(`["reporter"]`)
		}
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, bindings)
	}
	for _, t := range s.platformTools() {
		schema, _ := json.Marshal(t.InputSchema())
		_ = s.m.PG().SeedTool(t.Name(), t.Description(), schema, autoAgents)
	}
	s.refreshBuiltinToolSchemas()
	s.seedAutoDefaultBindings()
	s.seedPlannerDefaultBindings()
	s.seedPlannerListAssetsBinding()
	s.seedCompanyScopeRebind()
	s.seedWorkerReadToolsUnbind() // Unbind list_facts/list_companies/list_worker_traces from Workers once.
	s.seedWorkerReadbackRebind()  // Restore search_all_worker_traces/get_worker_trace/node_detail after an erroneous old migration.
	s.seedAutoReportFindingBinding()
	s.unbindGoalMetDefault()
	s.removeCaidoTools()              // One-time: purge retired Caido integration's catalog rows.
	s.reseedGoalsPrompt()             // One-time goals prompt revision adds operational-constraint extraction.
	s.reseedMainAgentPrompt()         // One-time mainagent revision asks whether direct intents after completion should become goals.
	s.reseedPlannerPrompt()           // One-time planner revision clarifies zero-intent cases and quantified acceptance checks.
	s.reseedWorkerPrompt()            // One-time Worker revision adds evidence threshold for negative conclusions.
	s.seedReporterAgent()             // One-time report-writing agent/tool/finding-trigger seed.
	s.upgradeReporterTriggerMessage() // One-time legacy reporter migration returns evidence_version.
	s.seedFindingTrafficTools()       // Add optional evidence parameters/read-only evidence tools while preserving user configuration.
	s.seedFindingWorkflowTools()
	// Solo pentest defaults require no migration: fresh initialization already seeds list_assets,
	// insert_assets, report_finding, list_findings, and list_companies with pentest bindings.
	// No historical database requires that migration.
}

// refreshBuiltinToolSchemas propagates code schema/description changes on the
// orchestration + platform tools into already-seeded rows ONCE per version flag —
// SeedTool is first-insert-only, so new parameters such as spawn_task.llm_profile never
// reaches an old DB otherwise. Preserves each tool's agent binding + enabled flag.
// Bump the flag whenever these tools' schemas/descriptions change in code.
func (s *Server) refreshBuiltinToolSchemas() {
	const flag = "tool_schema_refresh_v9_test_assurance"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := append(s.orchestrationTools(), s.platformTools()...)
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema); err != nil {
			log.Printf("[tools] refresh %s schema failed: %v", t.Name(), err)
		}
	}
	// Also refresh selected built-in tool defaults:
	// - goal_met: old wording implied ending one planning round, incorrectly completing whole tasks
	//   immediately after starting.
	// - insert_assets: new related parameter marks task relevance/coverage inclusion;
	//   first-insert seeding otherwise cannot update old schemas.
	// - list_facts: pagination adds limit/before/q; old empty schemas would misleadingly show
	//   no parameters in UI and omit model-facing argument guidance.
	// - list_findings: description pointed workers at list_facts, which they are not bound to.
	// - add_intent/prove_goal/report_finding: test-assurance revision (vuln_class/component/skills,
	//   chain_analysis finish gate, required confidence/counterevidence).
	refreshBuiltin := map[string]bool{"goal_met": true, "insert_assets": true, "list_facts": true, "list_findings": true,
		"add_intent": true, "prove_goal": true, "report_finding": true}
	for _, sd := range agent.BuiltinToolSeeds() {
		if !refreshBuiltin[sd.Key] {
			continue
		}
		schema, _ := json.Marshal(sd.Schema)
		if err := s.m.pg.RefreshToolDefaults(sd.Key, sd.Desc, schema); err != nil {
			log.Printf("[tools] refresh %s desc failed: %v", sd.Key, err)
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[tools] refreshed orchestration/platform schemas to code defaults (one-time)")
}

// unbindGoalMetDefault removes goal_met's default "planner" binding ONCE (guarded by
// a settings flag), so existing DBs match the new default of NO agent. goal_met bypasses
// per-goal prove_goal to declare the whole task done — powerful/risky and redundant with
// the prove_goal→auto-complete path — so it ships unbound; users can re-bind it per agent
// in the UI. A user's own binding to another agent is untouched (we only strip planner).
func (s *Server) unbindGoalMetDefault() {
	const flag = "goal_met_unbind_default_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("planner", "goal_met"); err != nil {
		log.Printf("[tools] failed to unbind goal_met from planner: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// removeCaidoTools deletes the retired Caido integration's catalog rows ONCE, so
// old DBs stop showing caido_* in the tools UI. The tools are already inert (no
// backing CoreTool remains), so this is cosmetic cleanup; agents use the Burp MCP
// mobile_traffic_* tools for proxy traffic.
func (s *Server) removeCaidoTools() {
	const flag = "caido_tools_removed_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.DeleteToolsByPrefix("caido_"); err != nil {
		log.Printf("[tools] failed to remove caido tools: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// reseedGoalsPrompt installs the current goals default: a round-0 pass that extracts only
// explicit operational constraints (and scope), with goals stored verbatim rather than
// LLM-decomposed. First-insert-only SeedPromptIfEmpty cannot update existing version 1,
// so ResetPromptToDefault appends and activates a new revision while retaining old custom
// content in history. A settings flag limits migration to once; bump it for later changes.
// Fresh databases already seed latest defaults and need no duplicate revision.
func (s *Server) reseedGoalsPrompt() {
	const flag = "goals_prompt_verbatim_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // Attempt once regardless of success.
	a, err := s.m.pg.GetAgentByKey("goals")
	if err != nil || a == nil {
		return // Fresh DB without agent rows will seed latest defaults later; skip migration.
	}
	tmpl := agent.BuiltinPromptSeeds()["goals"]
	if tmpl == "" {
		return
	}
	// Current already equals latest seeded default; avoid appending a duplicate revision.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to refresh goals prompt to new default: %v", err)
		return
	}
	log.Printf("[prompts] appended new default goals prompt (verbatim goals, constraint/scope extraction only, one-time)")
}

// reseedMainAgentPrompt adds guidance asking humans to formalize goals when submitting intents
// after all goals are met. First-insert-only seeds cannot update old revisions, so append/activate
// through ResetPromptToDefault, retaining recoverable historical custom text.
// Guard once with a settings flag; fresh databases already have latest default.
// Same migration pattern as reseedGoalsPrompt.
func (s *Server) reseedMainAgentPrompt() {
	const flag = "mainagent_prompt_goalless_intent_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // Attempt once regardless of success.
	a, err := s.m.pg.GetAgentByKey("mainagent")
	if err != nil || a == nil {
		return // Fresh DB without agent rows will seed latest defaults later; skip migration.
	}
	tmpl := agent.BuiltinPromptSeeds()["mainagent"]
	if tmpl == "" {
		return
	}
	// Current already equals latest seeded default; avoid appending a duplicate revision.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to refresh mainagent prompt to new default: %v", err)
		return
	}
	log.Printf("[prompts] appended new default mainagent prompt (ask about new goals after completion, one-time)")
}

// reseedPlannerPrompt installs simplified defaults: restraint means deduplication, depth before
// coverage, mandatory direction when unmet goals lack work, and bounded negative-result rechecks.
// Bump settings flag (currently v2) for each substantive default change; first-insert seeds cannot
// update old prompts, so append/activate a revision and retain old custom content in history.
// Guard once; fresh DBs already have latest defaults, following reseedGoalsPrompt.
// Keep revision history recoverable.
func (s *Server) reseedPlannerPrompt() {
	const flag = "planner_prompt_assurance_v4"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // Attempt once regardless of success.
	a, err := s.m.pg.GetAgentByKey("planner")
	if err != nil || a == nil {
		return // Fresh DB without agent rows will seed latest defaults later; skip migration.
	}
	tmpl := agent.BuiltinPromptSeeds()["planner"]
	if tmpl == "" {
		return
	}
	// Current already equals latest seeded default; avoid appending a duplicate revision.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to refresh planner prompt to new default: %v", err)
		return
	}
	log.Printf("[prompts] appended new default planner prompt (exhaustive per-endpoint/role/param coverage goals, one-time)")
}

// reseedWorkerPrompt removes misleading tentative-negative wording and decouples observed/inferred
// confidence from exhaustive-method checks, restricting fact splitting to truly independent results.
// Flag v3 refreshes existing DBs once.
// Append/activate a new revision instead of first-insert-only seeding; preserve old history.
// Guard once; fresh DBs need no migration, following reseedGoalsPrompt.
func (s *Server) reseedWorkerPrompt() {
	const flag = "worker_prompt_assurance_v6"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // Attempt once regardless of success.
	a, err := s.m.pg.GetAgentByKey("worker")
	if err != nil || a == nil {
		return // Fresh DB without agent rows will seed latest defaults later; skip migration.
	}
	tmpl := agent.BuiltinPromptSeeds()["worker"]
	if tmpl == "" {
		return
	}
	// Current already equals latest seeded default; avoid appending a duplicate revision.
	if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil && cur == tmpl {
		return
	}
	if _, err := s.m.pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
		log.Printf("[prompts] failed to refresh worker prompt to new default: %v", err)
		return
	}
	log.Printf("[prompts] appended new default worker prompt (exhaustive within-intent coverage + root-cause dedup, one-time)")
}

// reporterToolCallMessage must always require get_finding_traffic before reporting.
// The read-only tool ignores capture/auto-binding switches and can read manual evidence too.
// Conditional reads would omit evidence_version when auto-binding defaults off, causing
// SetFindingReportVersionByNodeID to write legacy -1 and permanently mark reports stale in
// finding details/Markdown exports, without any UI action to clear that state.
const reporterToolCallMessage = "A finding was just registered through report_finding. Read finding_id (independent record ID) and finding_node_id (exploration node ID) from its returned JSON; " +
	"first call get_finding_traffic(finding_id) for current evidence and version (empty lists are normal; still write the report); " +
	"if runtime guidance enables automatic binding, verify and associate this finding's traffic before reading. Use finding_node_id for node details. " +
	"Finally save through update_finding_report(finding_id=finding_node_id, report, evidence_version=the version actually read). " +
	"evidence_version is required or the report remains permanently marked for update. Do not mix the two ID spaces."

// Historical default trigger (<=0.3.8); migrate exact matches only, preserving user edits.
// This historical default is a migration fingerprint, not generated output.
const reporterToolCallMessageV1 = "\u4e0a\u9762\u521a\u6709\u4e00\u4e2a\u6f0f\u6d1e\u88ab report_finding \u767b\u8bb0\u3002\u8bf7\u4ece\u89e6\u53d1\u4e0a\u4e0b\u6587\u91cc\u53d6\u51fa finding_id" +
	"\uff08\u5de5\u5177\u8fd4\u56de \"finding recorded: <id>\" \u91cc\u7684\u6570\u5b57\uff09\u4e0e\u4efb\u52a1 id\uff0c\u6309\u4f60\u7684\u804c\u8d23\u64b0\u5199\u8be5\u6f0f\u6d1e\u7684\u8be6\u7ec6\u62a5\u544a\uff0c" +
	"\u6700\u540e\u8c03\u7528 update_finding_report(finding_id, report) \u4fdd\u5b58\u3002"

// upgradeReporterTriggerMessage refreshes unchanged legacy defaults.
// reporter_agent_seed_v1 creates triggers only on initial agent creation; old installations get
// evidence_version schema through seedFindingTrafficTools but lack guidance to use it.
// One-time migration changes only untouched trigger text.
func (s *Server) upgradeReporterTriggerMessage() {
	const flag = "reporter_trigger_evidence_version_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // Attempt once.
	triggers, err := s.m.pg.ListTriggersFor("reporter")
	if err != nil {
		log.Printf("[reporter] failed to read triggers: %v", err)
		return
	}
	for _, t := range triggers {
		if !t.OnToolCall || t.ToolCallMessage != reporterToolCallMessageV1 {
			continue // Preserve user edits and non-finding triggers.
		}
		t.ToolCallMessage = reporterToolCallMessage
		if err := s.m.pg.UpdateTrigger(t); err != nil {
			log.Printf("[reporter] failed to upgrade trigger message: %v", err)
			return
		}
		log.Printf("[reporter] trigger message upgraded to read and return evidence_version")
	}
}

// seedReporterAgent creates editable/deletable non-builtin reporter, binds report/evidence/query
// tools, and triggers on report_finding so each registered finding receives a detailed report.
// Once-only settings guard respects user deletion and does not recreate the agent.
// Orchestration tools were seeded above, so bindings can resolve.
func (s *Server) seedReporterAgent() {
	const flag = "reporter_agent_seed_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // Attempt once regardless of success.

	if exist, _ := s.m.pg.GetAgentByKey("reporter"); exist != nil {
		return // User already owns this key; do not overwrite.
	}
	a, err := s.m.pg.CreateAgent("reporter", "Report writer",
		"Automatically gathers evidence and execution history for new findings, writes detailed Markdown reports, and saves them.")
	if err != nil {
		log.Printf("[reporter] failed to create agent: %v", err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, agent.ReporterDefaultPrompt); err != nil {
		log.Printf("[reporter] failed to seed prompt: %v", err)
	}
	// parallel+none gives one independent report session per finding.
	// merge=none avoids collapsing a wave of findings into one run and defeating parallelism.
	// maxParallel=5 bounds concurrent report sessions/LLM calls.
	if err := s.m.pg.SetAgentTriggerBehavior("reporter", "parallel", "none", 5); err != nil {
		log.Printf("[reporter] failed to set trigger run policy: %v", err)
	}
	// Bind report writing plus evidence/trace/state readers.
	if err := s.m.pg.AddAgentToToolBinding("reporter", []string{
		"update_finding_report", "get_task_node_detail", "list_task_findings",
		"get_task_worker_trace", "list_task_worker_traces", "search_task_worker_traces",
		"get_task_graph",
	}); err != nil {
		log.Printf("[reporter] failed to bind tools: %v", err)
	}
	// Trigger on report_finding; result includes finding recorded: <id>, and trigger context also
	// contains task ID.
	if _, err := s.m.pg.CreateTrigger(&db.AgentTrigger{
		AgentKey:        "reporter",
		Enabled:         true,
		OnToolCall:      true,
		ToolNames:       []string{"report_finding"},
		ToolCallMessage: reporterToolCallMessage,
	}); err != nil {
		log.Printf("[reporter] failed to create trigger: %v", err)
	}
	log.Printf("[reporter] seeded report-writing agent and finding trigger")
}

// seedAutoReportFindingBinding adds "auto" to report_finding's binding ONCE so
// conversation-context agents can call it without requiring an intent_id.
func (s *Server) seedAutoReportFindingBinding() {
	const flag = "auto_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("auto", []string{"report_finding"}); err != nil {
		log.Printf("[auto] failed to bind default report_finding: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerDefaultBindings adds "planner" to report_finding's binding ONCE
// (guarded by a settings flag), so existing DBs — whose report_finding row was
// seeded as worker-only — also let the planner record findings. Fresh DBs already
// get it via PlannerTools(); this only backfills without overriding a user unbind.
func (s *Server) seedPlannerDefaultBindings() {
	const flag = "planner_report_finding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"report_finding"}); err != nil {
		log.Printf("[planner] failed to bind default report_finding: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedPlannerListAssetsBinding adds "planner" to list_assets's binding ONCE
// (guarded by a settings flag), so existing DBs — whose list_assets row was seeded
// as auto/pentest-only — also let the planner query the asset store by DSL. Fresh
// DBs already get it via PlannerTools(); this only backfills without overriding a
// user unbind.
func (s *Server) seedPlannerListAssetsBinding() {
	const flag = "planner_list_assets_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"list_assets"}); err != nil {
		log.Printf("[planner] failed to bind default list_assets: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedCompanyScopeRebind changes add_company_scope's default binding ONCE on
// existing DBs (guarded by a settings flag): the tool moves off worker and onto
// planner — defining a company's asset scope is a planning/main/auto concern, not
// something a worker does mid-exploration. Fresh DBs already get planner via
// PlannerTools() and lack worker via WorkerTools(); this only backfills old rows.
// One-shot + flag-guarded so a user who later re-binds worker isn't overridden.
func (s *Server) seedCompanyScopeRebind() {
	const flag = "company_scope_rebind_v1" // Move default binding from Worker to planner.
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("planner", []string{"add_company_scope"}); err != nil {
		log.Printf("[planner] failed to bind default add_company_scope: %v", err)
		return
	}
	if err := s.m.pg.RemoveAgentFromTool("worker", "add_company_scope"); err != nil {
		log.Printf("[worker] failed to unbind add_company_scope: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadToolsUnbind strips the read-context tools off worker's default
// binding ONCE on existing DBs (guarded by a settings flag): a worker executes one
// intent and writes back — reading facts/companies and listing all workers' traces is
// a planning/main concern, not the executor's. Fresh DBs already lack these via
// WorkerTools(); this only backfills old rows without overriding a user who
// deliberately re-binds worker. Each RemoveAgentFromTool is per-tool +
// membership-guarded, so planner/mainagent bindings of the same tool are untouched.
//
// NOTE: search_all_worker_traces / get_worker_trace / node_detail are intentionally NOT
// unbound — worker owns them for cross-work look-back + node drill-down (see WorkerTools).
// They used to be in this list back when worker lacked them; seedWorkerReadbackRebind
// repairs DBs whose old run stripped them.
func (s *Server) seedWorkerReadToolsUnbind() {
	const flag = "worker_readtools_unbind_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, k := range []string{
		"list_facts", "list_companies", "list_worker_traces",
	} {
		if err := s.m.pg.RemoveAgentFromTool("worker", k); err != nil {
			log.Printf("[worker] failed to unbind %s from worker: %v", k, err)
			return // On error leave flag unset for startup retry.
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedWorkerReadbackRebind re-binds the cross-work look-back / drill-down tools onto
// worker ONCE (guarded by a settings flag): an earlier seedWorkerReadToolsUnbind wrongly
// stripped search_all_worker_traces / get_worker_trace / node_detail from worker after
// they had been added to WorkerTools(), so any DB that ran that migration lost them.
// Fresh DBs already have them via WorkerTools() and this is a harmless no-op there.
// One-shot + flag-guarded so a user who later deliberately unbinds them isn't overridden.
func (s *Server) seedWorkerReadbackRebind() {
	const flag = "worker_readback_rebind_v2" // v2 adds node_detail.
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("worker", []string{
		"search_all_worker_traces", "get_worker_trace", "node_detail",
	}); err != nil {
		log.Printf("[worker] failed to bind trace/detail tools: %v", err)
		return // On error leave flag unset for startup retry.
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// seedAutoDefaultBindings adds "auto" to the task-op + platform tools' bindings
// ONCE (guarded by a settings flag), so existing DBs whose tool rows were seeded
// before Auto existed still give Auto its default toolset — without re-adding it
// after a user deliberately unbinds.
func (s *Server) seedAutoDefaultBindings() {
	const flag = "auto_default_bindings_v3" // v3 replaces old asset names and adds insert_assets/add_company_scope.
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	keys := make([]string, 0, len(platformToolKeys)+12)
	for _, t := range s.orchestrationTools() {
		keys = append(keys, t.Name())
	}
	keys = append(keys, platformToolKeys...)
	// Auto platform operations need asset query/registration and company-scope management.
	keys = append(keys, "insert_assets", "add_company_scope", "list_assets")
	if err := s.m.pg.AddAgentToToolBinding("auto", keys); err != nil {
		log.Printf("[auto] failed to bind defaults: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
