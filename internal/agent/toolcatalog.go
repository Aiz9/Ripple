package agent

import (
	"context"
	"encoding/json"

	actool "github.com/Autumn-27/norma/tool"
)

// Make built-in tools enumerable and overridable by the database:
// - BuiltinToolSeeds expands the three execution agents' tools into seed records (key,
//   description, parameter schema, default agent bindings) for idempotent startup seeding.
// - ToolResolve filters assembled tools per agent, overrides description/schema, and injects
//   defaults from DB rows. Keys/handlers remain in code; DB edits affect prose/defaults only.
// Call handlers always come from code; DB changes only model-facing descriptions/default arguments.

// ToolSeed is a seedable snapshot: key equals CoreTool.Name(), fixed to the handler and read-only
// in UI. Desc/Schema come from code; Agents names the code-default bindings.
type ToolSeed struct {
	Key    string         // CoreTool.Name(): immutable primary key.
	Desc   string         // Top-level description, overridable in UI.
	Schema map[string]any // JSON Schema structure is read-only; description/default may be edited in UI.
	Agents []string       // Default agent keys (worker/planner/mainagent).
}

// builtinToolsByAgent constructs domain tools with an empty read-only ToolSet (nil stores).
// Constructors only put closures in Spec without dereferencing stores, so nil is safe:
// only Name/Description/InputSchema are read here; Call is never invoked.
//
// SDK base tools (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash) are deliberately excluded:
// every agent always has them, and most guidance lives in Prompt(), beyond Description().
// Seeding only descriptions would misleadingly override half the guidance. No DB row means
// ToolResolve passes them through unchanged; only ARTEX domain tools enter the managed table.
func builtinToolsByAgent() map[string][]actool.CoreTool {
	ts := NewToolSet(nil, "")
	return map[string][]actool.CoreTool{
		"mainagent": ts.MainAgentTools(),
		"planner":   ts.PlannerTools(),
		"worker":    ts.WorkerTools(),
		// Goals round-0 pass defaults to set_constraints only: it extracts explicit operational
		// constraints (and scope via add_task_scope), while goals are stored verbatim, not decomposed.
		// Shared with mainagent, with UI-editable descriptions/schema and agent bindings.
		"goals": {ts.setConstraints()},
		// Auto defaults to finding reporting and asset management; other domain tools are opt-in via UI.
		// Fresh DBs use this seed; existing DBs migrate with seedAutoDefaultBindings.
		"auto": {ts.addFinding(), ts.insertAssets(), ts.addCompanyScope(), ts.listAssets(), ts.listCompanies()},
		// Solo pentest defaults to query/insert assets, report/list findings, and list companies.
		// Fresh DBs use this seed; existing DBs migrate with seedPentestDefaultBindings.
		"pentest": {ts.listAssets(), ts.insertAssets(), ts.addFinding(), ts.listFindings(), ts.listCompanies()},
	}
}

// defaultUnbound tools remain visible in the catalog and can be manually assigned, but default
// to no agents. ToolResolve drops empty-bound tools for all agents until explicitly enabled.
// They remain in an agent's base list (for example PlannerTools goal_met) so seed can obtain
// desc/schema and ToolResolve can retain them when a user explicitly binds them again.
//
// goal_met bypasses per-goal proof and declares the whole task complete, risking false completion.
// Since proving the last goal already completes the task, leave goal_met unbound by default.
var defaultUnbound = map[string]bool{"goal_met": true}

// BuiltinToolSeeds deduplicates tools by name across agents (for example list_assets), unions
// agent bindings, and forces defaultUnbound bindings empty.
func BuiltinToolSeeds() []ToolSeed {
	byAgent := builtinToolsByAgent()
	order := []string{"mainagent", "goals", "planner", "worker", "auto", "pentest"}

	type acc struct {
		tool   actool.CoreTool
		agents []string
	}
	m := map[string]*acc{}
	var keys []string
	for _, ak := range order {
		for _, t := range byAgent[ak] {
			a, ok := m[t.Name()]
			if !ok {
				a = &acc{tool: t}
				m[t.Name()] = a
				keys = append(keys, t.Name())
			}
			a.agents = append(a.agents, ak)
		}
	}

	out := make([]ToolSeed, 0, len(keys))
	for _, k := range keys {
		a := m[k]
		agents := a.agents
		if defaultUnbound[k] {
			agents = []string{} // Cataloged and manually bindable, but unassigned by default; store [] rather than null.
		}
		out = append(out, ToolSeed{
			Key:    k,
			Desc:   a.tool.Description(),
			Schema: a.tool.InputSchema(),
			Agents: agents,
		})
	}
	return out
}

// ToolResolve, if set, post-processes an agent's fully-assembled tool list against
// the DB tools table: it drops tools not bound to this agent (or globally disabled)
// and wraps the rest so the model sees the DB-overridden description/schema and
// Default arguments get injected. Tools without matching DB rows (MCP/skill/host tools like
// traffic) pass through untouched. nil = tools unchanged. Wired in server/assembly.go.
var ToolResolve func(ctx context.Context, agentKey string, tools []actool.CoreTool) []actool.CoreTool

// DecorateTool wraps t so Description()/InputSchema() report the DB overrides and
// Call() injects scalar parameter defaults (from schema's "default" props) whenever
// the model omitted them. Name/Prompt/permission/scheduler flags delegate to t, so
// the tool's identity and handler are unchanged. Empty desc/schema fall back to t's.
func DecorateTool(t actool.CoreTool, desc string, schema map[string]any) actool.CoreTool {
	if desc == "" {
		desc = t.Description()
	}
	if len(schema) == 0 {
		schema = t.InputSchema()
	}
	return &overriddenTool{CoreTool: t, desc: desc, schema: schema}
}

// overriddenTool is a CoreTool decorator: it embeds the original (so all behavioral
// methods — Prompt/IsReadOnly/IsConcurrencySafe/CheckPermissions/Name — delegate)
// and overrides only the model-facing description/schema plus default injection.
type overriddenTool struct {
	actool.CoreTool
	desc   string
	schema map[string]any
}

func (o *overriddenTool) Description() string         { return o.desc }
func (o *overriddenTool) InputSchema() map[string]any { return o.schema }

func (o *overriddenTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	return o.CoreTool.Call(ctx, injectDefaults(in, o.schema), tc)
}

// injectDefaults fills scalar parameter defaults declared in the (possibly edited)
// schema into the input JSON whenever the model omitted the field or left it empty/
// null. Names/types/required structure stays untouched; only defaults are merged.
func injectDefaults(in json.RawMessage, schema map[string]any) json.RawMessage {
	defs := scalarDefaults(schema)
	if len(defs) == 0 {
		return in
	}
	m := map[string]json.RawMessage{}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &m); err != nil {
			return in // non-object input: don't touch it
		}
	}
	changed := false
	for k, dv := range defs {
		if cur, ok := m[k]; !ok || isEmptyJSON(cur) {
			m[k] = dv
			changed = true
		}
	}
	if !changed {
		return in
	}
	b, err := json.Marshal(m)
	if err != nil {
		return in
	}
	return b
}

// scalarDefaults extracts properties[k]["default"] for scalar params (string/
// integer/number/boolean). Array/object defaults are skipped: merging them is
// ambiguous and not worth the surprise.
func scalarDefaults(schema map[string]any) map[string]json.RawMessage {
	props, _ := schema["properties"].(map[string]any)
	if len(props) == 0 {
		return nil
	}
	out := map[string]json.RawMessage{}
	for name, raw := range props {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		dv, ok := p["default"]
		if !ok || dv == nil {
			continue
		}
		switch p["type"] {
		case "string", "integer", "number", "boolean":
			if b, err := json.Marshal(dv); err == nil {
				out[name] = b
			}
		}
	}
	return out
}

func isEmptyJSON(raw json.RawMessage) bool {
	s := string(raw)
	return s == "null" || s == `""`
}
