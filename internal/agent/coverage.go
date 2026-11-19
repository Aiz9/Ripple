package agent

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/Aiz9/ripple/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// coverageKey is the "METHOD normalized-path" ledger key for a captured exchange.
func coverageKey(ex devicelab.Exchange) string {
	m, canon, ok := exchangeEndpoint(ex)
	if !ok {
		return ""
	}
	return m + " " + pathOf(canon)
}

// Per-endpoint testing-coverage ledger. The inventory records what endpoints exist;
// this records what has actually been TESTED on each — authz, auth, business-logic,
// injection, etc. — so the orchestrator can see coverage and target the untested,
// instead of coverage living only implicitly in whatever findings happened to fire.

var (
	coverageMu    sync.Mutex
	coverageStore = map[int64]map[string]map[string]bool{} // taskID -> "METHOD path" -> check -> tested
)

// recordCoverage marks that `check` was exercised against `endpoint` ("METHOD path")
// for a task. Safe to call with taskID 0 (shared/no-op bucket) and from any tool.
func recordCoverage(taskID int64, endpoint, check string) {
	if endpoint == "" || check == "" {
		return
	}
	coverageMu.Lock()
	defer coverageMu.Unlock()
	if coverageStore[taskID] == nil {
		coverageStore[taskID] = map[string]map[string]bool{}
	}
	if coverageStore[taskID][endpoint] == nil {
		coverageStore[taskID][endpoint] = map[string]bool{}
	}
	coverageStore[taskID][endpoint][check] = true
}

func coverageSnapshot(taskID int64) map[string][]string {
	coverageMu.Lock()
	defer coverageMu.Unlock()
	out := map[string][]string{}
	for ep, checks := range coverageStore[taskID] {
		list := make([]string, 0, len(checks))
		for c := range checks {
			list = append(list, c)
		}
		sort.Strings(list)
		out[ep] = list
	}
	return out
}

func (t *ToolSet) mobileCoverage() actool.CoreTool {
	return readTool("mobile_coverage",
		"Testing-coverage ledger: for each endpoint exercised this task, which checks have run (authz, jwt, business-logic, race, workflow, injection, mass-assignment, rate-limit, session, schema-fuzz, balance). Use it to see what is tested and to target endpoints with no or thin coverage. Endpoints in the inventory (mobile_api_harvest) with no entry here are untested.",
		obj(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			snap := coverageSnapshot(t.taskID)
			type row struct {
				Endpoint string   `json:"endpoint"`
				Checks   []string `json:"checks"`
			}
			rows := make([]row, 0, len(snap))
			checkCounts := map[string]int{}
			for ep, checks := range snap {
				rows = append(rows, row{Endpoint: ep, Checks: checks})
				for _, c := range checks {
					checkCounts[c]++
				}
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].Endpoint < rows[j].Endpoint })
			// untested harvested endpoints, when the inventory is available
			var untested []string
			if t.as != nil {
				if assets, err := t.as.QueryDSL("", "endpoint", t.taskID, 2000, 0); err == nil {
					for _, a := range assets {
						ep := strings.ToUpper(a.Method) + " " + pathFromURL(a.URL)
						if _, seen := snap[ep]; !seen {
							untested = append(untested, ep)
						}
					}
					sort.Strings(untested)
				}
			}
			out, _ := json.Marshal(map[string]any{
				"endpoints_tested": len(rows),
				"by_check":         checkCounts,
				"coverage":         rows,
				"untested":         untested,
			})
			return actool.Text(string(out)), nil
		})
}

// pathFromURL returns the path portion of a stored endpoint URL.
func pathFromURL(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		p := s[i:]
		if q := strings.IndexByte(p, '?'); q >= 0 {
			p = p[:q]
		}
		return p
	}
	return "/"
}
