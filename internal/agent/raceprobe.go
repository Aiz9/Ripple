package agent

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/Autumn-27/artex/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Concurrency / race-condition (TOCTOU) testing. A single-use or limited operation
// — redeem a coupon, withdraw against a balance, verify an OTP, approve a transfer —
// must succeed at most once even when fired in parallel. This probe sends K
// identical copies of a captured request simultaneously and counts how many the
// server ACCEPTS; more than the expected maximum is a race/TOCTOU finding
// (double-spend, limit bypass, coupon stacking, duplicate processing). As always
// the proof is behavioural (N accepted, not a status code). SANDBOX ONLY.

// raceVerdict counts accepted outcomes and decides whether the concurrency limit
// was breached. expectedMax is the number of concurrent acceptances that is
// legitimate (default 1 for single-use operations).
func raceVerdict(outcomes []txnOutcome, expectedMax int) (accepted int, violation bool) {
	if expectedMax < 1 {
		expectedMax = 1
	}
	for _, o := range outcomes {
		if o == txnAccepted {
			accepted++
		}
	}
	return accepted, accepted > expectedMax
}

// fireConcurrent sends raw to host K times in parallel (released together) and
// returns each response's classified outcome and status.
func fireConcurrent(ctx context.Context, c *devicelab.BurpMCP, host string, port int, tls bool, raw string, k int) ([]txnOutcome, []int) {
	outcomes := make([]txnOutcome, k)
	statuses := make([]int, k)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < k; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release all goroutines at once to maximise overlap
			resp, err := c.SendRequest(ctx, host, port, tls, raw)
			if err != nil {
				outcomes[i] = txnError
				return
			}
			statuses[i] = httpStatus(resp)
			outcomes[i] = classifyTxn(httpStatus(resp), httpBody(resp))
		}(i)
	}
	close(start)
	wg.Wait()
	return outcomes, statuses
}

func (t *ToolSet) mobileRaceProbe() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":               strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index":         intField("history index of the captured single-use/limited operation to race (redeem, withdraw, approve, verify-OTP, transfer)"),
			"concurrency":           intField("number of identical requests to fire in parallel (default 20)"),
			"expected_max_accepted": intField("how many concurrent acceptances are legitimate (default 1 for a single-use operation)"),
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return writeTool("mobile_race_probe",
		"Deterministic race-condition / TOCTOU tester. Fires K identical copies of a captured request simultaneously and counts how many the server ACCEPTS; if more than expected_max_accepted succeed, the operation is not atomic under concurrency (double-spend, limit bypass, coupon stacking, duplicate processing). Use on single-use or limited operations (redeem/withdraw/approve/verify/transfer). A finding is raised only on the behavioural result (N > expected accepted), never a status code. SANDBOX ONLY: authorized test accounts and simulated funds.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL       string `json:"mcp_url"`
				HistoryIndex *int   `json:"history_index"`
				Concurrency  int    `json:"concurrency"`
				ExpectedMax  int    `json:"expected_max_accepted"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if a.HistoryIndex == nil || *a.HistoryIndex < 0 {
				return actool.Errorf("history_index (>= 0) is required"), nil
			}
			if a.Concurrency <= 1 {
				a.Concurrency = 20
			}
			if a.ExpectedMax < 1 {
				a.ExpectedMax = 1
			}
			if a.MCPURL == "" {
				a.MCPURL = devicelab.BurpMCPURL()
			}
			c, err := devicelab.DialBurpMCP(ctx, a.MCPURL)
			if err != nil {
				return errf("connect Burp MCP: %v", err), nil
			}
			defer c.Close()
			ex, herr := c.ProxyHistory(ctx, *a.HistoryIndex, 1)
			if herr != nil {
				return errf("read history: %v", herr), nil
			}
			if len(ex) == 0 {
				return errf("no captured exchange at history_index %d", *a.HistoryIndex), nil
			}
			req := ex[0]
			port := 443
			if !req.TLS {
				port = 80
			}
			outcomes, statuses := fireConcurrent(ctx, c, req.Host, port, req.TLS, req.Request, a.Concurrency)
			accepted, violation := raceVerdict(outcomes, a.ExpectedMax)

			result := map[string]any{
				"endpoint":              req.Method + " " + req.Host + req.Path,
				"concurrency":           a.Concurrency,
				"expected_max_accepted": a.ExpectedMax,
				"accepted":              accepted,
				"statuses":              statuses,
				"race_condition":        violation,
				"note":                  "accepted > expected_max_accepted means the operation is not serialized under concurrency; verify the duplicated effect (ledger/balance) out-of-band.",
			}
			if violation {
				fb := &findingBlock{
					VulnClass:        "Business Logic — race condition / TOCTOU (non-atomic operation)",
					Name:             "Race condition on " + req.Method + " " + req.Path,
					Severity:         "high",
					Summary:          "Firing identical requests concurrently caused the server to accept the operation more times than is legitimate, indicating no server-side serialization.",
					AffectedEndpoint: req.Host + req.Path,
					Method:           req.Method,
					Preconditions:    "An authorized sandbox account and a captured single-use/limited operation.",
					Reproduction: []string{
						"Capture one legitimate request to " + req.Method + " " + req.Path + ".",
						"Fire " + itoa(a.Concurrency) + " identical copies concurrently.",
						"Observe " + itoa(accepted) + " acceptances where at most " + itoa(a.ExpectedMax) + " is legitimate.",
					},
					Expected:           "The server serializes the operation so at most " + itoa(a.ExpectedMax) + " concurrent request(s) succeed.",
					Actual:             itoa(accepted) + " of " + itoa(a.Concurrency) + " concurrent requests were accepted.",
					Impact:             "Double-spend / limit bypass / coupon stacking / duplicate processing — direct financial loss or integrity violation.",
					Remediation:        "Make the operation atomic server-side: use row locks / SELECT … FOR UPDATE / unique constraints / idempotency keys so concurrent duplicates cannot both commit.",
					VerificationStatus: "confirmed",
				}
				if id, ok := t.fileFinding(ctx, fb, t.endpointAssetID("https://"+req.Host+req.Path, req.Method)); ok {
					fb.FiledFindingID = id
				}
				result["finding"] = fb
			}
			out, _ := json.Marshal(result)
			return actool.Text(string(out)), nil
		})
}
