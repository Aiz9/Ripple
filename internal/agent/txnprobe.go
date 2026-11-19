package agent

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Aiz9/ripple/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// mobile_txn_probe runs the financial business-logic experiments (invariants.go)
// against one captured transaction request, deterministically. It never asserts a
// bug from a status code alone: a tampered request is only a finding when the
// server ACCEPTS it in violation of a configured invariant.

type txnExperiment struct {
	Name      string     `json:"experiment"`
	Tamper    string     `json:"tamper"`
	Status    int        `json:"status"`
	Outcome   txnOutcome `json:"outcome"`
	Violation string     `json:"violation,omitempty"`
}

func (t *ToolSet) mobileTxnProbe() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":            strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index":      intField("history index of the captured transaction request (a transfer/payment with a JSON body) to probe"),
			"amount_field":       strField("JSON body field holding the amount (enables amount/limit experiments)"),
			"max_amount":         map[string]any{"type": "number", "description": "server-side per-transaction limit; 0 = none configured"},
			"currency_field":     strField("JSON body field holding the currency code (enables currency experiment)"),
			"allowed_currencies": strArr("currencies the account may transact in; a disallowed one is tried"),
			"idempotency_field":  strField("body field that should make a repeat a no-op; set to run the replay/idempotency experiment"),
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return writeTool("mobile_txn_probe",
		"Deterministic financial business-logic tester for ONE captured transaction request. Runs only the experiments whose invariants you configure (amount sign/limit via amount_field+max_amount, disallowed currency via currency_field+allowed_currencies, duplicate processing via idempotency_field) by tampering the request, replaying it, and classifying the server's response as accepted/rejected/denied from status AND body. A finding is raised only when the server ACCEPTS a request that violates an invariant — a clean decline is correct behavior. SANDBOX ONLY: use authorized test accounts and simulated funds; never run against production financial systems.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL            string   `json:"mcp_url"`
				HistoryIndex      *int     `json:"history_index"`
				AmountField       string   `json:"amount_field"`
				MaxAmount         float64  `json:"max_amount"`
				CurrencyField     string   `json:"currency_field"`
				AllowedCurrencies []string `json:"allowed_currencies"`
				IdempotencyField  string   `json:"idempotency_field"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if a.HistoryIndex == nil || *a.HistoryIndex < 0 {
				return actool.Errorf("history_index (>= 0) is required"), nil
			}
			inv := FinancialInvariants{AmountField: a.AmountField, MaxAmount: a.MaxAmount, CurrencyField: a.CurrencyField, AllowedCurrencies: a.AllowedCurrencies, IdempotencyField: a.IdempotencyField}
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
			recordCoverage(t.taskID, coverageKey(req), "business-logic")
			if !hasMutableBody(req.Request) {
				return actool.Errorf("captured request has no JSON or form body to tamper"), nil
			}
			_, curFields := bodyFieldTypes(req.Request)
			port := 443
			if !req.TLS {
				port = 80
			}
			replay := func(reqStr string) (int, string, error) {
				resp, e := c.SendRequest(ctx, req.Host, port, req.TLS, reqStr)
				if e != nil {
					return 0, "", e
				}
				return httpStatus(resp), httpBody(resp), nil
			}

			var exps []txnExperiment
			var violations []string
			runTamper := func(name, tamper, reqStr, violationIfAccepted string) {
				st, rb, e := replay(reqStr)
				if e != nil {
					exps = append(exps, txnExperiment{Name: name, Tamper: tamper, Violation: "replay error: " + e.Error()})
					return
				}
				oc := classifyTxn(st, rb)
				ex := txnExperiment{Name: name, Tamper: tamper, Status: st, Outcome: oc}
				if oc == txnAccepted && violationIfAccepted != "" {
					ex.Violation = violationIfAccepted
					violations = append(violations, name+": "+violationIfAccepted)
				}
				exps = append(exps, ex)
			}

			// Amount experiments.
			if a.AmountField != "" {
				if _, ok := curFields[a.AmountField]; ok {
					for _, tv := range amountTestValues(inv) {
						if nr, ok := setBodyFieldRaw(req.Request, a.AmountField, tv.raw); ok {
							runTamper("amount_"+tv.label, a.AmountField+"="+tv.raw, nr, amountViolation(tv.val, inv))
						}
					}
				}
			}
			// Currency experiment: try a disallowed currency.
			if a.CurrencyField != "" && len(a.AllowedCurrencies) > 0 {
				bad := disallowedCurrency(inv)
				if nr, ok := setBodyFieldRaw(req.Request, a.CurrencyField, strconv.Quote(bad)); ok {
					runTamper("currency_swap", a.CurrencyField+"="+bad, nr, "disallowed currency "+bad+" accepted")
				}
			}
			// Replay / idempotency experiment: send the original request twice.
			if a.IdempotencyField != "" {
				st1, rb1, e1 := replay(req.Request)
				st2, rb2, e2 := replay(req.Request)
				if e1 == nil && e2 == nil {
					o1, o2 := classifyTxn(st1, rb1), classifyTxn(st2, rb2)
					ex := txnExperiment{Name: "replay_idempotency", Tamper: "send identical request twice", Status: st2, Outcome: o2}
					if o1 == txnAccepted && o2 == txnAccepted && !indicatesDuplicateSuppressed(rb2) {
						ex.Violation = "identical request with the same " + a.IdempotencyField + " was accepted twice (no idempotency enforcement → duplicate processing)"
						violations = append(violations, "replay_idempotency: "+ex.Violation)
					}
					exps = append(exps, ex)
				}
			}

			if len(exps) == 0 {
				return actool.Errorf("no experiments ran; configure amount_field, currency_field+allowed_currencies, or idempotency_field matching the request body"), nil
			}

			result := map[string]any{
				"endpoint":    req.Method + " " + req.Host + req.Path,
				"experiments": exps,
				"violations":  violations,
				"note":        "A 'violation' means the server accepted an invariant-breaking request; verify the financial effect (balance/txn record) out-of-band before confirming.",
			}
			if len(violations) > 0 {
				fb := &findingBlock{
					VulnClass:        "Business Logic — financial invariant violation",
					Name:             "Financial invariant not enforced on " + req.Method + " " + req.Path,
					Severity:         "high",
					Summary:          "The server accepted transaction request(s) that violate a configured business invariant.",
					AffectedEndpoint: req.Host + req.Path,
					Method:           req.Method,
					Preconditions:    "An authorized sandbox account with simulated funds and a captured transaction request with a JSON body.",
					Reproduction: append([]string{"Capture a legitimate transaction request to " + req.Method + " " + req.Path + "."},
						"Replay it tampering the field(s) below; observe the server accepts each:",
					),
					Expected:           "The server rejects any request that breaks the configured invariant (negative/zero/over-limit amount, disallowed currency, or a duplicate of an already-processed transaction).",
					Actual:             "Accepted invariant-breaking requests: " + strings.Join(violations, "; "),
					Impact:             "Financial integrity failure: incorrect or unauthorized value movement, limit bypass, or duplicate processing of funds.",
					Remediation:        "Enforce the invariant server-side: validate amount sign and per-transaction limits, restrict currencies to the account's allow-list, and make transaction submission idempotent via a server-tracked key.",
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

type amountTest struct {
	label, raw string
	val        float64
}

// amountTestValues returns the tamper amounts to try given the invariants.
func amountTestValues(inv FinancialInvariants) []amountTest {
	tests := []amountTest{
		{"negative", "-1", -1},
		{"zero", "0", 0},
	}
	if inv.MaxAmount > 0 {
		over := inv.MaxAmount + 1
		tests = append(tests, amountTest{"over_limit", strconv.FormatFloat(over, 'f', -1, 64), over})
	}
	return tests
}

// disallowedCurrency returns a currency code not in the allow-list (ISO 4217 test
// code XTS unless that is itself allowed, in which case XXX).
func disallowedCurrency(inv FinancialInvariants) string {
	if currencyAllowed("XTS", inv) {
		return "XXX"
	}
	return "XTS"
}
