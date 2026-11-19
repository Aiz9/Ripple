package agent

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"strings"

	"github.com/Aiz9/ripple/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Financial state consistency, verified out-of-band: read the balance, perform a
// transaction, read the balance again, and check the invariants that generic API
// testing cannot see — an accepted debit must equal the transaction amount, and a
// rejected transaction must leave the balance unchanged.

const balanceEpsilon = 0.0001

// balanceVerdict checks the balance invariant given the transaction outcome and the
// before/after balances. Returns ok and, when not ok, the violated invariant.
func balanceVerdict(outcome txnOutcome, before, after, expected float64) (bool, string) {
	delta := before - after // amount debited from the sender
	switch outcome {
	case txnAccepted:
		switch {
		case math.Abs(delta-expected) < balanceEpsilon:
			return true, ""
		case math.Abs(delta) < balanceEpsilon:
			return false, "transaction accepted but the balance did not change (no debit for a completed transfer)"
		default:
			return false, "debit " + ftoa(delta) + " does not match the transaction amount " + ftoa(expected)
		}
	case txnRejected, txnDenied:
		if math.Abs(delta) < balanceEpsilon {
			return true, ""
		}
		return false, "a rejected/failed transaction changed the balance by " + ftoa(delta)
	default:
		return true, "" // error/inconclusive: do not flag
	}
}

func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func (t *ToolSet) mobileBalanceCheck() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":        strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"balance_index":  intField("history index of a GET balance request (its response carries the account balance)"),
			"transfer_index": intField("history index of the transaction request to perform between the two balance reads"),
			"balance_field":  strField("JSON field in the balance response holding the numeric balance (e.g. balance, availableBalance)"),
			"amount":         map[string]any{"type": "number", "description": "the transaction amount expected to be debited"},
		},
		"required":             []any{"balance_index", "transfer_index", "balance_field", "amount"},
		"additionalProperties": false,
	}
	return writeTool("mobile_balance_check",
		"Financial state-consistency tester. Reads the account balance, performs a captured transaction, then reads the balance again, and checks: an ACCEPTED transfer must debit exactly the transaction amount (debit-matches); a REJECTED transfer must leave the balance unchanged (failed-txn-no-effect). Confirms ledger integrity out-of-band, which status codes cannot show. SANDBOX ONLY: authorized test accounts and simulated funds.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL        string  `json:"mcp_url"`
				BalanceIndex  *int    `json:"balance_index"`
				TransferIndex *int    `json:"transfer_index"`
				BalanceField  string  `json:"balance_field"`
				Amount        float64 `json:"amount"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if a.BalanceIndex == nil || a.TransferIndex == nil || strings.TrimSpace(a.BalanceField) == "" {
				return actool.Errorf("balance_index, transfer_index and balance_field are required"), nil
			}
			if a.MCPURL == "" {
				a.MCPURL = devicelab.BurpMCPURL()
			}
			c, err := devicelab.DialBurpMCP(ctx, a.MCPURL)
			if err != nil {
				return errf("connect Burp MCP: %v", err), nil
			}
			defer c.Close()
			get := func(idx int) (devicelab.Exchange, error) {
				ex, e := c.ProxyHistory(ctx, idx, 1)
				if e != nil {
					return devicelab.Exchange{}, e
				}
				if len(ex) == 0 {
					return devicelab.Exchange{}, errfNative(idx)
				}
				return ex[0], nil
			}
			balReq, e1 := get(*a.BalanceIndex)
			txReq, e2 := get(*a.TransferIndex)
			if e1 != nil || e2 != nil {
				return actool.Errorf("could not read the balance/transfer exchanges from history"), nil
			}
			send := func(ex devicelab.Exchange) (string, error) {
				port := 443
				if !ex.TLS {
					port = 80
				}
				return c.SendRequest(ctx, ex.Host, port, ex.TLS, ex.Request)
			}
			readBalance := func() (float64, bool) {
				resp, e := send(balReq)
				if e != nil {
					return 0, false
				}
				return jsonNumber(httpBody(resp), a.BalanceField)
			}

			before, ok1 := readBalance()
			txResp, e := send(txReq)
			if e != nil {
				return errf("perform transaction: %v", e), nil
			}
			recordCoverage(t.taskID, coverageKey(txReq), "balance")
			outcome := classifyTxn(httpStatus(txResp), httpBody(txResp))
			after, ok2 := readBalance()
			if !ok1 || !ok2 {
				return errf("could not read numeric balance field %q from the balance response", a.BalanceField), nil
			}
			ok, issue := balanceVerdict(outcome, before, after, a.Amount)
			result := map[string]any{
				"balance_before": before,
				"balance_after":  after,
				"amount":         a.Amount,
				"txn_outcome":    outcome,
				"consistent":     ok,
				"issue":          issue,
			}
			if !ok {
				fb := &findingBlock{
					VulnClass:        "Business Logic — balance/ledger inconsistency",
					Name:             "Balance invariant violated on " + txReq.Method + " " + txReq.Path,
					Severity:         "critical",
					Summary:          "The account balance did not change consistently with the transaction outcome.",
					AffectedEndpoint: txReq.Host + txReq.Path,
					Method:           txReq.Method,
					Preconditions:    "A balance-read endpoint and a transaction endpoint on an authorized sandbox account.",
					Reproduction: []string{
						"Read the balance (" + ftoa(before) + ").",
						"Perform " + txReq.Method + " " + txReq.Path + " for amount " + ftoa(a.Amount) + " (outcome: " + string(outcome) + ").",
						"Read the balance again (" + ftoa(after) + ").",
						issue,
					},
					Expected:           "An accepted transfer debits exactly the amount; a rejected transfer leaves the balance unchanged.",
					Actual:             issue,
					Impact:             "Financial integrity failure — value created or destroyed, double-spend, or failed transactions with real effect.",
					Remediation:        "Make transactions atomic and reconcile the ledger server-side: debit exactly the authorized amount within one transaction, and roll back fully on failure.",
					VerificationStatus: "confirmed",
				}
				if id, ok := t.fileFinding(ctx, fb, t.endpointAssetID("https://"+txReq.Host+txReq.Path, txReq.Method)); ok {
					fb.FiledFindingID = id
				}
				result["finding"] = fb
			}
			out, _ := json.Marshal(result)
			return actool.Text(string(out)), nil
		})
}

// errfNative builds a plain error for the no-exchange case.
func errfNative(idx int) error {
	return &simpleErr{"no captured exchange at history_index " + itoa(idx)}
}

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }
