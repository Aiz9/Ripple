package agent

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Financial business-logic verification.
//
// Generic fuzzing cannot tell a declined request from an accepted one, so it
// cannot test a financial invariant. This module models the invariants explicitly
// (amount sign/limit, allowed currencies, idempotency) and decides each experiment
// deterministically from the server's own response: a tampered request that the
// server ACCEPTS in violation of a configured invariant is the finding; a decline
// (4xx, or a 2xx body that reports rejection) is correct behavior and is not
// flagged. Experiments must run against an authorized sandbox with simulated funds.

// FinancialInvariants is the per-target, configurable rule set. All fields are
// optional; an unset rule disables its experiment, because business rules differ
// between applications and must not be assumed universal.
type FinancialInvariants struct {
	AmountField       string   `json:"amount_field"`       // JSON body field holding the transaction amount
	MaxAmount         float64  `json:"max_amount"`         // server-side per-transaction limit (0 = no limit configured)
	CurrencyField     string   `json:"currency_field"`     // JSON body field holding the currency code
	AllowedCurrencies []string `json:"allowed_currencies"` // currencies the account may transact in
	IdempotencyField  string   `json:"idempotency_field"`  // body field that should make a repeat a no-op (nonce/idempotency key)
}

// txnOutcome classifies a server response to a transaction attempt.
type txnOutcome string

const (
	txnAccepted txnOutcome = "accepted"
	txnRejected txnOutcome = "rejected"
	txnDenied   txnOutcome = "denied" // authN/authZ failure, distinct from business rejection
	txnError    txnOutcome = "error"
)

var rejectionMarkers = []string{"error", "declined", "invalid", "insufficient", "not allowed",
	"not permitted", "failed", "rejected", "denied", "limit exceeded", "forbidden"}

// classifyTxn decides whether the server accepted or rejected a transaction, from
// status and body together — a 2xx that reports a rejection in its body is a
// rejection, so a tamper that is cleanly declined is never mis-flagged as accepted.
func classifyTxn(status int, body string) txnOutcome {
	switch {
	case status == 401 || status == 403:
		return txnDenied
	case status >= 400 && status < 500:
		return txnRejected
	case status >= 200 && status < 300:
		lb := strings.ToLower(body)
		for _, m := range rejectionMarkers {
			if strings.Contains(lb, m) {
				return txnRejected
			}
		}
		return txnAccepted
	default:
		return txnError
	}
}

var duplicateSuppressedMarkers = []string{"duplicate", "already processed", "already_processed",
	"alreadyprocessed", "idempoten", "no-op", "noop", "ignored", "already exists"}

// indicatesDuplicateSuppressed reports whether a 2xx body signals that a repeat
// request had no new effect (correct idempotency), so a second "accepted" response
// is not evidence of duplicate processing.
func indicatesDuplicateSuppressed(body string) bool {
	lb := strings.ToLower(body)
	for _, m := range duplicateSuppressedMarkers {
		if strings.Contains(lb, m) {
			return true
		}
	}
	return false
}

// jsonNumber reads a numeric top-level field from a JSON object body.
func jsonNumber(body, field string) (float64, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &m) != nil {
		return 0, false
	}
	raw, ok := m[field]
	if !ok {
		return 0, false
	}
	// Accept both 100 and "100".
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// setJSONField replaces a top-level field's value in a JSON object body, preserving
// the surrounding request envelope. value is emitted as raw JSON (numbers unquoted,
// strings must arrive already quoted). Returns false if the body is not a JSON
// object or the field is absent.
func setJSONField(body, field, rawValue string) (string, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &m) != nil {
		return "", false
	}
	if _, ok := m[field]; !ok {
		return "", false
	}
	m[field] = json.RawMessage(rawValue)
	out, err := json.Marshal(m)
	if err != nil {
		return "", false
	}
	return string(out), true
}

// setRequestBody replaces a raw HTTP request's body and fixes its Content-Length
// header (case-insensitive; added if absent) so the tampered request is well-formed.
func setRequestBody(raw, newBody string) string {
	head := raw
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head = raw[:i]
	} else if i := strings.Index(raw, "\n\n"); i >= 0 {
		head = raw[:i]
	}
	lines := strings.Split(head, "\n")
	kept := make([]string, 0, len(lines))
	hasCL := false
	for _, ln := range lines {
		l := strings.TrimRight(ln, "\r")
		if name, _, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "content-length") {
			kept = append(kept, "Content-Length: "+strconv.Itoa(len(newBody)))
			hasCL = true
			continue
		}
		kept = append(kept, l)
	}
	if !hasCL {
		kept = append(kept, "Content-Length: "+strconv.Itoa(len(newBody)))
	}
	return strings.Join(kept, "\r\n") + "\r\n\r\n" + newBody
}

// amountViolation names the invariant a tampered amount would break if accepted.
func amountViolation(amount float64, inv FinancialInvariants) string {
	switch {
	case amount < 0:
		return "negative amount accepted (a debit/transfer must not be negative)"
	case amount == 0:
		return "zero amount accepted"
	case inv.MaxAmount > 0 && amount > inv.MaxAmount:
		return "amount exceeds the server-side per-transaction limit " + strconv.FormatFloat(inv.MaxAmount, 'f', -1, 64) + " yet was accepted"
	default:
		return ""
	}
}

// currencyAllowed reports whether cur is in the configured allow-list (case-insensitive).
// An empty allow-list means the currency invariant is not configured.
func currencyAllowed(cur string, inv FinancialInvariants) bool {
	if len(inv.AllowedCurrencies) == 0 {
		return true
	}
	for _, c := range inv.AllowedCurrencies {
		if strings.EqualFold(c, cur) {
			return true
		}
	}
	return false
}
