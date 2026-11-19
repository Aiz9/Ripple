package agent

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/Aiz9/ripple/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Excessive data exposure (OWASP API3): sensitive data returned in API responses
// that a client should never receive. Deterministic — flags response fields whose
// KEY names a secret/PII attribute (with a non-empty value) or whose VALUE matches
// a sensitive pattern (card number, SSN, JWT, private key).

// secretKeyRe matches field names a server must NEVER return to any client,
// regardless of whose data it is: a response echoing a password or CVV is always a
// flaw. These produce a confirmed finding on presence alone.
var secretKeyRe = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|private[_-]?key|cvv|cvc|otp[_-]?secret|security[_-]?answer|mother[_-]?maiden|\bpin\b)`)

// piiKeyRe matches field names that are sensitive but may legitimately be the
// authenticated caller's OWN data (their saved card, their SSN). Presence alone
// does not prove excessive exposure — it must be confirmed cross-identity — so these
// are reported for verification, never auto-confirmed.
var piiKeyRe = regexp.MustCompile(`(?i)(card[_-]?number|cardnumber|full[_-]?pan|ssn|social[_-]?security|tax[_-]?id|passport|routing[_-]?number|iban)`)

var (
	panRe     = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	ssnRe     = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	jwtRe     = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`)
	privKeyRe = regexp.MustCompile(`BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY`)
)

// sensitiveValue classifies a string value, returning the sensitive data type (or
// "") and whether its mere presence confirms a leak. A private key is never
// legitimately in a response; a JWT/SSN/card may be the caller's own data, so those
// are reported for cross-identity verification rather than confirmed.
func sensitiveValue(v string) (kind string, confirmed bool) {
	switch {
	case privKeyRe.MatchString(v):
		return "private key", true
	case jwtRe.MatchString(v):
		return "JWT", false
	case ssnRe.MatchString(v):
		return "SSN", false
	case panRe.MatchString(stripSep(v)) && luhnValid(stripSep(v)):
		return "card number (PAN)", false
	}
	return "", false
}

func stripSep(s string) string {
	return strings.NewReplacer(" ", "", "-", "").Replace(s)
}

// luhnValid checks a candidate PAN with the Luhn checksum to cut false positives.
func luhnValid(s string) bool {
	if len(s) < 13 || len(s) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// sensitiveFieldsInJSON walks a JSON body and splits hits into two buckets:
// confirmed (secrets/keys a server must never return to any client) and unverified
// (values that may legitimately be the authenticated caller's own data, so they
// prove a leak only when a different identity also receives them).
func sensitiveFieldsInJSON(body string) (confirmed, unverified []string) {
	var v any
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &v) != nil {
		return nil, nil
	}
	cseen, useen := map[string]bool{}, map[string]bool{}
	addC := func(s string) {
		if !cseen[s] {
			cseen[s] = true
			confirmed = append(confirmed, s)
		}
	}
	addU := func(s string) {
		if !useen[s] {
			useen[s] = true
			unverified = append(unverified, s)
		}
	}
	var walk func(key string, val any)
	walk = func(key string, val any) {
		switch t := val.(type) {
		case map[string]any:
			for k, vv := range t {
				if !isEmptyValue(vv) {
					switch {
					case secretKeyRe.MatchString(k):
						addC("secret field '" + k + "' present in response")
					case piiKeyRe.MatchString(k):
						addU("PII field '" + k + "' present in response")
					}
				}
				walk(k, vv)
			}
		case []any:
			for _, vv := range t {
				walk(key, vv)
			}
		case string:
			if kind, ok := sensitiveValue(t); kind != "" {
				if ok {
					addC(kind + " value exposed" + keySuffix(key))
				} else {
					addU(kind + " value exposed" + keySuffix(key))
				}
			}
		}
	}
	walk("", v)
	sort.Strings(confirmed)
	sort.Strings(unverified)
	return confirmed, unverified
}

func keySuffix(key string) string {
	if key == "" {
		return ""
	}
	return " (field '" + key + "')"
}

func isEmptyValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case bool:
		return false
	}
	return false
}

func (t *ToolSet) mobileDataExposure() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":       strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index": intField("history index of a captured exchange whose RESPONSE body to scan for sensitive data"),
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return readTool("mobile_data_exposure",
		"Excessive data exposure scan (OWASP API3). Scans a captured response body for sensitive data a client should not receive: secret/PII field names (password, secret, cvv, ssn, card_number, private_key, pin…) with non-empty values, and values matching sensitive patterns (Luhn-valid card number, SSN, JWT, private key). Deterministic; review hits for whether the exposure is intended.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL       string `json:"mcp_url"`
				HistoryIndex *int   `json:"history_index"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if a.HistoryIndex == nil || *a.HistoryIndex < 0 {
				return actool.Errorf("history_index (>= 0) is required"), nil
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
			recordCoverage(t.taskID, coverageKey(req), "data-exposure")
			confirmed, unverified := sensitiveFieldsInJSON(httpBody(req.Response))
			result := map[string]any{
				"endpoint":   req.Method + " " + req.Host + req.Path,
				"exposed":    confirmed,
				"unverified": unverified,
				"note":       "exposed = data a server must never return to any client (secrets/keys/CVV/PIN) — auto-filed as confirmed. unverified = values that may legitimately belong to the authenticated caller (their own token, card, SSN) — NOT filed; re-request with a DIFFERENT identity's token and confirm the data still returns (cross-user leakage) before treating it as a finding.",
			}
			// Only secrets no client should ever receive are confirmed on presence. A
			// JWT/card/SSN returned to its owner is normal, so those stay in 'unverified'
			// and are never auto-filed — unverified AI conclusions must not become
			// confirmed findings.
			if len(confirmed) > 0 {
				fb := &findingBlock{
					VulnClass:          "Excessive Data Exposure (sensitive data in API response)",
					Name:               "Sensitive data in response of " + req.Method + " " + req.Path,
					Severity:           "high",
					Summary:            "The API response contains secret fields/values that no client should ever receive.",
					AffectedEndpoint:   req.Host + req.Path,
					Method:             req.Method,
					Preconditions:      "A captured response from the endpoint.",
					Reproduction:       append([]string{"Call " + req.Method + " " + req.Path + " and inspect the response body:"}, confirmed...),
					Expected:           "The response returns only the fields the client needs; secrets, keys and CVV/PIN are never serialized into a response.",
					Actual:             "Exposed: " + strings.Join(confirmed, "; "),
					Impact:             "Leakage of credentials/secrets to the client (and anyone who can read the traffic), enabling account/payment compromise.",
					Remediation:        "Return only required fields (explicit response DTOs/allow-list); never serialize secrets, keys or card verification data.",
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
