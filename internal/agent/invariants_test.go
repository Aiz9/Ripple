package agent

import "testing"

func TestClassifyTxn(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   txnOutcome
	}{
		{200, `{"status":"completed","id":"t1"}`, txnAccepted},
		{200, `{"status":"declined","reason":"insufficient funds"}`, txnRejected}, // 2xx body reports rejection
		{201, `{"ok":true}`, txnAccepted},
		{400, `{"error":"bad amount"}`, txnRejected},
		{403, ``, txnDenied},
		{500, ``, txnError},
	}
	for _, c := range cases {
		if got := classifyTxn(c.status, c.body); got != c.want {
			t.Errorf("classifyTxn(%d,%q) = %q, want %q", c.status, c.body, got, c.want)
		}
	}
}

func TestSetJSONFieldAndNumber(t *testing.T) {
	body := `{"to":"B","amount":100,"currency":"USD"}`
	out, ok := setJSONField(body, "amount", "-1")
	if !ok {
		t.Fatal("setJSONField failed")
	}
	if n, ok := jsonNumber(out, "amount"); !ok || n != -1 {
		t.Fatalf("amount = %v,%v want -1", n, ok)
	}
	if _, ok := setJSONField(body, "missing", "1"); ok {
		t.Error("setJSONField should fail on absent field")
	}
	// string-encoded number
	if n, ok := jsonNumber(`{"amount":"250"}`, "amount"); !ok || n != 250 {
		t.Fatalf("string number = %v,%v", n, ok)
	}
}

func TestSetRequestBodyFixesContentLength(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Type: application/json\r\n\r\n{}"
	out := setRequestBody(raw, `{"amount":-1}`)
	if !contains(out, "Content-Length: 13") {
		t.Fatalf("content-length not fixed: %q", out)
	}
	if httpBody(out) != `{"amount":-1}` {
		t.Fatalf("body not replaced: %q", httpBody(out))
	}
}

func TestAmountViolation(t *testing.T) {
	inv := FinancialInvariants{MaxAmount: 1000}
	if amountViolation(-1, inv) == "" {
		t.Error("negative should violate")
	}
	if amountViolation(0, inv) == "" {
		t.Error("zero should violate")
	}
	if amountViolation(1001, inv) == "" {
		t.Error("over-limit should violate")
	}
	if amountViolation(500, inv) != "" {
		t.Error("in-range must not violate")
	}
	if amountViolation(1001, FinancialInvariants{}) != "" {
		t.Error("no configured limit -> over-limit not a violation")
	}
}

func TestCurrencyAllowed(t *testing.T) {
	inv := FinancialInvariants{AllowedCurrencies: []string{"USD", "EUR"}}
	if !currencyAllowed("usd", inv) {
		t.Error("usd should be allowed (case-insensitive)")
	}
	if currencyAllowed("XTS", inv) {
		t.Error("XTS should be disallowed")
	}
	if !currencyAllowed("anything", FinancialInvariants{}) {
		t.Error("empty allow-list disables the invariant")
	}
	if got := disallowedCurrency(inv); got != "XTS" {
		t.Errorf("disallowedCurrency = %q want XTS", got)
	}
}
