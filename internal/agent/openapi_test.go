package agent

import "testing"

func epByKey(eps []specEndpoint, method, path string) *specEndpoint {
	for i := range eps {
		if eps[i].Method == method && eps[i].Path == path {
			return &eps[i]
		}
	}
	return nil
}

func hasParam(e *specEndpoint, loc, name string) bool {
	for _, p := range e.Params {
		if p["location"] == loc && p["name"] == name {
			return true
		}
	}
	return false
}

func TestNormalizeSpecPath(t *testing.T) {
	if got := normalizeSpecPath("/accounts/{accountId}/beneficiaries/{beneficiaryId}"); got != "/accounts/{id}/beneficiaries/{id}" {
		t.Fatalf("got %q", got)
	}
}

func TestParseOpenAPIv3(t *testing.T) {
	spec := `{
      "openapi":"3.0.0",
      "servers":[{"url":"https://api.bank.test/v1"}],
      "security":[{"bearer":[]}],
      "paths":{
        "/accounts/{accountId}":{
          "get":{"operationId":"getAccount","parameters":[{"name":"accountId","in":"path"},{"name":"expand","in":"query"}]}
        },
        "/transfers":{
          "post":{
            "security":[],
            "requestBody":{"content":{"application/json":{"schema":{"properties":{"amount":{},"to":{}}}}}}
          }
        }
      }
    }`
	eps, err := parseOpenAPI([]byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	ga := epByKey(eps, "GET", "/v1/accounts/{id}")
	if ga == nil {
		t.Fatalf("missing GET /v1/accounts/{id}; got %+v", eps)
	}
	if !ga.AuthRequired {
		t.Error("GET account should inherit global security (auth required)")
	}
	if !hasParam(ga, "query", "expand") || !hasParam(ga, "path", "accountId") {
		t.Errorf("account params wrong: %+v", ga.Params)
	}
	tp := epByKey(eps, "POST", "/v1/transfers")
	if tp == nil {
		t.Fatal("missing POST /v1/transfers")
	}
	if tp.AuthRequired {
		t.Error("transfers has empty operation security -> auth NOT required (override)")
	}
	if !hasParam(tp, "body", "amount") || !hasParam(tp, "body", "to") {
		t.Errorf("body params wrong: %+v", tp.Params)
	}
}

func TestParseSwaggerV2(t *testing.T) {
	spec := `{
      "swagger":"2.0",
      "basePath":"/api",
      "paths":{
        "/users/{userId}":{
          "get":{"parameters":[{"name":"userId","in":"path"}]}
        },
        "/login":{
          "post":{"parameters":[{"name":"body","in":"body","schema":{"properties":{"username":{},"password":{}}}}]}
        }
      }
    }`
	eps, err := parseOpenAPI([]byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	if epByKey(eps, "GET", "/api/users/{id}") == nil {
		t.Fatalf("missing GET /api/users/{id}; got %+v", eps)
	}
	lp := epByKey(eps, "POST", "/api/login")
	if lp == nil || !hasParam(lp, "body", "username") || !hasParam(lp, "body", "password") {
		t.Fatalf("login body params wrong: %+v", lp)
	}
}
