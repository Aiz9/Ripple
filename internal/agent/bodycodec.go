package agent

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Content-type-aware request-body handling. The mutation tools (txn/schema/mass/
// inject) originally assumed a JSON object body; real apps also use
// application/x-www-form-urlencoded. This codec abstracts "list fields / set field
// / add field" over JSON and form bodies so one tool works on both. Multipart is
// detected but not mutated (reported so the tool degrades loudly, not silently).

// bodyFormat classifies a request body: "json", "form", "multipart", or "none".
func bodyFormat(rawRequest string) string {
	ct := strings.ToLower(headerValue(rawRequest, "content-type"))
	switch {
	case strings.Contains(ct, "application/json"), strings.Contains(ct, "+json"):
		return "json"
	case strings.Contains(ct, "x-www-form-urlencoded"):
		return "form"
	case strings.Contains(ct, "multipart/form-data"):
		return "multipart"
	}
	b := strings.TrimSpace(httpBody(rawRequest))
	switch {
	case b == "":
		return "none"
	case strings.HasPrefix(b, "{"):
		return "json"
	case !strings.ContainsAny(b, "{[") && strings.Contains(b, "="):
		return "form"
	}
	return "none"
}

// headerValue returns a request header's value (case-insensitive), or "".
func headerValue(rawRequest, name string) string {
	head := rawRequest
	if i := strings.Index(rawRequest, "\r\n\r\n"); i >= 0 {
		head = rawRequest[:i]
	} else if i := strings.Index(rawRequest, "\n\n"); i >= 0 {
		head = rawRequest[:i]
	}
	for _, ln := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(ln, "\r"), ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// bodyFieldTypes returns the mutable body fields and their inferred types, for any
// supported format. Form values are typed by their text (digits -> integer, etc.).
func bodyFieldTypes(rawRequest string) (format string, fields map[string]string) {
	format = bodyFormat(rawRequest)
	fields = map[string]string{}
	body := httpBody(rawRequest)
	switch format {
	case "json":
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(strings.TrimSpace(body)), &m) == nil {
			for k, v := range m {
				fields[k] = inferJSONType(string(v))
			}
		}
	case "form":
		if vals, err := url.ParseQuery(strings.TrimSpace(body)); err == nil {
			for k, vs := range vals {
				if len(vs) > 0 {
					fields[k] = inferStringType(vs[0])
				} else {
					fields[k] = "string"
				}
			}
		}
	}
	return format, fields
}

// bodyStringFields returns only the string-valued body fields (injection targets).
func bodyStringFields(rawRequest string) []string {
	format, fields := bodyFieldTypes(rawRequest)
	var out []string
	for name, typ := range fields {
		if format == "form" || typ == "string" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// jsonRawToText converts a raw JSON value to its plain text form for a form body
// ("admin" -> admin, 123 -> 123, true -> true).
func jsonRawToText(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && raw[0] == '"' {
		var s string
		if json.Unmarshal([]byte(raw), &s) == nil {
			return s
		}
	}
	return raw
}

// setBodyFieldRaw sets an existing field to a raw JSON value, honoring the format,
// and rewrites the request (Content-Length fixed). ok is false if the field is
// absent or the format is unsupported.
func setBodyFieldRaw(rawRequest, field, rawValue string) (string, bool) {
	switch bodyFormat(rawRequest) {
	case "json":
		nb, ok := setJSONField(httpBody(rawRequest), field, rawValue)
		if !ok {
			return "", false
		}
		return setRequestBody(rawRequest, nb), true
	case "form":
		return setFormField(rawRequest, field, jsonRawToText(rawValue), false)
	}
	return "", false
}

// addBodyFieldRaw adds (or overrides) a field with a raw JSON value (mass assignment).
func addBodyFieldRaw(rawRequest, field, rawValue string) (string, bool) {
	switch bodyFormat(rawRequest) {
	case "json":
		nb, ok := addOrSetJSONField(httpBody(rawRequest), field, rawValue)
		if !ok {
			return "", false
		}
		return setRequestBody(rawRequest, nb), true
	case "form":
		return setFormField(rawRequest, field, jsonRawToText(rawValue), true)
	}
	return "", false
}

// setBodyFieldString sets a field to a plain string value (injection payloads).
func setBodyFieldString(rawRequest, field, value string) (string, bool) {
	switch bodyFormat(rawRequest) {
	case "json":
		nb, ok := setJSONField(httpBody(rawRequest), field, strconv.Quote(value))
		if !ok {
			return "", false
		}
		return setRequestBody(rawRequest, nb), true
	case "form":
		return setFormField(rawRequest, field, value, false)
	}
	return "", false
}

// setFormField rewrites one field in a urlencoded body. add=true inserts an absent
// field; add=false requires it to exist.
func setFormField(rawRequest, field, value string, add bool) (string, bool) {
	vals, err := url.ParseQuery(strings.TrimSpace(httpBody(rawRequest)))
	if err != nil {
		return "", false
	}
	if _, ok := vals[field]; !ok && !add {
		return "", false
	}
	vals.Set(field, value)
	// Encode in a stable order for reproducibility.
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(vals.Get(k)))
	}
	return setRequestBody(rawRequest, strings.Join(parts, "&")), true
}

// removeBodyField deletes a field from a JSON or form body.
func removeBodyField(rawRequest, field string) (string, bool) {
	switch bodyFormat(rawRequest) {
	case "json":
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(strings.TrimSpace(httpBody(rawRequest))), &m) != nil {
			return "", false
		}
		if _, ok := m[field]; !ok {
			return "", false
		}
		delete(m, field)
		b, err := json.Marshal(m)
		if err != nil {
			return "", false
		}
		return setRequestBody(rawRequest, string(b)), true
	case "form":
		vals, err := url.ParseQuery(strings.TrimSpace(httpBody(rawRequest)))
		if err != nil {
			return "", false
		}
		if _, ok := vals[field]; !ok {
			return "", false
		}
		vals.Del(field)
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(vals.Get(k)))
		}
		return setRequestBody(rawRequest, strings.Join(parts, "&")), true
	}
	return "", false
}

// hasMutableBody reports whether the request has a JSON or form body we can tamper.
func hasMutableBody(rawRequest string) bool {
	f := bodyFormat(rawRequest)
	return f == "json" || f == "form"
}
