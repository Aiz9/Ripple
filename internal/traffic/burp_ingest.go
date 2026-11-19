package traffic

import (
	"strconv"
	"strings"
)

// Burp MCP ingest. Exchanges are captured by
// Burp (the single proxy) and pulled in through its MCP server; this parses Burp's
// raw request/response strings into the neutral exchange and records them into the
// same store the UI, traffic_search and finding-evidence all read.

// Ingest records one externally-captured exchange (raw HTTP/1.1 request and
// response text, as Burp returns them). It is a no-op if the request is unparseable.
func (t *Traffic) Ingest(host, method, rawRequest, rawResponse string, tls bool) {
	if ex, ok := parseExchange(host, method, rawRequest, rawResponse, tls); ok {
		t.record(ex)
	}
}

// splitHead splits a raw HTTP message into its header block (first line + headers,
// without the trailing blank line) and body.
func splitHead(raw string) (head, body string) {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	return raw, ""
}

// headerBlock returns the header lines of a head (everything after the first line).
func headerBlock(head string) string {
	if i := strings.IndexAny(head, "\r\n"); i >= 0 {
		return strings.TrimLeft(head[i:], "\r\n")
	}
	return ""
}

// rawHeader reads one header value from a header block (case-insensitive).
func rawHeader(head, name string) string {
	for _, ln := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(ln, "\r"), ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseExchange builds a neutral exchange from Burp's raw request/response text.
func parseExchange(host, method, rawRequest, rawResponse string, tls bool) (exchange, bool) {
	reqHead, reqBody := splitHead(rawRequest)
	nl := strings.IndexAny(reqHead, "\r\n")
	reqLine := reqHead
	if nl >= 0 {
		reqLine = reqHead[:nl]
	}
	parts := strings.Fields(reqLine)
	if len(parts) < 2 {
		return exchange{}, false
	}
	if method == "" {
		method = parts[0]
	}
	reqURI := parts[1]
	proto := "HTTP/1.1"
	if len(parts) >= 3 {
		proto = parts[2]
	}
	reqHeaders := headerBlock(reqHead)
	if host == "" {
		host = rawHeader(reqHeaders, "Host")
	}
	// reqURI may be absolute-form (proxy) — keep only the path+query for the template.
	path := reqURI
	if i := strings.Index(path, "://"); i >= 0 {
		if j := strings.IndexByte(path[i+3:], '/'); j >= 0 {
			path = path[i+3+j:]
		} else {
			path = "/"
		}
	}
	escapedPath := path
	if i := strings.IndexByte(escapedPath, '?'); i >= 0 {
		escapedPath = escapedPath[:i]
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	url := scheme + "://" + host + path
	if host == "" {
		return exchange{}, false
	}

	respHead, respBody := splitHead(rawResponse)
	status := 0
	if f := strings.Fields(respHead); len(f) >= 2 {
		status, _ = strconv.Atoi(f[1])
	}
	respHeaders := headerBlock(respHead)

	return exchange{
		host: host, method: method, url: url, reqURI: reqURI, proto: proto,
		escapedPath: escapedPath, contentType: rawHeader(respHeaders, "Content-Type"),
		status:         status,
		reqHeaderLines: reqHeaders, respHeaderLines: respHeaders,
		reqContentType: rawHeader(reqHeaders, "Content-Type"),
		reqBody:        []byte(reqBody), respBody: []byte(respBody),
	}, true
}
