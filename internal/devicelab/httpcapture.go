package devicelab

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// RuntimeEndpoint is one HTTP endpoint observed at runtime by Frida
// instrumentation of the app's HTTP clients — the API surface the app actually
// calls, captured at the client call site (before TLS). It therefore surfaces
// endpoints that never traverse the intercepting proxy and ones constructed
// dynamically at runtime, which static URL extraction and proxy history miss.
type RuntimeEndpoint struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Lib    string `json:"lib,omitempty"`
}

// GenerateRuntimeCaptureScript builds a Frida script that (1) installs the given
// client-protection bypasses and (2) hooks the common Android HTTP clients to log
// every request as an ANDROIDLAB_EVENT {kind:"http_request"}. Hooking at the
// client layer captures the real runtime API surface regardless of SSL pinning or
// whether the request reaches a proxy. It reuses the bypass generator's emit()
// helper and emits hooks_ready so FridaSpawn can confirm initialization.
func GenerateRuntimeCaptureScript(bypasses []Bypass) string {
	return GenerateFridaBypassScript(bypasses) + httpCaptureJS
}

// httpCaptureJS hooks OkHttp (also Retrofit's transport) and java.net.URL →
// HttpURLConnection, emitting one http_request event per call. Each hook is
// independent and defensive so a missing class never aborts the others. groups
// counts installed hooks; FridaSpawn treats groups==0 as "no visibility" (a
// native/Flutter app with no JVM HTTP client), which the caller reports as a
// limitation rather than an infrastructure failure.
const httpCaptureJS = `
if (typeof Java !== 'undefined' && Java.available) { Java.perform(function () {
  var groups = 0;
  // OkHttp 3/4 (Retrofit rides on this): read the Request handed to newCall.
  try {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    OkHttpClient.newCall.implementation = function (req) {
      try { emit({kind:'http_request', lib:'okhttp', method:'' + req.method(), url:'' + req.url().toString()}); } catch (e) {}
      return this.newCall(req);
    };
    groups++;
  } catch (e) {}
  // java.net.URL.openConnection() → HttpURLConnection / HttpsURLConnection.
  try {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function () {
      try { emit({kind:'http_request', lib:'urlconnection', method:'?', url:'' + this.toString()}); } catch (e) {}
      return this.openConnection();
    };
    groups++;
  } catch (e) {}
  emit({kind:'hooks_ready', groups: groups});
}); } else {
  emit({kind:'hooks_ready', groups: 0});
  emit({kind:'limitation', detail:'no JVM HTTP client to hook (native/Flutter engine); rely on proxy capture and the native TLS bypass'});
}
`

// RuntimeEndpointsFromEvents extracts and de-duplicates HTTP endpoints from
// http_request instrumentation events. Query values are dropped (keys kept) to
// match the static URL inventory and to avoid storing credential values.
func RuntimeEndpointsFromEvents(events []FridaEvent) []RuntimeEndpoint {
	seen := map[string]bool{}
	out := []RuntimeEndpoint{}
	for _, e := range events {
		if e["kind"] != "http_request" {
			continue
		}
		raw, _ := e["url"].(string)
		method, _ := e["method"].(string)
		lib, _ := e["lib"].(string)
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			continue
		}
		q := u.Query()
		for k := range q {
			q.Set(k, "")
		}
		u.RawQuery = q.Encode()
		u.Fragment = ""
		if strings.TrimSpace(method) == "" {
			method = "?"
		}
		key := method + " " + u.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, RuntimeEndpoint{Method: method, URL: u.String(), Host: u.Host, Path: u.Path, Lib: lib})
	}
	return out
}

// DiscoverRuntimeAPIs spawns the approved package under Frida with HTTP-client
// instrumentation and returns the runtime API endpoints observed in the window.
// It ensures a frida-server is running (reusing a preexisting one) and requires
// root. A native/Flutter app installs no JVM hooks; that is a visibility
// limitation (reported via the returned events), not an error, so long as the
// script ran. serverPath (optional) is pushed only if no server is running.
func (d *Device) DiscoverRuntimeAPIs(ctx context.Context, bypasses []Bypass, seconds int, serverPath, stateDir string) ([]RuntimeEndpoint, []FridaEvent, error) {
	if !d.HasRoot() {
		d.DetectRoot(ctx)
	}
	if _, err := d.startFridaServer(ctx, serverPath, stateDir); err != nil {
		return nil, nil, fmt.Errorf("frida-server unavailable: %w", err)
	}
	events, _, err := d.FridaSpawn(ctx, GenerateRuntimeCaptureScript(bypasses), seconds, nil)
	eps := RuntimeEndpointsFromEvents(events)
	if err != nil {
		// A groups==0 run (no JVM HTTP client) makes FridaSpawn report "not
		// initialized"; treat that as a limitation, not a failure, when the
		// script demonstrably ran (a hooks_ready event was emitted).
		for _, e := range events {
			if e["kind"] == "hooks_ready" {
				return eps, events, nil
			}
		}
		return eps, events, err
	}
	return eps, events, nil
}
