package androidapk

import (
	"archive/zip"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

type URLObservation struct {
	URL   string `json:"url"`
	File  string `json:"file"`
	Owner string `json:"owner,omitempty"`
	// Kind is "" (or "url") for a full http(s):// URL, or "path" for a host-less
	// endpoint path template (e.g. a Retrofit @GET path). Path templates combine
	// with the base URL resolved at RUNTIME (observed in proxy traffic), which the
	// static base URL often is not.
	Kind string `json:"kind,omitempty"`
}

var literalURL = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%{}-]{4,1000}`)

// DiscoverURLs reads bounded string-bearing entries in place. It never extracts
// archives, executes APK code, follows discovered URLs, or infers HTTP methods.
func DiscoverURLs(apkPath string) ([]URLObservation, []string, error) {
	return DiscoverApplicationURLs(apkPath, "")
}

func DiscoverApplicationURLs(apkPath, pkg string) ([]URLObservation, []string, error) {
	file, err := os.Open(apkPath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if err = preflightAPK(file, stat.Size()); err != nil {
		return nil, nil, err
	}
	z, err := zip.NewReader(file, stat.Size())
	if err != nil {
		return nil, nil, err
	}
	if len(z.File) > 100000 {
		return nil, nil, fmt.Errorf("APK entry limit exceeded")
	}
	out := []URLObservation{}
	warnings := []string{}
	seen := map[string]bool{}
	remaining := int64(64 << 20)
	for _, entry := range z.File {
		name := strings.ToLower(entry.Name)
		eligible := false
		for _, ext := range []string{".dex", ".xml", ".json", ".js", ".bundle", ".so", ".properties", ".txt", ".html", ".arsc"} {
			if strings.HasSuffix(name, ext) {
				eligible = true
			}
		}
		if !eligible {
			continue
		}
		if remaining <= 0 {
			warnings = append(warnings, "APK URL discovery stopped at the 64 MiB read budget.")
			break
		}
		limit := int64(8 << 20)
		if remaining < limit {
			limit = remaining
		}
		reader, err := entry.Open()
		if err != nil {
			return nil, nil, err
		}
		data, err := io.ReadAll(io.LimitReader(reader, limit))
		closeErr := reader.Close()
		if err != nil || closeErr != nil {
			return nil, nil, fmt.Errorf("cannot inspect APK entry")
		}
		remaining -= int64(len(data))
		if uint64(len(data)) < entry.UncompressedSize64 {
			warnings = append(warnings, "APK URL discovery read only a bounded prefix of "+entry.Name)
		}
		owners := map[string]string{}
		if pkg != "" && strings.HasSuffix(name, ".dex") {
			owners = dexAppURLs(data, pkg)
		}
		candidates := literalURL.FindAll(data, 1000)
		if strings.HasSuffix(name, ".arsc") {
			for _, value := range resourceTableStrings(data) {
				for _, candidate := range literalURL.FindAllString(value, 32) {
					candidates = append(candidates, []byte(candidate))
					owners[strings.TrimRight(candidate, ".,;)}]")] = pkg + "/resources"
				}
				if len(candidates) >= 2000 {
					break
				}
			}
		}
		for _, candidate := range candidates {
			raw := strings.TrimRight(string(candidate), ".,;)}]")
			owner := owners[raw]
			parsed, err := url.Parse(raw)
			if err != nil || parsed.User != nil || parsed.Hostname() == "" {
				continue
			}
			// XML namespace/standards URIs are not application API candidates.
			if parsed.Hostname() == "schemas.android.com" || parsed.Hostname() == "www.w3.org" {
				continue
			}
			// Retain parameter names in inventory, never query credential values.
			query := parsed.Query()
			for key := range query {
				query.Set(key, "")
			}
			parsed.RawQuery = query.Encode()
			parsed.Fragment = ""
			raw = parsed.String()
			key := raw + "\x00" + entry.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, URLObservation{URL: raw, File: entry.Name, Owner: owner})
			if len(out) >= 2000 {
				warnings = append(warnings, "APK URL discovery stopped at 2000 observations.")
				return out, warnings, nil
			}
		}
		// Host-less API path templates from code (Retrofit/OkHttp etc.). These carry
		// no base URL — the agent combines them with the base observed in runtime
		// proxy traffic, which the app often resolves differently at runtime.
		if strings.HasSuffix(name, ".dex") {
			for _, p := range dexAPIPaths(data) {
				key := p + "\x00" + entry.Name
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, URLObservation{URL: p, File: entry.Name, Owner: pkg + "/path", Kind: "path"})
				if len(out) >= 2000 {
					warnings = append(warnings, "APK URL discovery stopped at 2000 observations.")
					return out, warnings, nil
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out, warnings, nil
}
