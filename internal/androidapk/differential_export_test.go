package androidapk

// Diagnostic adapter: exercises the production parsers without replacing them.
// Full DEX strings are deliberately null: production has no full-table API.
import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestDifferentialExport(t *testing.T) {
	input, output := os.Getenv("APK_DIFFERENTIAL_INPUT"), os.Getenv("APK_DIFFERENTIAL_OUTPUT")
	if input == "" || output == "" {
		t.Skip("external corpus runner only")
	}
	paths, err := filepath.Glob(filepath.Join(input, "*.apk"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("empty corpus")
	}
	if err = os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		out := map[string]any{"dex_strings": nil, "dex_strings_status": "unsupported: production exposes URL observations, not a complete DEX string table"}
		report, err := Analyze(path)
		if err != nil {
			out["error"] = err.Error()
		} else {
			out["report"] = report
			urls, warnings, err := DiscoverApplicationURLs(path, report.Package)
			if err != nil {
				out["url_error"] = err.Error()
			}
			out["urls"] = urls
			out["url_warnings"] = warnings
			z, err := zip.OpenReader(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range z.File {
				if f.Name != "AndroidManifest.xml" {
					continue
				}
				r, err := f.Open()
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					t.Fatal(err)
				}
				root, err := parseManifest(data)
				if err != nil {
					t.Fatal(err)
				}
				flags := map[string]string{}
				for _, app := range root.children {
					if app.name == "application" {
						for _, key := range []string{"debuggable", "allowBackup", "usesCleartextTraffic", "testOnly", "extractNativeLibs", "supportsRtl"} {
							flags[key] = app.attr(key)
						}
					}
				}
				out["manifest_flags"] = flags
			}
			z.Close()
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(output, filepath.Base(path)+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
