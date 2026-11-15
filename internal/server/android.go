package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/internal/androidapk"
)

const maxAPKUpload = 256 << 20

var apkIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type androidApp struct {
	ID         string             `json:"id"`
	Filename   string             `json:"filename"`
	UploadedAt string             `json:"uploaded_at"`
	APKPath    string             `json:"apk_path"`
	ReportPath string             `json:"report_path"`
	Report     *androidapk.Report `json:"report"`
	// StaticURLs is the full static endpoint inventory extracted from the APK at
	// upload (DEX const-strings with owning class, resources, native libs). It is
	// injected into the APK task so the agent starts from every statically-found
	// endpoint instead of re-discovering them ad hoc.
	StaticURLs []androidapk.URLObservation `json:"static_urls,omitempty"`
}

func (s *Server) androidRoot() string { return filepath.Join(s.m.dir, "android", "apps") }

func (s *Server) readAndroidApp(id string) (*androidApp, error) {
	if !apkIDPattern.MatchString(id) {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(filepath.Join(s.androidRoot(), id, "report.json"))
	if err != nil {
		return nil, err
	}
	var app androidApp
	if err = json.Unmarshal(b, &app); err != nil {
		return nil, err
	}
	return &app, nil
}

func (s *Server) androidApps(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.androidRoot())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeErr(w, 500, "Cannot read Android app storage")
		return
	}
	apps := []*androidApp{}
	for _, entry := range entries {
		if entry.IsDir() && apkIDPattern.MatchString(entry.Name()) {
			app, err := s.readAndroidApp(entry.Name())
			if err != nil {
				writeErr(w, 500, "Cannot read stored Android report")
				return
			}
			apps = append(apps, app)
		}
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].UploadedAt > apps[j].UploadedAt })
	writeJSON(w, 200, map[string]any{"apps": apps})
}

func (s *Server) androidAppDetail(w http.ResponseWriter, r *http.Request) {
	app, err := s.readAndroidApp(r.PathValue("id"))
	if err != nil {
		writeErr(w, 404, "Android app not found")
		return
	}
	writeJSON(w, 200, app)
}

func (s *Server) androidUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAPKUpload+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		if r.MultipartForm != nil {
			r.MultipartForm.RemoveAll()
		}
		writeErr(w, 400, "Invalid upload or request exceeds the 256 MiB APK limit")
		return
	}
	defer r.MultipartForm.RemoveAll()
	headers := r.MultipartForm.File["file"]
	if len(headers) != 1 {
		writeErr(w, 400, "Upload exactly one APK in the file field")
		return
	}
	hdr := headers[0]
	name := filepath.Base(strings.ReplaceAll(hdr.Filename, `\`, "/"))
	if !strings.EqualFold(filepath.Ext(name), ".apk") || hdr.Size > maxAPKUpload {
		writeErr(w, 400, "Choose an .apk file up to 256 MiB")
		return
	}
	if err := os.MkdirAll(s.androidRoot(), 0o700); err != nil {
		writeErr(w, 500, "Cannot create Android app storage")
		return
	}
	tmp, err := os.MkdirTemp(s.androidRoot(), ".upload-")
	if err != nil {
		writeErr(w, 500, "Cannot stage APK")
		return
	}
	defer os.RemoveAll(tmp)
	src, err := hdr.Open()
	if err != nil {
		writeErr(w, 400, "Cannot read upload")
		return
	}
	defer src.Close()
	dst, err := os.OpenFile(filepath.Join(tmp, "app.apk"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		writeErr(w, 500, "Cannot save APK")
		return
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil || closeErr != nil {
		writeErr(w, 500, "Cannot save APK")
		return
	}
	report, err := androidapk.Analyze(filepath.Join(tmp, "app.apk"))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if existing, err := s.readAndroidApp(report.SHA256); err == nil {
		writeJSON(w, 200, existing)
		return
	}
	dir := filepath.Join(s.androidRoot(), report.SHA256)
	// Extract the static endpoint inventory now (best-effort) so the task carries
	// every statically-found endpoint; discovery failure never blocks the upload.
	staticURLs, _, _ := androidapk.DiscoverApplicationURLs(filepath.Join(tmp, "app.apk"), report.Package)
	app := androidApp{ID: report.SHA256, Filename: name, UploadedAt: time.Now().UTC().Format(time.RFC3339Nano), APKPath: filepath.Join(dir, "app.apk"), ReportPath: filepath.Join(dir, "report.json"), Report: report, StaticURLs: staticURLs}
	b, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		writeErr(w, 500, "Cannot encode analysis report")
		return
	}
	if err = os.WriteFile(filepath.Join(tmp, "report.json"), b, 0o600); err != nil {
		writeErr(w, 500, "Cannot save analysis report")
		return
	}
	if err = os.Rename(tmp, dir); err != nil {
		// Concurrent uploads of the same hash return the already committed report.
		if existing, e := s.readAndroidApp(report.SHA256); e == nil {
			writeJSON(w, 200, existing)
			return
		}
		writeErr(w, 500, "Cannot commit APK analysis")
		return
	}
	writeJSON(w, 201, app)
}

type androidDevice struct {
	Serial string `json:"serial"`
	State  string `json:"state"`
	Model  string `json:"model"`
}

func parseAndroidDevices(output string) []androidDevice {
	devices := []androidDevice{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(line, "List of devices") || strings.HasPrefix(line, "*") {
			continue
		}
		device := androidDevice{Serial: fields[0], State: fields[1]}
		for _, field := range fields[2:] {
			if strings.HasPrefix(field, "model:") {
				device.Model = strings.ReplaceAll(strings.TrimPrefix(field, "model:"), "_", " ")
			}
		}
		devices = append(devices, device)
	}
	return devices
}

func connectedAndroidDevices(ctx context.Context) ([]androidDevice, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "adb", "devices", "-l").Output()
	if err != nil {
		return []androidDevice{}, fmt.Errorf("ADB device discovery failed; check the SDK, USB authorization, and ADB server")
	}
	return parseAndroidDevices(string(out)), nil
}

func (s *Server) androidEnvironment(w http.ResponseWriter, r *http.Request) {
	tools := map[string]bool{}
	// Device + decompile tooling, then SAST/secret-scan and SCA/CVE tooling.
	// All are optional: each worker degrades gracefully when its tool is absent,
	// and scripts/install-apk-tools.sh installs the full set.
	for _, name := range []string{
		"adb", "apktool", "jadx", "apksigner", "frida", "objection",
		"semgrep", "trufflehog", "gitleaks", "osv-scanner", "trivy", "dependency-check", "mobsf",
	} {
		_, err := exec.LookPath(name)
		tools[name] = err == nil
	}
	devices := []androidDevice{}
	message := ""
	if tools["adb"] {
		var err error
		devices, err = connectedAndroidDevices(r.Context())
		if err != nil {
			message = err.Error()
		}
	} else {
		message = "ADB is not installed on the backend host. Offline APK triage is available."
	}
	writeJSON(w, 200, map[string]any{"tools": tools, "devices": devices, "message": message, "max_upload_bytes": maxAPKUpload})
}
