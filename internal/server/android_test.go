package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func uploadAndroidFixture(t *testing.T, s *Server, name, manifest string) *httptest.ResponseRecorder {
	t.Helper()
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	f, err := z.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte(manifest))
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	m := multipart.NewWriter(&body)
	part, err := m.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(archive.Bytes())
	_ = m.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/android/apps", &body)
	r.Header.Set("Content-Type", m.FormDataContentType())
	w := httptest.NewRecorder()
	s.androidUpload(w, r)
	return w
}

// uploadAPKWithEntries uploads a zip containing the given entries and returns the
// decoded androidApp. Shared helper for APK-task tests.
func uploadAPKWithEntries(t *testing.T, s *Server, name string, entries map[string]string) *androidApp {
	t.Helper()
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	for path, content := range entries {
		f, err := z.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(content))
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	m := multipart.NewWriter(&body)
	part, err := m.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(archive.Bytes())
	_ = m.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/android/apps", &body)
	r.Header.Set("Content-Type", m.FormDataContentType())
	w := httptest.NewRecorder()
	s.androidUpload(w, r)
	if w.Code != 201 {
		t.Fatalf("uploadAPKWithEntries: %d %s", w.Code, w.Body.String())
	}
	var app androidApp
	if err := json.Unmarshal(w.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}
	return &app
}

func TestAndroidUploadPersistenceDedupAndTraversal(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}}
	manifest := `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test"><application android:allowBackup="false"/></manifest>`
	first := uploadAndroidFixture(t, s, "../../wallet.apk", manifest)
	if first.Code != 201 {
		t.Fatalf("upload: %d %s", first.Code, first.Body.String())
	}
	var app androidApp
	if err := json.Unmarshal(first.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}
	if app.Filename != "wallet.apk" || app.ID != app.Report.SHA256 || !strings.HasPrefix(app.APKPath, s.androidRoot()+string(os.PathSeparator)) {
		t.Fatalf("invalid paths: %+v", app)
	}
	if _, err := os.Stat(app.APKPath); err != nil {
		t.Fatal(err)
	}
	second := uploadAndroidFixture(t, s, "different.apk", manifest)
	if second.Code != 200 {
		t.Fatalf("dedup: %d %s", second.Code, second.Body.String())
	}
	w := httptest.NewRecorder()
	s.androidApps(w, httptest.NewRequest("GET", "/api/android/apps", nil))
	var list struct {
		Apps []androidApp `json:"apps"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Apps) != 1 {
		t.Fatalf("expected one APK: %s", w.Body.String())
	}
	if _, err := s.readAndroidApp("../../etc/passwd"); err == nil {
		t.Fatal("accepted invalid ID")
	}
	entries, err := os.ReadDir(s.androidRoot())
	if err != nil || len(entries) != 1 {
		t.Fatalf("staging files leaked: %v %v", entries, err)
	}
	for _, name := range []string{"report.txt", "test.apk"} {
		bad := uploadAndroidFixture(t, s, name, "invalid manifest")
		if bad.Code != 400 {
			t.Fatalf("accepted malformed upload: %s", bad.Body.String())
		}
	}
	if _, err := os.Stat(filepath.Join(s.m.dir, "wallet.apk")); !os.IsNotExist(err) {
		t.Fatal("unexpected file outside APK storage")
	}
}

func TestAndroidDeviceParsing(t *testing.T) {
	devices := parseAndroidDevices("List of devices attached\nemulator-5554 device product:sdk model:Pixel_8 transport_id:1\nABC unauthorized usb:1-1\nXYZ offline\n")
	if len(devices) != 3 || devices[0].Model != "Pixel 8" || devices[1].State != "unauthorized" {
		t.Fatalf("bad devices: %+v", devices)
	}
}

func TestAndroidRoutesRequireAuthentication(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}, jwtKey: []byte("test-only-jwt-key-32-bytes-minimum")}
	handler := s.Handler()
	for _, path := range []string{"/api/android/apps", "/api/android/environment", "/api/android/apps/invalid"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Fatalf("unauthenticated %s returned %d", path, w.Code)
		}
	}
}
