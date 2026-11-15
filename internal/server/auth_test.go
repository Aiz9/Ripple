package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// Missing-key and read-error GetSetting results both have empty values; only error distinguishes
// them. Treating failures as unset opens unauthenticated initialization during DB disruption,
// letting authInit overwrite passwords and authStatus send users toward /setup.
// Both handlers must fail closed rather than reinterpret database failure as first-run setup.
//
// Close the pool to induce read errors and verify both boundaries.
func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	// Closed pool returns a real error rather than sql.ErrNoRows.
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (treating a read failure as uninitialized would send the user to /setup to overwrite the password); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("on a read failure it must not answer initialized, got %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"password":"correct horse battery"}`)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", body))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (allowing on a read failure would let unauthenticated requests overwrite the existing password); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("on a read failure it must not issue a token: %s", w.Body.String())
	}
}

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name, pw string
		wantErr  bool
	}{
		{"empty", "", true},
		{"seven characters", "1234567", true},
		{"eight characters", "12345678", false},
		{"eight CJK characters count by characters, not bytes", "\u5bc6\u7801\u5bc6\u7801\u5bc6\u7801\u5bc6\u7801", false},
		{"three CJK characters reach 9 bytes but are only 3 characters", "\u5bc6\u7801\u5f3a", true},
		{"72 bytes", strings.Repeat("a", 72), false},
		{"73 bytes exceeds the bcrypt limit", strings.Repeat("a", 73), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.pw); (got != "") != tc.wantErr {
				t.Fatalf("validatePassword(%q)=%q, wantErr=%v", tc.pw, got, tc.wantErr)
			}
		})
	}
}
