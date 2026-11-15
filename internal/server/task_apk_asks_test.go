package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/internal/androidapk"
)

// TestAPKTaskDescriptionTriggersAllAsks verifies that the description the New APK
// dialog pre-fills (and submits) carries every ask: exhaustive static + runtime
// (pre/post-login) endpoint enumeration, reliable login, the static inventory,
// and OWASP/business-logic testing of every endpoint. The dialog's POST also
// tags the description with the APK marker, which drives runtime-first phase-goal
// seeding — asserted here via apkMarkerID.
func TestAPKTaskDescriptionTriggersAllAsks(t *testing.T) {
	app := &androidApp{
		ID:      strings.Repeat("a", 64),
		APKPath: "/data/android/apps/x/app.apk",
		Report:  &androidapk.Report{Package: "com.example.app"},
		StaticURLs: []androidapk.URLObservation{
			{URL: "https://api.example.com/v1/login", Owner: "com.example.app/Api"},
		},
	}
	d := apkTaskDescription(app, []string{"api.example.com"}, "")

	for _, want := range []string{
		"ENDPOINT ENUMERATION IS MANDATORY",
		"BEFORE LOGIN",
		"LOG IN RELIABLY",
		"AFTER LOGIN",
		"mobile_discover_runtime_apis",
		"mobile_identity_set",
		"BOLA / IDOR (API1)",
		"BUSINESS LOGIC",
		"STATIC ENDPOINT INVENTORY",
		"https://api.example.com/v1/login",
	} {
		if !strings.Contains(d, want) {
			t.Fatalf("APK task description is missing ask: %q", want)
		}
	}

	// The dialog's POST prepends this marker; it must be recognised so createGoals
	// seeds the runtime-first phase flow instead of one generic goal.
	tagged := "[Android APK: " + app.ID + "]\n" + d
	if id, ok := apkMarkerID(tagged); !ok || id != app.ID {
		t.Fatalf("APK marker not recognised on tagged description (ok=%v id=%q)", ok, id)
	}
}
