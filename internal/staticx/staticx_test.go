package staticx

import "testing"

func TestAaptAttrValue(t *testing.T) {
	cases := map[string][2]string{
		`            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true`:                    {"exported", "true"},
		`            A: http://schemas.android.com/apk/res/android:name(0x01010003)="x.y.Z" (Raw: "x.y.Z")`:      {"name", "x.y.Z"},
		`        A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f)=(type 0x12)0xffffffff`:     {"debuggable", "true"},
		`        A: http://schemas.android.com/apk/res/android:minSdkVersion(0x0101020c)=(type 0x10)0x17`:        {"minSdkVersion", "0x17"},
		`          A: http://schemas.android.com/apk/res/android:authorities(0x01010018)="a.b.c" (Raw: "a.b.c")`: {"authorities", "a.b.c"},
		`            A: http://schemas.android.com/apk/res/android:scheme="allsafe" (Raw: "allsafe")`:            {"scheme", "allsafe"},
	}
	for line, want := range cases {
		n, v := aaptAttrValue(line)
		if n != want[0] || v != want[1] {
			t.Errorf("line %q => (%q,%q) want (%q,%q)", line, n, v, want[0], want[1])
		}
	}
	if atoi("0x17") != 23 || atoi("35") != 35 {
		t.Errorf("atoi hex/dec: %d %d", atoi("0x17"), atoi("35"))
	}
}

func TestSecretLike(t *testing.T) {
	yes := map[string]string{"key": "ebfb7ff0-b2f6-41c8-bef3-4fba17be410c", "api_secret": "abcdef123456"}
	no := map[string]string{"password_toggle_content_description": "Show password", "path_password_eye": "M12,4.5C7,4.5", "password_hint": "Enter password here"}
	for name, val := range yes {
		if !secretLike(name, val) {
			t.Errorf("expected secretLike(%q,%q)=true", name, val)
		}
	}
	for name, val := range no {
		if secretLike(name, val) {
			t.Errorf("expected secretLike(%q,%q)=false", name, val)
		}
	}
}

func TestLooksLikeKey(t *testing.T) {
	if !looksLikeKey("1nf053c4dv3n7ur3") {
		t.Error("16-char AES key should qualify")
	}
	if looksLikeKey("short") || looksLikeKey("has space here") || looksLikeKey("http://x.y/z") {
		t.Error("non-keys should not qualify")
	}
}

func TestManifestParsing(t *testing.T) {
	// A trimmed aapt2 xmltree of an exported receiver with extras and a provider.
	dump := `N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=1)
    E: uses-sdk (line=7)
      A: http://schemas.android.com/apk/res/android:minSdkVersion(0x0101020c)=(type 0x10)0x17
      A: http://schemas.android.com/apk/res/android:targetSdkVersion(0x01010270)=(type 0x10)0x23
    E: application (line=24)
      A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f)=true
      A: http://schemas.android.com/apk/res/android:allowBackup(0x01010280)=true
      E: receiver (line=73)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="x.NoteReceiver" (Raw: "x.NoteReceiver")
        A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true
        E: intent-filter (line=76)
          E: action (line=77)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="x.action.PROCESS_NOTE" (Raw: "x.action.PROCESS_NOTE")
      E: provider (line=86)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="x.DataProvider" (Raw: "x.DataProvider")
        A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true
        A: http://schemas.android.com/apk/res/android:authorities(0x01010018)="x.dataprovider" (Raw: "x.dataprovider")
      E: activity (line=39)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="x.DeepLinkTask" (Raw: "x.DeepLinkTask")
        A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true
        E: intent-filter (line=43)
          E: action (line=44)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.intent.action.VIEW" (Raw: "android.intent.action.VIEW")
          E: data (line=49)
            A: http://schemas.android.com/apk/res/android:scheme(0x01010027)="allsafe" (Raw: "allsafe")
            A: http://schemas.android.com/apk/res/android:host(0x01010028)="infosecadventures" (Raw: "infosecadventures")`
	f := &Facts{}
	if err := f.parseManifestLines(dump); err != nil {
		t.Fatal(err)
	}
	if f.MinSDK != 23 || f.TargetSDK != 35 || !f.Debuggable || !f.AllowBackup {
		t.Fatalf("app flags: minsdk=%d target=%d dbg=%v backup=%v", f.MinSDK, f.TargetSDK, f.Debuggable, f.AllowBackup)
	}
	nr := f.Component("NoteReceiver")
	if nr == nil || !nr.Exported || len(nr.Actions) != 1 || nr.Actions[0] != "x.action.PROCESS_NOTE" {
		t.Fatalf("NoteReceiver not parsed: %+v", nr)
	}
	dp := f.Component("DataProvider")
	if dp == nil || !dp.Exported || dp.Authority != "x.dataprovider" {
		t.Fatalf("DataProvider not parsed: %+v", dp)
	}
	if len(f.DeepLinks) != 1 || f.DeepLinks[0].Scheme != "allsafe" || f.DeepLinks[0].Host != "infosecadventures" {
		t.Fatalf("deep link not parsed: %+v", f.DeepLinks)
	}
	if len(f.ExportedActivities()) != 1 {
		t.Fatalf("expected 1 exported activity, got %d", len(f.ExportedActivities()))
	}
}
