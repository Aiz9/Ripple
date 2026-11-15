package devicelab

import "testing"

func TestForegroundFromDump(t *testing.T) {
	cases := []struct{ name, dump, want string }{
		{"activity mResumedActivity", "    mResumedActivity: ActivityRecord{7d91878 u0 com.f1soft.shangrilamobilebanking/.MainActivity t25}", "com.f1soft.shangrilamobilebanking/com.f1soft.shangrilamobilebanking.MainActivity"},
		{"window mCurrentFocus", "  mCurrentFocus=Window{42c8de8 u0 com.f1soft.shangrilamobilebanking/com.f1soft.shangrilamobilebanking.MainActivity}", "com.f1soft.shangrilamobilebanking/com.f1soft.shangrilamobilebanking.MainActivity"},
		{"permission dialog", "    mResumedActivity: ActivityRecord{abc u0 com.google.android.permissioncontroller/.permission.ui.GrantPermissionsActivity t9}", "com.google.android.permissioncontroller/com.google.android.permissioncontroller.permission.ui.GrantPermissionsActivity"},
		{"none", "no resumed line here", ""},
	}
	for _, c := range cases {
		if got := foregroundFromDump(c.dump); got != c.want {
			t.Errorf("%s: foregroundFromDump = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestSystemFlowAllowlist(t *testing.T) {
	// A runtime-permission dialog is part of the target's own flow → allowed.
	if !systemFlowPackages["com.google.android.permissioncontroller"] {
		t.Error("permission controller should be an in-flow system surface")
	}
	// The launcher and arbitrary apps are not in the allowlist (still blocked
	// unless they ARE the approved package, which InteractAllowed checks).
	if systemFlowPackages["com.android.launcher3"] || systemFlowPackages["com.android.chrome"] {
		t.Error("launcher / unrelated apps must not be allowlisted")
	}
}
