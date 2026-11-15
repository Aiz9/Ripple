package devicelab

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Live tests run only when ARTEX_LIVE_DEVICE is set (serial) with the AllSafe
// APK at ARTEX_LIVE_APK. They exercise the real adb path end to end.
func liveDevice(t *testing.T) *Device {
	serial := os.Getenv("ARTEX_LIVE_DEVICE")
	if serial == "" {
		t.Skip("set ARTEX_LIVE_DEVICE to run live device tests")
	}
	sha := os.Getenv("ARTEX_LIVE_SHA")
	pkg := os.Getenv("ARTEX_LIVE_PKG")
	if pkg == "" {
		pkg = "infosecadventures.allsafe"
	}
	d, err := New(serial, pkg, sha, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if !d.Online(ctx) {
		t.Fatalf("device %s offline", serial)
	}
	d.DetectRoot(ctx)
	return d
}

func TestLiveRootAndProps(t *testing.T) {
	d := liveDevice(t)
	ctx := context.Background()
	t.Logf("root=%q sdk=%d abi=%s", d.rootMode, d.SDK(ctx), d.Prop(ctx, "ro.product.cpu.abi"))
	if d.SDK(ctx) < 23 {
		t.Fatalf("unexpected sdk %d", d.SDK(ctx))
	}
}

func TestLiveInstalledHash(t *testing.T) {
	d := liveDevice(t)
	ctx := context.Background()
	if d.InstalledAPKPath(ctx) == "" {
		t.Skip("AllSafe not installed")
	}
	got, err := d.InstalledSHA256(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("installed sha256=%s", got)
	if len(got) != 64 {
		t.Fatalf("bad hash %q", got)
	}
}

func TestLiveLaunchAndDump(t *testing.T) {
	d := liveDevice(t)
	ctx := context.Background()
	_ = d.ForceStop(ctx)
	if _, err := d.Launch(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	if !d.InForeground(ctx) {
		t.Fatalf("app not foreground, current=%s", d.CurrentActivity(ctx))
	}
	screen, err := d.DumpUI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("activity=%s signature=%s nodes=%d texts=%d", screen.Activity, screen.Signature, len(screen.Nodes), len(screen.Texts))
	if !screen.OwnedBy(d.Package) || len(screen.Nodes) == 0 {
		t.Fatalf("expected owned screen with nodes")
	}
	uid := d.UID(ctx)
	t.Logf("uid=%d flags=%q", uid, d.PackageFlags(ctx))
	if uid <= 0 {
		t.Fatalf("expected a package uid")
	}
}

func TestLiveFlagSecureScreenshot(t *testing.T) {
	d := liveDevice(t)
	ctx := context.Background()
	_ = d.ForceStop(ctx)
	if _, err := d.Launch(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	png, err := d.Screenshot(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// AllSafe's MainActivity sets FLAG_SECURE, so the capture is blocked.
	t.Logf("screenshot bytes=%d blocked=%v", len(png), ScreenCaptureBlocked(png))
	if !ScreenCaptureBlocked(png) {
		t.Fatalf("expected FLAG_SECURE to block capture on MainActivity")
	}
}

func TestLiveStorageSnapshot(t *testing.T) {
	d := liveDevice(t)
	ctx := context.Background()
	files, notes := d.SnapshotStorage(ctx)
	t.Logf("files=%d notes=%v", len(files), notes)
	for _, f := range files {
		if !d.allowedPath(f.Path) {
			t.Fatalf("snapshot returned out-of-scope path %s", f.Path)
		}
		if strings.HasSuffix(f.Path, ".db") || strings.Contains(f.Path, "databases/") {
			if dump, err := DumpSQLite(f.Content); err == nil {
				t.Logf("SQLite parse succeeded; decoded_bytes=%d", len(dump))
			}
		}
	}
}
