package staticx

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveAnalyzeAllSafe(t *testing.T) {
	apk := os.Getenv("ARTEX_LIVE_APK")
	if apk == "" {
		t.Skip("set ARTEX_LIVE_APK")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	f, err := Analyze(ctx, apk, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if f.Package != "infosecadventures.allsafe" || f.SHA256 != "d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9" {
		t.Fatal("static fixture does not match the approved AllSafe APK")
	}
	t.Logf("AllSafe static analysis: complete=%t components=%d crypto_sites=%d recovered_literals=%d warnings=%d", f.Complete, len(f.Components), len(f.CryptoCallSites), len(f.Secrets), len(f.Warnings))
}
