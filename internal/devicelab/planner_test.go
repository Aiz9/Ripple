package devicelab

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Aiz9/ripple/internal/staticx"
)

func TestPlanProtections_NoProtections(t *testing.T) {
	facts := &staticx.Facts{Package: "com.example.app"}
	plan := PlanProtections(facts, nil)
	if plan.HasRootDetection || plan.HasSSLPinning || plan.FlipRoot || plan.FlipSSL {
		t.Fatal("expected no protections for clean app")
	}
}

func TestPlanProtections_RootBeerNativeLib(t *testing.T) {
	facts := &staticx.Facts{
		Package:    "com.example.app",
		NativeLibs: []string{"libfoo.so", "librootbeer.so", "libbar.so"},
	}
	plan := PlanProtections(facts, nil)
	if !plan.HasRootDetection {
		t.Fatal("expected root detection from rootbeer native lib")
	}
	if !plan.FlipRoot {
		t.Fatal("expected FlipRoot enabled")
	}
	if plan.HasSSLPinning {
		t.Fatal("expected no SSL pinning")
	}
}

func TestPlanProtections_NetworkSecurityConfigPinSet(t *testing.T) {
	facts := &staticx.Facts{
		Package:       "com.example.app",
		NetworkConfig: `<pin-set expiration="2025-01-01"><pin digest="SHA-256">abc</pin></pin-set>`,
	}
	plan := PlanProtections(facts, nil)
	if !plan.HasSSLPinning {
		t.Fatal("expected SSL pinning from pin-set in network config")
	}
	if !plan.FlipSSL {
		t.Fatal("expected FlipSSL enabled")
	}
}

func TestPlanProtections_SourceScan(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "com", "example")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "Security.java"), []byte(`
		import com.scottyab.rootbeer.RootBeer;
		public class Security {
			boolean check() { return new RootBeer(ctx).isRooted(); }
		}
	`), 0o644)
	os.WriteFile(filepath.Join(src, "Network.java"), []byte(`
		import okhttp3.CertificatePinner;
		CertificatePinner pinner = new CertificatePinner.Builder().build();
	`), 0o644)

	facts := &staticx.Facts{Package: "com.example.app", SourceRoot: dir}
	plan := PlanProtections(facts, nil)
	if !plan.HasRootDetection {
		t.Fatal("expected root detection from source scan")
	}
	if !plan.HasSSLPinning {
		t.Fatal("expected SSL pinning from source scan")
	}
	if len(plan.RootSignals) == 0 {
		t.Fatal("expected root signals populated")
	}
	if len(plan.PinningSignals) == 0 {
		t.Fatal("expected pinning signals populated")
	}
}
