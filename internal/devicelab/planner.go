package devicelab

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Aiz9/ripple/internal/staticx"
)

// ProtectionPlan describes what runtime bypasses the target app requires.
// The planner inspects static facts and decompiled source to decide autonomously
// whether root detection and SSL pinning must be neutralized for the assessment
// to exercise dynamic behavior.
type ProtectionPlan struct {
	HasRootDetection bool     `json:"has_root_detection"`
	HasSSLPinning    bool     `json:"has_ssl_pinning"`
	HasFlutter       bool     `json:"has_flutter"`
	RootSignals      []string `json:"root_signals,omitempty"`
	PinningSignals   []string `json:"pinning_signals,omitempty"`
	FlutterSignals   []string `json:"flutter_signals,omitempty"`
	FlipRoot         bool     `json:"flip_root"`
	FlipSSL          bool     `json:"flip_ssl"`
	// FlipFlutterSSL enables the native BoringSSL cert-chain-verify bypass in
	// instrument.js. Flutter does TLS in libflutter.so (BoringSSL) against its
	// own bundled CA set, ignoring the Android system trust store — so the
	// Java-layer pinning hooks never see it. When a Flutter engine is present we
	// attempt the native bypass so proxy-captured TLS can be decrypted.
	FlipFlutterSSL bool         `json:"flip_flutter_ssl"`
	FlipMethods    []FlipMethod `json:"flip_methods,omitempty"`
}

// FlipMethod is a Frida hook override passed to instrument.js via CFG.flip_methods.
type FlipMethod struct {
	Cls    string `json:"cls"`
	Method string `json:"method"`
	Ret    string `json:"ret"`
	Label  string `json:"label"`
}

type protectionPattern struct {
	pattern string
	signal  string
}

var rootDetectionPatterns = []protectionPattern{
	{"com.scottyab.rootbeer", "RootBeer"},
	{"com.google.android.gms.safetynet", "SafetyNet"},
	{"com.google.android.play.core.integrity", "PlayIntegrity"},
	{"flutter_jailbreak_detection", "FlutterJailbreakDetection"},
	{"RootBeer", "RootBeer"},
	{".isRooted()", "RootCheck"},
	{"isDeviceRooted", "RootCheck"},
	{"checkForSuBinary", "SuBinaryCheck"},
	{"checkForBusyBoxBinary", "BusyBoxCheck"},
	{"checkForDangerousProps", "PropCheck"},
	{"checkForRWPaths", "RWPathCheck"},
	{"com.noshufou.android.su", "SuApp"},
	{"eu.chainfire.supersu", "SuperSU"},
	{"com.topjohnwu.magisk", "Magisk"},
}

var sslPinningPatterns = []protectionPattern{
	{"CertificatePinner", "OkHttpPinning"},
	{"certificatePinner", "OkHttpPinning"},
	{"X509TrustManager", "CustomTrustManager"},
	{"checkServerTrusted", "CustomTrustManager"},
	{"SSLPeerUnverifiedException", "PinningException"},
	{"CertPathValidatorException", "CertValidation"},
	{"network_security_config", "NetworkSecurityConfig"},
	{"TrustManagerFactory", "TrustManagerFactory"},
	{"okhttp3.CertificatePinner", "OkHttpPinning"},
}

// PlanProtections analyzes static facts and the decompiled source tree to
// determine whether the app uses root detection or SSL pinning. When detected,
// the plan enables the corresponding Frida bypass so the assessment can exercise
// dynamic behavior without being blocked. When nothing is detected, the app
// runs unmodified.
func PlanProtections(facts *staticx.Facts, logf func(string, ...any)) ProtectionPlan {
	plan := ProtectionPlan{}

	for _, lib := range facts.NativeLibs {
		lower := strings.ToLower(lib)
		if strings.Contains(lower, "rootbeer") || strings.Contains(lower, "rootdetect") {
			plan.HasRootDetection = true
			plan.RootSignals = uniqueAppend(plan.RootSignals, "native_lib:"+lib)
		}
		if strings.Contains(lower, "libflutter.so") {
			plan.HasFlutter = true
			plan.FlutterSignals = uniqueAppend(plan.FlutterSignals, "native_lib:"+lib)
		}
	}

	if facts.NetworkConfig != "" {
		nc := strings.ToLower(facts.NetworkConfig)
		if strings.Contains(nc, "pin-set") || strings.Contains(nc, "pinset") {
			plan.HasSSLPinning = true
			plan.PinningSignals = uniqueAppend(plan.PinningSignals, "network_security_config:pin-set")
		}
	}

	if facts.SourceRoot != "" {
		scanSourceForProtections(facts.SourceRoot, &plan)
	}

	plan.FlipRoot = plan.HasRootDetection
	plan.FlipSSL = plan.HasSSLPinning
	plan.FlipFlutterSSL = plan.HasFlutter

	if plan.HasRootDetection {
		plan.FlipMethods = append(plan.FlipMethods, knownRootFlipMethods(plan.RootSignals)...)
	}

	if logf != nil {
		if plan.HasRootDetection {
			logf("planner: root detection found (%s) — bypass enabled", strings.Join(plan.RootSignals, ", "))
		}
		if plan.HasSSLPinning {
			logf("planner: SSL pinning found (%s) — bypass enabled", strings.Join(plan.PinningSignals, ", "))
		}
		if plan.HasFlutter {
			logf("planner: Flutter engine found (%s) — native BoringSSL cert-verify bypass enabled", strings.Join(plan.FlutterSignals, ", "))
		}
		if !plan.HasRootDetection && !plan.HasSSLPinning && !plan.HasFlutter {
			logf("planner: no root detection or SSL pinning detected — running app unmodified")
		}
	}

	return plan
}

// knownRootFlipMethods produces additional flip_methods for root detection
// libraries beyond the built-in RootBeer hook in instrument.js.
func knownRootFlipMethods(signals []string) []FlipMethod {
	var methods []FlipMethod
	for _, sig := range signals {
		switch {
		case strings.Contains(sig, "SafetyNet"):
			methods = append(methods, FlipMethod{
				Cls: "com.google.android.gms.safetynet.SafetyNetClient", Method: "attest", Label: "safetynet_attest",
			})
		case strings.Contains(sig, "FlutterJailbreakDetection"):
			methods = append(methods, FlipMethod{
				Cls: "flutter_jailbreak_detection.FlutterJailbreakDetectionPlugin", Method: "onMethodCall", Label: "flutter_jailbreak",
			})
		}
	}
	return methods
}

const maxSourceScanFiles = 2000
const maxSourceFileSize = 512 * 1024

func scanSourceForProtections(root string, plan *ProtectionPlan) {
	scanned := 0
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if scanned >= maxSourceScanFiles {
			return filepath.SkipAll
		}
		if info.Size() > maxSourceFileSize {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".kt" && ext != ".smali" && ext != ".xml" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		scanned++
		text := string(content)
		rel := relSourcePath(root, path)

		for _, p := range rootDetectionPatterns {
			if strings.Contains(text, p.pattern) {
				plan.HasRootDetection = true
				plan.RootSignals = uniqueAppend(plan.RootSignals, p.signal+":"+rel)
			}
		}
		for _, p := range sslPinningPatterns {
			if strings.Contains(text, p.pattern) {
				plan.HasSSLPinning = true
				plan.PinningSignals = uniqueAppend(plan.PinningSignals, p.signal+":"+rel)
			}
		}
		return nil
	})
}

func relSourcePath(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return filepath.Base(path)
	}
	return rel
}

func uniqueAppend(ss []string, s string) []string {
	for _, v := range ss {
		if v == s {
			return ss
		}
	}
	return append(ss, s)
}
