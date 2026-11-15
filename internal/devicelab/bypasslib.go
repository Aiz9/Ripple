package devicelab

import (
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/internal/staticx"
)

// Bypass is a reusable client-side-protection defeat: how to DETECT a protection
// from static facts, and how to NEUTRALIZE it at runtime via Frida. The registry
// below is the single source of truth the planner and the instrumentation layer
// reason over, so a new protection is added as data, not another code branch.
//
// Patterns that were reverse-engineered by hand — e.g. the Flutter BoringSSL
// cert-verify function in a stripped libflutter.so — live here as durable,
// reusable capability instead of being re-derived each run. The autonomous agent
// selects applicable bypasses by reasoning over DetectLibs/DetectSource; it does
// not invent the byte patterns.
type Bypass struct {
	ID       string // stable id, e.g. "flutter.boringssl.verify_cert_chain"
	Title    string
	Category string // ssl_pinning | root_detection | flutter_tls
	Platform string // android | ios | both
	// DetectLibs: substring signals matched against Facts.NativeLibs.
	DetectLibs []string
	// DetectSource: substring signals matched against decompiled source / class names
	// (the planner's source scan supplies these).
	DetectSource []string
	Native       []NativeHook // native-code hooks (byte-pattern scan in a module)
	Java         []JavaHook   // Java-layer hooks
	Notes        string
}

// NativeHook locates a function by byte pattern in a native module and overrides
// its behaviour. Pattern is a Frida Memory.scan hex string; '??' wildcards allowed.
type NativeHook struct {
	Module  string
	Arch    string // "x86_64" | "arm64" | "" (any)
	Pattern string
	OnLeave string // JS applied to retval in onLeave, e.g. "retval.replace(0x1)"
	Desc    string
}

// JavaHook overrides a Java method. Kind "flip" forces Ret; "pinning_swallow"
// calls through and swallows a pinning/cert exception so verification passes.
type JavaHook struct {
	Class  string
	Method string
	Ret    string // "true" | "false" | "void" | ""
	Kind   string // "flip" | "pinning_swallow"
}

// BuiltinBypasses is the registry of known client-protection defeats.
var BuiltinBypasses = []Bypass{
	{
		ID:         "flutter.boringssl.verify_cert_chain",
		Title:      "Flutter BoringSSL certificate-chain verification bypass",
		Category:   "flutter_tls",
		Platform:   "android", // iOS uses the same engine; arch pattern differs (see Notes)
		DetectLibs: []string{"libflutter.so"},
		Native: []NativeHook{
			{
				Module: "libflutter.so", Arch: "x86_64",
				// Recent Flutter (3.x) x86_64 ssl_crypto_x509_session_verify_cert_chain entry:
				// the 6-arg register shuffle after the push chain is the fingerprint; the
				// frame-size immediate is wildcarded so minor builds still match.
				Pattern: "55 41 57 41 56 41 55 41 54 53 48 81 ec ?? ?? ?? ?? 4c 89 cd 4d 89 c5 49 89 ce 49 89 d4 48 89 f3 49 89 ff",
				OnLeave: "retval.replace(0x1)",
				Desc:    "force verify result = 1 (ok)",
			},
			{
				Module: "libflutter.so", Arch: "x86_64",
				Pattern: "55 41 57 41 56 41 55 41 54 53 48 81 ec f8 00 00 00 c6 02 50 48 8b 9f a8 00 00 00 48 85 db 0f 84 10 01 00 00 48 83 3b 00 0f 84 06 01 00 00",
				OnLeave: "retval.replace(0x1)",
				Desc:    "nviso-2020 x86_64 fallback",
			},
			{
				Module: "libflutter.so", Arch: "arm64",
				Pattern: "f6 57 bd a9 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 f3 03 00 aa 08 0a 40 f9 08 15 40 f9 a8 02 00 b4",
				OnLeave: "retval.replace(0x1)",
				Desc:    "nviso-2020 arm64 fallback",
			},
		},
		Notes: "Flutter validates TLS in its statically-linked BoringSSL against its own CA " +
			"set, ignoring the Android system trust store and the Java layer — so the OkHttp/" +
			"Conscrypt hooks never see it. Not all builds call this function (some pin via a " +
			"custom_verify callback or in Dart); the agent must confirm the hook fires.",
	},
	{
		ID:           "okhttp.certificate_pinner",
		Title:        "OkHttp CertificatePinner bypass",
		Category:     "ssl_pinning",
		Platform:     "android",
		DetectSource: []string{"okhttp3.CertificatePinner", "CertificatePinner", "certificatePinner"},
		Java: []JavaHook{
			{Class: "okhttp3.CertificatePinner", Method: "check", Kind: "pinning_swallow"},
			{Class: "com.squareup.okhttp.CertificatePinner", Method: "check", Kind: "pinning_swallow"},
		},
	},
	{
		ID:           "conscrypt.trustmanager",
		Title:        "Conscrypt TrustManagerImpl chain verification bypass",
		Category:     "ssl_pinning",
		Platform:     "android",
		DetectSource: []string{"X509TrustManager", "checkServerTrusted", "TrustManagerFactory", "SSLPeerUnverifiedException"},
		Java: []JavaHook{
			{Class: "com.android.org.conscrypt.TrustManagerImpl", Method: "verifyChain", Kind: "pinning_swallow"},
			{Class: "org.conscrypt.TrustManagerImpl", Method: "verifyChain", Kind: "pinning_swallow"},
		},
	},
	{
		ID:           "rootbeer",
		Title:        "RootBeer root-detection bypass",
		Category:     "root_detection",
		Platform:     "android",
		DetectSource: []string{"com.scottyab.rootbeer", "RootBeer", "isRooted"},
		Java: []JavaHook{
			{Class: "com.scottyab.rootbeer.RootBeer", Method: "isRooted", Ret: "false", Kind: "flip"},
		},
	},
}

// ApplicableBypasses returns the registry entries whose DetectLibs match the APK's
// native libs or whose DetectSource signals appear in the provided source signals
// (as computed by the planner's decompiled-source scan).
func ApplicableBypasses(facts *staticx.Facts, sourceSignals []string) []Bypass {
	var out []Bypass
	libs := ""
	if facts != nil {
		libs = strings.ToLower(strings.Join(facts.NativeLibs, "\n"))
	}
	sig := strings.ToLower(strings.Join(sourceSignals, "\n"))
	for _, b := range BuiltinBypasses {
		if matchesAny(libs, b.DetectLibs) || matchesAny(sig, b.DetectSource) {
			out = append(out, b)
		}
	}
	return out
}

// BypassByID returns the registry entry with the given id, or false.
func BypassByID(id string) (Bypass, bool) {
	for _, b := range BuiltinBypasses {
		if b.ID == id {
			return b, true
		}
	}
	return Bypass{}, false
}

func matchesAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(haystack, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// GenerateFridaBypassScript emits a self-contained Frida script that installs every
// hook in the given bypasses: native byte-pattern scans (with graceful retry while the
// target module loads) and Java-layer hooks. Emitting each ANDROIDLAB_EVENT line lets
// the agent confirm which hooks actually fired, so it can tell "applied" from "the app
// pins elsewhere" — the exact distinction that mattered during manual testing.
func GenerateFridaBypassScript(bypasses []Bypass) string {
	var b strings.Builder
	b.WriteString("'use strict';\n")
	b.WriteString("var __n=0; function emit(e){ if(__n++<1500) console.log('ANDROIDLAB_EVENT '+JSON.stringify(e)); }\n")

	// Native hooks grouped by module: one retrying scanner per module.
	type nh struct {
		b Bypass
		h NativeHook
	}
	byModule := map[string][]nh{}
	var javaAll []struct {
		b Bypass
		h JavaHook
	}
	for _, bp := range bypasses {
		for _, h := range bp.Native {
			byModule[h.Module] = append(byModule[h.Module], nh{bp, h})
		}
		for _, h := range bp.Java {
			javaAll = append(javaAll, struct {
				b Bypass
				h JavaHook
			}{bp, h})
		}
	}

	for module, hooks := range byModule {
		fmt.Fprintf(&b, "(function(){ var tries=0; var id=setInterval(function(){ tries++;\n")
		fmt.Fprintf(&b, "  var m=null; try{ m=Process.findModuleByName(%q); }catch(e){}\n", module)
		b.WriteString("  if(!m){ if(tries>40) clearInterval(id); return; }\n")
		b.WriteString("  var ranges=[]; try{ ranges=m.enumerateRanges('r-x'); }catch(e){}\n")
		b.WriteString("  var any=false;\n")
		b.WriteString("  var pats=[\n")
		for _, x := range hooks {
			arch := x.h.Arch
			fmt.Fprintf(&b, "    {id:%q,arch:%q,sig:%q,onleave:%q},\n", x.b.ID, arch, x.h.Pattern, x.h.OnLeave)
		}
		b.WriteString("  ];\n")
		b.WriteString("  pats.forEach(function(p){ if(p.arch && p.arch!==Process.arch) return;\n")
		b.WriteString("    ranges.forEach(function(r){ try{ Memory.scanSync(r.base,r.size,p.sig).forEach(function(hit){\n")
		b.WriteString("      try{ Interceptor.attach(hit.address,{ onLeave:function(retval){ " + "/*action*/" + " eval(p.onleave); } });\n")
		b.WriteString("        any=true; emit({kind:'ssl_bypass_applied', hook:p.id, module:m.name, addr:hit.address.toString()});\n")
		b.WriteString("      }catch(e){ emit({kind:'limitation', detail:'attach failed '+p.id+': '+e}); }\n")
		b.WriteString("    }); }catch(e){} }); });\n")
		fmt.Fprintf(&b, "  if(any || tries>40){ if(!any) emit({kind:'limitation', detail:'no pattern matched in %s (protection may use a different path)'}); clearInterval(id); }\n", module)
		b.WriteString("}, 250); })();\n")
	}

	if len(javaAll) > 0 {
		b.WriteString("if(typeof Java!=='undefined' && Java.available){ Java.perform(function(){\n")
		for _, x := range javaAll {
			switch x.h.Kind {
			case "flip":
				ret := "false"
				if x.h.Ret == "true" {
					ret = "true"
				}
				fmt.Fprintf(&b, "  try{ var C=Java.use(%q); (C[%q].overloads||[C[%q]]).forEach(function(ov){ ov.implementation=function(){ emit({kind:'ssl_bypass_applied',hook:%q}); return %s; }; }); }catch(e){}\n",
					x.h.Class, x.h.Method, x.h.Method, x.b.ID, ret)
			default: // pinning_swallow
				fmt.Fprintf(&b, "  try{ var C=Java.use(%q); ['%s','%s$okhttp','check$okhttp'].forEach(function(mn){ if(!C[mn]) return; C[mn].overloads.forEach(function(ov){ ov.implementation=function(){ try{ return ov.apply(this,arguments); }catch(e){ if(!/Certificate|SSLPeerUnverified|CertPath/.test(String(e))) throw e; emit({kind:'ssl_bypass_applied',hook:%q}); return; } }; }); }); }catch(e){}\n",
					x.h.Class, x.h.Method, x.h.Method, x.b.ID)
			}
		}
		b.WriteString("}); }\n")
	}
	return b.String()
}
