package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/Aiz9/ripple/internal/devicelab"
)

// No-root adb UI-automation tools for the task agent.
//
// These bring the deterministic devicelab UI primitives (dump / tap / swipe /
// type / key / launch) into the LLM task flow so the agent can actually drive
// an app on an attached emulator or device — a Genymotion Android 11 image, for
// example — WITHOUT root. They only expose constrained input primitives (no
// arbitrary `adb shell`), and they target a single scoped device. Root-gated
// capabilities (Frida instrumentation, system-CA MITM, egress isolation) are
// intentionally NOT here; mobile_device_status reports the device's root/API so
// the agent knows what is and isn't possible.
//
// Device selection: ANDROIDLAB_RUNTIME_DEVICE if set, otherwise the single adb
// device in state "device". Ambiguity (more than one) is refused so the agent
// never drives the wrong phone.

// placeholderPackage is a pattern-valid package for primitives that do not care
// which app owns the screen (dump/tap/swipe/status). Package-scoped primitives
// (type/key/launch) require the real package as an argument.
const placeholderPackage = "com.android.shell"

// noopResolver satisfies devicelab.Resolver for literal (non-credential) typing.
type noopResolver struct{}

func (noopResolver) Resolve(string, string) (string, bool) { return "", false }
func (noopResolver) Redact(s string) string                { return s }

func resolveMobileSerial(ctx context.Context) (string, error) {
	if s := strings.TrimSpace(os.Getenv("ANDROIDLAB_RUNTIME_DEVICE")); s != "" {
		return s, nil
	}
	out, err := devicelab.Execute(ctx, "adb", "devices")
	if err != nil {
		return "", fmt.Errorf("adb devices failed: %w", err)
	}
	var online []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == "device" {
			online = append(online, f[0])
		}
	}
	switch len(online) {
	case 0:
		return "", fmt.Errorf("no attached device in state 'device' (check `adb devices`; start your Genymotion/emulator first)")
	case 1:
		return online[0], nil
	default:
		return "", fmt.Errorf("multiple devices attached (%s); set ANDROIDLAB_RUNTIME_DEVICE to choose one", strings.Join(online, ", "))
	}
}

// mobileDevice resolves the serial and builds a devicelab.Device. pkg may be ""
// for primitives that do not need package ownership.
func (t *ToolSet) mobileDevice(ctx context.Context, pkg string) (*devicelab.Device, error) {
	serial, err := resolveMobileSerial(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(pkg) == "" {
		pkg = placeholderPackage
	}
	return devicelab.New(serial, pkg, "", devicelab.Execute)
}

func (t *ToolSet) mobileDeviceStatus() actool.CoreTool {
	return readTool("mobile_device_status",
		"Report the attached device used for UI automation: serial, online state, Android API level, and root mode. No root is required for dump/tap/swipe/type/launch; Frida instrumentation, system-CA TLS interception and egress isolation DO require root and are unavailable without it.",
		obj(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			dev, err := t.mobileDevice(ctx, "")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			online := dev.Online(cctx)
			rootMode := dev.DetectRoot(cctx)
			if rootMode == "" {
				rootMode = "none"
			}
			out, _ := json.Marshal(map[string]any{
				"serial": dev.Serial, "online": online, "android_api": dev.SDK(cctx),
				"root_mode": rootMode, "has_root": dev.HasRoot(),
				"note": "No root: UI automation and app-scoped observation work; Frida/pinning-bypass, system-CA MITM and egress isolation are unavailable.",
			})
			return actool.Text(string(out)), nil
		})
}

func (t *ToolSet) mobileUIDump() actool.CoreTool {
	return readTool("mobile_ui_dump",
		"Dump the device's current screen as a compact UI tree (uiautomator). Returns actionable nodes with a stable `ref`, text/desc, class, bounds [x1,y1,x2,y2], and flags (clickable/editable/scrollable). Use a node's ref with mobile_ui_type, or its bounds center with mobile_ui_tap.\n"+
			"A dump/screenshot reflects ONLY the moment it was taken. A session can expire or the app can navigate away between steps, so never rely on a prior capture as evidence for a finding — re-dump and confirm the current screen's identity (title/known text) first. If you cannot positively identify the screen a capture shows, do not cite it; recapture or mark the step blocked.",
		obj(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			dev, err := t.mobileDevice(ctx, "")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			screen, err := dev.DumpUI(cctx)
			if err != nil {
				return actool.Errorf("ui dump failed: " + err.Error()), nil
			}
			out, _ := json.Marshal(screen)
			return actool.Text(string(out)), nil
		})
}

func (t *ToolSet) mobileLaunchApp() actool.CoreTool {
	return writeTool("mobile_launch_app",
		"Launch the given package's main launcher activity on the device (am start). Use the target app's package name.",
		obj(map[string]any{"package": strField("Android package name, e.g. com.example.app")}, "package"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Package string }
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dev, err := t.mobileDevice(ctx, a.Package)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			component, err := dev.Launch(cctx)
			if err != nil {
				return actool.Errorf("launch failed: " + err.Error()), nil
			}
			return actool.Text("launched " + component), nil
		})
}

func (t *ToolSet) mobileUITap() actool.CoreTool {
	return writeTool("mobile_ui_tap",
		"Tap the screen at pixel coordinates (x,y). Compute the center of a node's bounds from mobile_ui_dump: x=(x1+x2)/2, y=(y1+y2)/2.",
		obj(map[string]any{"x": intField("X pixel"), "y": intField("Y pixel")}, "x", "y"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ X, Y int }
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dev, err := t.mobileDevice(ctx, "")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if err := dev.Tap(cctx, a.X, a.Y); err != nil {
				return actool.Errorf("tap failed: " + err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("tapped (%d,%d)", a.X, a.Y)), nil
		})
}

func (t *ToolSet) mobileUISwipe() actool.CoreTool {
	return writeTool("mobile_ui_swipe",
		"Swipe/scroll from (x1,y1) to (x2,y2). To scroll down, swipe from a lower y to a higher y near the screen center.",
		obj(map[string]any{"x1": intField("start X"), "y1": intField("start Y"), "x2": intField("end X"), "y2": intField("end Y")}, "x1", "y1", "x2", "y2"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ X1, Y1, X2, Y2 int }
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dev, err := t.mobileDevice(ctx, "")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if err := dev.Swipe(cctx, a.X1, a.Y1, a.X2, a.Y2); err != nil {
				return actool.Errorf("swipe failed: " + err.Error()), nil
			}
			return actool.Text("swiped"), nil
		})
}

func (t *ToolSet) mobileUIType() actool.CoreTool {
	return writeTool("mobile_ui_type",
		"Type literal text into an editable field identified by its `ref` from mobile_ui_dump. Requires the target app's package (the field must belong to it). Do not include credential placeholders; pass the actual value. The field is focused and cleared first.",
		obj(map[string]any{"package": strField("Android package the field belongs to"), "ref": intField("Node ref from mobile_ui_dump"), "text": strField("Literal text to type (single line, <=512 chars)")}, "package", "ref", "text"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Package, Text string
				Ref           int
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dev, err := t.mobileDevice(ctx, a.Package)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			screen, err := dev.DumpUI(cctx)
			if err != nil {
				return actool.Errorf("ui dump failed: " + err.Error()), nil
			}
			var target *devicelab.Node
			for i := range screen.Nodes {
				if screen.Nodes[i].Ref == a.Ref {
					target = &screen.Nodes[i]
					break
				}
			}
			if target == nil {
				return actool.Errorf(fmt.Sprintf("no node with ref=%d on the current screen; re-dump and use a current ref", a.Ref)), nil
			}
			msg, err := dev.TypeText(cctx, *target, a.Text, noopResolver{})
			if err != nil {
				return actool.Errorf("type failed: " + err.Error()), nil
			}
			return actool.Text(msg), nil
		})
}

func (t *ToolSet) mobileUIKey() actool.CoreTool {
	return writeTool("mobile_ui_key",
		"Send a key event while the given package is in the foreground. Supported: back, home, enter, tab, escape.",
		obj(map[string]any{"package": strField("Android package expected in the foreground"), "key": strField("One of: back, home, enter, tab, escape")}, "package", "key"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Package, Key string }
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dev, err := t.mobileDevice(ctx, a.Package)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if err := dev.Key(cctx, strings.ToLower(strings.TrimSpace(a.Key))); err != nil {
				return actool.Errorf("key failed: " + err.Error()), nil
			}
			return actool.Text("sent key " + a.Key), nil
		})
}
