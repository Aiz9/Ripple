// Package devicelab drives one authorized Android device for one approved,
// hash-verified package. Every operation is bound to the device serial and the
// package; callers (including the UI explorer's LLM tools) never supply shell
// text, device paths outside the package sandbox, or other package names.
package devicelab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	packagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$`)
	serialPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	componentName  = regexp.MustCompile(`^[A-Za-z0-9_.$]+$`)
	apkPathPattern = regexp.MustCompile(`^/data/app/[A-Za-z0-9_./=~+-]+\.apk$`)
)

// Command runs a host program. It is injectable for deterministic tests.
type Command func(ctx context.Context, name string, args ...string) (string, error)

// Device is bound to one serial and one approved package.
type Device struct {
	Serial  string
	Package string
	APKSHA  string
	Run     Command
	// rootMode is "adbd" (adb shell is uid 0), "su" (su binary) or "" (none).
	rootMode string
	sdk      int
}

// New validates identifiers; it performs no device I/O.
func New(serial, pkg, apkSHA string, run Command) (*Device, error) {
	if !serialPattern.MatchString(serial) || !packagePattern.MatchString(pkg) {
		return nil, fmt.Errorf("invalid device serial or package")
	}
	if run == nil {
		run = Execute
	}
	return &Device{Serial: serial, Package: pkg, APKSHA: apkSHA, Run: run}, nil
}

type boundedBuffer struct {
	buf   bytes.Buffer
	limit int
	cut   bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := b.limit - b.buf.Len(); room < len(p) {
		if room > 0 {
			b.buf.Write(p[:room])
		}
		b.cut = true
	} else {
		b.buf.Write(p)
	}
	return n, nil
}

// Execute runs a host command with bounded output (4 MiB).
func Execute(ctx context.Context, name string, args ...string) (string, error) {
	out := &boundedBuffer{limit: 4 << 20}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if out.cut && err == nil {
		err = fmt.Errorf("output truncated at 4 MiB")
	}
	return out.buf.String(), err
}

// ADB runs adb against this serial with a per-call deadline.
func (d *Device) ADB(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.Run(c, "adb", append([]string{"-s", d.Serial}, args...)...)
}

// shell runs a fixed command line built by this package. Arguments are quoted
// for the device shell; callers outside the package cannot reach it.
func (d *Device) shell(ctx context.Context, args ...string) (string, error) {
	return d.ADB(ctx, 30*time.Second, append([]string{"shell"}, quoteAll(args)...)...)
}

// rootShell runs a fixed command as root.
func (d *Device) rootShell(ctx context.Context, args ...string) (string, error) {
	switch d.rootMode {
	case "adbd":
		return d.shell(ctx, args...)
	case "su":
		return d.ADB(ctx, 30*time.Second, "shell", "su", "0", "sh", "-c", shellQuote(strings.Join(quoteAll(args), " ")))
	}
	return "", fmt.Errorf("root is not available on %s", d.Serial)
}

// UnprivilegedShell runs a fixed command as the shell user (uid 2000), which
// stands in for "any other app" when proving exported-component exposure.
func (d *Device) UnprivilegedShell(ctx context.Context, args ...string) (string, error) {
	if d.rootMode == "adbd" {
		return d.ADB(ctx, 30*time.Second, "shell", "su", "2000", "sh", "-c", shellQuote(strings.Join(quoteAll(args), " ")))
	}
	return d.shell(ctx, args...)
}

func quoteAll(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = shellQuote(a)
	}
	return out
}

var safeShellWord = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

func shellQuote(s string) string {
	if s != "" && safeShellWord.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// DetectRoot records how root can be obtained. It never enables root itself.
func (d *Device) DetectRoot(ctx context.Context) string {
	if out, err := d.shell(ctx, "id", "-u"); err == nil && strings.TrimSpace(out) == "0" {
		d.rootMode = "adbd"
		return d.rootMode
	}
	if out, err := d.ADB(ctx, 10*time.Second, "shell", "su", "0", "id", "-u"); err == nil && strings.TrimSpace(out) == "0" {
		d.rootMode = "su"
		return d.rootMode
	}
	d.rootMode = ""
	return ""
}

// HasRoot reports the result of the last DetectRoot.
func (d *Device) HasRoot() bool { return d.rootMode != "" }

// Prop reads one system property.
func (d *Device) Prop(ctx context.Context, name string) string {
	if !regexp.MustCompile(`^[a-z0-9_.]+$`).MatchString(name) {
		return ""
	}
	out, _ := d.shell(ctx, "getprop", name)
	return strings.TrimSpace(out)
}

// SDK returns the device API level (cached).
func (d *Device) SDK(ctx context.Context) int {
	if d.sdk == 0 {
		d.sdk, _ = strconv.Atoi(d.Prop(ctx, "ro.build.version.sdk"))
	}
	return d.sdk
}

// Online reports whether adb sees the device in the "device" state.
func (d *Device) Online(ctx context.Context) bool {
	out, err := d.ADB(ctx, 10*time.Second, "get-state")
	return err == nil && strings.TrimSpace(out) == "device"
}

// InstalledAPKPath returns the base APK path of the approved package.
func (d *Device) InstalledAPKPath(ctx context.Context) string {
	out, err := d.shell(ctx, "pm", "path", d.Package)
	if err != nil {
		return ""
	}
	chosen := ""
	for _, line := range strings.Fields(out) {
		p := strings.TrimPrefix(line, "package:")
		if apkPathPattern.MatchString(p) && (chosen == "" || strings.HasSuffix(p, "/base.apk")) {
			chosen = p
		}
	}
	return chosen
}

// InstalledSHA256 hashes the installed base APK. It uses the device's
// sha256sum and falls back to pulling the file when that is unavailable.
func (d *Device) InstalledSHA256(ctx context.Context) (string, error) {
	path := d.InstalledAPKPath(ctx)
	if path == "" {
		return "", fmt.Errorf("package not installed")
	}
	if out, err := d.shell(ctx, "sha256sum", path); err == nil {
		if f := strings.Fields(out); len(f) > 0 && len(f[0]) == 64 {
			return f[0], nil
		}
	}
	tmp, err := os.CreateTemp("", "devicelab-apk-*.apk")
	if err != nil {
		return "", err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if _, err := d.ADB(ctx, 120*time.Second, "pull", path, tmp.Name()); err != nil {
		return "", fmt.Errorf("pull installed APK: %w", err)
	}
	return fileSHA256(tmp.Name())
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 512<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// EnsureInstalled verifies the installed build by hash on every run (also when
// already installed) and reinstalls the approved APK on mismatch.
func (d *Device) EnsureInstalled(ctx context.Context, apkPath string) (string, error) {
	want, err := fileSHA256(apkPath)
	if err != nil || want != d.APKSHA {
		return "", fmt.Errorf("approved APK integrity check failed")
	}
	if got, err := d.InstalledSHA256(ctx); err == nil && got == d.APKSHA {
		return "verified installed build (hash match, no reinstall)", nil
	}
	out, err := d.ADB(ctx, 180*time.Second, "install", "-r", "-g", "--no-streaming", apkPath)
	if err != nil || !strings.Contains(out, "Success") {
		return "", fmt.Errorf("install failed: %s", strings.TrimSpace(lastLine(out)))
	}
	got, err := d.InstalledSHA256(ctx)
	if err != nil || got != d.APKSHA {
		return "", fmt.Errorf("installed APK differs from the approved artifact after reinstall")
	}
	return "reinstalled approved APK after hash mismatch; installed hash verified", nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// UID returns the Linux UID of the approved package.
func (d *Device) UID(ctx context.Context) int {
	out, _ := d.shell(ctx, "cmd", "package", "list", "packages", "-U", d.Package)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "package:"+d.Package && strings.HasPrefix(fields[1], "uid:") {
			n, _ := strconv.Atoi(strings.TrimPrefix(fields[1], "uid:"))
			return n
		}
	}
	return 0
}

// PackageFlags returns the dumpsys package flags line(s) of the approved package.
func (d *Device) PackageFlags(ctx context.Context) string {
	out, _ := d.shell(ctx, "dumpsys", "package", d.Package)
	lines := []string{}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "flags=[") || strings.HasPrefix(t, "pkgFlags=[") || strings.HasPrefix(t, "privateFlags=[") {
			lines = append(lines, t)
		}
	}
	return strings.Join(lines, "\n")
}

// ForceStop stops the approved package.
func (d *Device) ForceStop(ctx context.Context) error {
	_, err := d.shell(ctx, "am", "force-stop", d.Package)
	return err
}

// Launch starts the package's launcher activity.
func (d *Device) Launch(ctx context.Context) (string, error) {
	out, err := d.shell(ctx, "cmd", "package", "resolve-activity", "--brief", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", d.Package)
	component := ""
	for _, line := range strings.Fields(out) {
		if strings.HasPrefix(line, d.Package+"/") {
			component = line
		}
	}
	if err != nil || component == "" {
		return "", fmt.Errorf("no launcher activity")
	}
	if _, err := d.shell(ctx, "am", "start", "-W", "-n", component); err != nil {
		return "", err
	}
	return component, nil
}

// StartActivity starts one of the approved package's own activities.
func (d *Device) StartActivity(ctx context.Context, activity string) (string, error) {
	activity = d.qualify(activity)
	if !componentName.MatchString(activity) || !strings.HasPrefix(activity, d.Package+".") && !strings.Contains(activity, ".") {
		return "", fmt.Errorf("invalid activity")
	}
	return d.shell(ctx, "am", "start", "-W", "-n", d.Package+"/"+activity)
}

func (d *Device) qualify(name string) string {
	if strings.HasPrefix(name, ".") {
		return d.Package + name
	}
	return name
}

// PID returns the main process ID of the approved package (0 when not running).
func (d *Device) PID(ctx context.Context) int {
	out, _ := d.shell(ctx, "pidof", d.Package)
	f := strings.Fields(out)
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(f[0])
	return n
}

// resumedPattern also matches the window-manager focus fields (mCurrentFocus /
// mFocusedApp), so CurrentActivity can fall back to `dumpsys window` when the
// activity dump does not expose a resumed line (varies by build/emulator).
var resumedPattern = regexp.MustCompile(`(?:mResumedActivity|topResumedActivity|ResumedActivity|mCurrentFocus|mFocusedApp)[:=].*?\s([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)`)

// foregroundFromDump extracts "package/activity" from a dumpsys block.
func foregroundFromDump(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if m := resumedPattern.FindStringSubmatch(line); m != nil {
			act := m[2]
			if strings.HasPrefix(act, ".") {
				act = m[1] + act
			}
			return m[1] + "/" + act
		}
	}
	return ""
}

// CurrentActivity returns "package/activity" of the resumed/focused activity,
// trying the activity dump first and the window dump as a fallback.
func (d *Device) CurrentActivity(ctx context.Context) string {
	for _, cmd := range [][]string{
		{"dumpsys", "activity", "activities"},
		{"dumpsys", "window"},
	} {
		out, _ := d.shell(ctx, cmd...)
		if a := foregroundFromDump(out); a != "" {
			return a
		}
	}
	return ""
}

// ForegroundPackage returns just the package owning the foreground activity.
func (d *Device) ForegroundPackage(ctx context.Context) string {
	act := d.CurrentActivity(ctx)
	if i := strings.IndexByte(act, '/'); i > 0 {
		return act[:i]
	}
	return ""
}

// systemFlowPackages are OS surfaces that legitimately appear during the approved
// app's own flow — runtime-permission prompts, the package installer, system UI —
// so UI input on them is part of driving the target, not pivoting to another app.
var systemFlowPackages = map[string]bool{
	"com.google.android.permissioncontroller": true,
	"com.android.permissioncontroller":        true,
	"com.android.packageinstaller":            true,
	"com.android.systemui":                    true,
}

// InForeground reports whether the approved package owns the foreground activity.
func (d *Device) InForeground(ctx context.Context) bool {
	return strings.HasPrefix(d.CurrentActivity(ctx), d.Package+"/")
}

// InteractAllowed reports whether UI input is permitted on the current foreground:
// the approved package, or a system surface that is part of its own flow (so a
// runtime-permission dialog does not dead-end the login). Unrelated third-party
// apps and the launcher are still refused.
func (d *Device) InteractAllowed(ctx context.Context) (string, bool) {
	pkg := d.ForegroundPackage(ctx)
	return pkg, pkg == d.Package || systemFlowPackages[pkg]
}

// interactBlockedErr is the actionable error returned when the foreground is not
// an interactable surface, naming what is in front so the agent can recover.
func (d *Device) interactBlockedErr(pkg string) error {
	if pkg == "" {
		pkg = "unknown"
	}
	return fmt.Errorf("UI input blocked: foreground is %q, not the approved app %q — call mobile_launch_app to bring it forward, or press Back/Home via mobile_ui_key to leave the other screen", pkg, d.Package)
}
