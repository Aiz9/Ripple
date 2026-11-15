package devicelab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// NetState is persisted before the device is changed so that a crashed run is
// reverted by the next preflight. It holds no secrets.
type NetState struct {
	Serial        string    `json:"serial"`
	PreviousProxy string    `json:"previous_proxy"`
	ReversePort   int       `json:"reverse_port"`
	CAMounted     bool      `json:"ca_mounted"`
	LogBuffer     string    `json:"log_buffer,omitempty"`
	ChangedAt     time.Time `json:"changed_at"`
}

func statePath(dir, serial string) string {
	safe := strings.NewReplacer(":", "_", "/", "_").Replace(serial)
	return filepath.Join(dir, safe+".json")
}

func (d *Device) saveState(dir string, s NetState) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(s)
	return os.WriteFile(statePath(dir, d.Serial), raw, 0o600)
}

func loadState(dir, serial string) (NetState, bool) {
	raw, err := os.ReadFile(statePath(dir, serial))
	if err != nil {
		return NetState{}, false
	}
	var s NetState
	if json.Unmarshal(raw, &s) != nil {
		return NetState{}, false
	}
	return s, true
}

// GlobalProxy returns the current global HTTP proxy setting ("" when unset).
func (d *Device) GlobalProxy(ctx context.Context) string {
	out, _ := d.shell(ctx, "settings", "get", "global", "http_proxy")
	v := strings.TrimSpace(out)
	if v == "null" || v == ":0" {
		return ""
	}
	return v
}

// NetSession routes the device's traffic through the host recording proxy and
// trusts its CA as a system CA. Revert restores the previous configuration.
type NetSession struct {
	d        *Device
	stateDir string
	state    NetState
	Notes    []string
}

// CAMounted reports whether the recording proxy CA was mounted into the system trust store.
func (s *NetSession) CAMounted() bool {
	return s != nil && s.state.CAMounted
}

// StartNetwork installs the CA (when root is available) and points the global
// proxy at hostPort through `adb reverse`, so the proxy can stay on loopback.
func (d *Device) StartNetwork(ctx context.Context, stateDir string, hostPort int, caPEM string) (*NetSession, error) {
	if hostPort <= 0 || hostPort > 65535 {
		return nil, fmt.Errorf("invalid proxy port")
	}
	s := &NetSession{d: d, stateDir: stateDir, state: NetState{Serial: d.Serial, PreviousProxy: d.GlobalProxy(ctx), ReversePort: hostPort, ChangedAt: time.Now().UTC()}}
	if prior, ok := loadState(stateDir, d.Serial); ok {
		// A crashed run left state behind: keep its original "previous" value.
		s.state.PreviousProxy = prior.PreviousProxy
		s.state.CAMounted = prior.CAMounted
	}
	if err := d.saveState(stateDir, s.state); err != nil {
		return nil, fmt.Errorf("persist device state: %w", err)
	}
	port := strconv.Itoa(hostPort)
	if _, err := d.ADB(ctx, 10*time.Second, "reverse", "tcp:"+port, "tcp:"+port); err != nil {
		return s, fmt.Errorf("adb reverse failed: %w", err)
	}
	if _, err := d.shell(ctx, "settings", "put", "global", "http_proxy", "127.0.0.1:"+port); err != nil {
		return s, fmt.Errorf("set global proxy: %w", err)
	}
	s.Notes = append(s.Notes, "Global HTTP proxy set to 127.0.0.1:"+port+" via adb reverse (previous: "+orNone(s.state.PreviousProxy)+")")
	if caPEM != "" {
		if err := d.installSystemCA(ctx, caPEM); err != nil {
			s.Notes = append(s.Notes, "System CA not installed: "+err.Error()+"; TLS traffic of apps that do not trust user CAs cannot be decrypted")
		} else {
			s.state.CAMounted = true
			_ = d.saveState(stateDir, s.state)
			s.Notes = append(s.Notes, "Recording proxy CA trusted as a system CA (tmpfs overlay, reverted at the end of the run)")
		}
	}
	return s, nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// Revert restores proxy and CA state. It is safe to call more than once.
func (s *NetSession) Revert(ctx context.Context) error {
	if s == nil {
		return nil
	}
	return s.d.revertState(ctx, s.stateDir, s.state)
}

// RecoverStale reverts device changes left by a crashed earlier run.
func (d *Device) RecoverStale(ctx context.Context, stateDir string) (bool, error) {
	st, ok := loadState(stateDir, d.Serial)
	if !ok {
		return false, nil
	}
	return true, d.revertState(ctx, stateDir, st)
}

func (d *Device) revertState(ctx context.Context, stateDir string, st NetState) error {
	var errs []string
	if st.PreviousProxy == "" {
		if _, err := d.shell(ctx, "settings", "put", "global", "http_proxy", ":0"); err != nil {
			errs = append(errs, "reset proxy: "+err.Error())
		}
		_, _ = d.shell(ctx, "settings", "delete", "global", "http_proxy")
	} else if _, err := d.shell(ctx, "settings", "put", "global", "http_proxy", st.PreviousProxy); err != nil {
		errs = append(errs, "restore proxy: "+err.Error())
	}
	if st.ReversePort > 0 {
		_, _ = d.ADB(ctx, 10*time.Second, "reverse", "--remove", "tcp:"+strconv.Itoa(st.ReversePort))
	}
	if st.CAMounted && d.HasRoot() {
		if err := d.removeSystemCA(ctx); err != nil {
			errs = append(errs, "remove CA overlay: "+err.Error())
		}
	}
	if st.LogBuffer != "" {
		_, _ = d.shell(ctx, "logcat", "-G", st.LogBuffer)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	if stateDir != "" {
		_ = os.Remove(statePath(stateDir, d.Serial))
	}
	return nil
}

const caStage = "/data/local/tmp/artex-ca"

// subjectHashOld computes the OpenSSL subject_hash_old used for system CA names.
func subjectHashOld(ctx context.Context, pem string) (string, error) {
	out, err := exec.CommandContext(ctx, "openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-noout", "-in", pem).Output()
	if err != nil {
		return "", fmt.Errorf("openssl subject hash: %w", err)
	}
	h := strings.TrimSpace(string(out))
	if len(h) != 8 {
		return "", fmt.Errorf("unexpected subject hash %q", h)
	}
	return h, nil
}

// SystemCATrusted reports whether the CA is present in the active system store.
func (d *Device) SystemCATrusted(ctx context.Context, caPEM string) bool {
	h, err := subjectHashOld(ctx, caPEM)
	if err != nil {
		return false
	}
	dir := "/system/etc/security/cacerts"
	if d.SDK(ctx) >= 34 {
		dir = "/apex/com.android.conscrypt/cacerts"
	}
	out, _ := d.shell(ctx, "ls", dir+"/"+h+".0")
	return strings.Contains(out, h+".0") && !strings.Contains(out, "No such file")
}

// installSystemCA overlays the system CA directory with a tmpfs copy that
// includes the recording proxy CA. On Android 14+ the conscrypt APEX copy is
// bind-mounted into the zygote mount namespaces as well.
func (d *Device) installSystemCA(ctx context.Context, caPEM string) error {
	if !d.HasRoot() {
		return fmt.Errorf("root unavailable")
	}
	if d.SystemCATrusted(ctx, caPEM) {
		return nil
	}
	h, err := subjectHashOld(ctx, caPEM)
	if err != nil {
		return err
	}
	if _, err := d.rootShell(ctx, "mkdir", "-p", caStage); err != nil {
		return err
	}
	if _, err := d.ADB(ctx, 30*time.Second, "push", caPEM, caStage+"/"+h+".0"); err != nil {
		return fmt.Errorf("push CA: %w", err)
	}
	script := `set -e
S=` + caStage + `
cp /system/etc/security/cacerts/* $S/ 2>/dev/null || true
mount -t tmpfs tmpfs /system/etc/security/cacerts
cp $S/* /system/etc/security/cacerts/
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/* 2>/dev/null || true`
	if d.SDK(ctx) >= 34 {
		script += `
for Z in $(pidof zygote zygote64); do nsenter --mount=/proc/$Z/ns/mnt -- mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts; done
mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts`
	}
	if out, err := d.rootShell(ctx, "sh", "-c", script); err != nil {
		return fmt.Errorf("mount CA overlay: %v %s", err, strings.TrimSpace(out))
	}
	if !d.SystemCATrusted(ctx, caPEM) {
		return fmt.Errorf("CA not visible after overlay")
	}
	// Running processes cached the old trust store.
	_ = d.ForceStop(ctx)
	return nil
}

func (d *Device) removeSystemCA(ctx context.Context) error {
	script := `umount /system/etc/security/cacerts 2>/dev/null || true`
	if d.SDK(ctx) >= 34 {
		script = `for Z in $(pidof zygote zygote64); do nsenter --mount=/proc/$Z/ns/mnt -- umount /apex/com.android.conscrypt/cacerts 2>/dev/null; done; umount /apex/com.android.conscrypt/cacerts 2>/dev/null; ` + script
	}
	script += `; rm -rf ` + caStage
	_, err := d.rootShell(ctx, "sh", "-c", script)
	_ = d.ForceStop(ctx)
	return err
}
