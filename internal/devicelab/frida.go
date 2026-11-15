package devicelab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// FridaEvent is one JSON line emitted by an instrumentation script.
type FridaEvent map[string]any

// FridaCheck reports client availability and the server version on the device.
type FridaCheck struct {
	ClientVersion string
	ServerVersion string
	ServerRunning bool
	ArchOK        bool
}

// CheckFrida verifies the client is installed, the server runs on the device and
// its version matches the client.
func (d *Device) CheckFrida(ctx context.Context) (FridaCheck, error) {
	var fc FridaCheck
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := d.Run(checkCtx, "frida", "--version")
	if err != nil {
		return fc, fmt.Errorf("frida client not installed: %w", err)
	}
	fc.ClientVersion = strings.TrimSpace(out)
	server, err := d.shell(checkCtx, "/data/local/tmp/frida-server", "--version")
	if err != nil {
		return fc, fmt.Errorf("cannot verify on-device frida-server version: %w", err)
	}
	fc.ServerVersion = strings.TrimSpace(server)
	abi := d.Prop(ctx, "ro.product.cpu.abi")
	fc.ArchOK = strings.Contains(abi, "x86_64") || strings.Contains(abi, "arm64") || strings.Contains(abi, "x86") || strings.Contains(abi, "arm")
	ps, _ := d.shell(ctx, "ps", "-A")
	fc.ServerRunning = strings.Contains(ps, "frida-server")
	if fc.ClientVersion == "" || fc.ClientVersion != fc.ServerVersion {
		return fc, fmt.Errorf("Frida client/server version mismatch: client %s, server %s", fc.ClientVersion, fc.ServerVersion)
	}
	return fc, nil
}

// startFridaServer reuses an existing server without taking ownership. When it
// starts a new server it journals that process for exact, crash-safe cleanup.
func (d *Device) startFridaServer(ctx context.Context, serverPath, stateDir string) (*FridaSession, error) {
	if ps, _ := d.shell(ctx, "ps", "-A"); strings.Contains(ps, "frida-server") {
		_, err := d.CheckFrida(ctx)
		return nil, err
	}
	if !d.HasRoot() {
		return nil, fmt.Errorf("frida-server requires root")
	}
	remote := "/data/local/tmp/frida-server"
	if serverPath != "" {
		if _, err := d.ADB(ctx, 60*time.Second, "push", serverPath, remote); err != nil {
			return nil, fmt.Errorf("push frida-server: %w", err)
		}
	}
	if _, err := d.rootShell(ctx, "chmod", "755", remote); err != nil {
		return nil, err
	}
	session, err := d.newFridaSession(stateDir)
	if err != nil {
		return nil, err
	}
	// Record PID and kernel start time before exec. Cleanup verifies both and
	// the executable path, so PID reuse cannot terminate an unrelated process.
	child := `echo "$$ $(awk '{print $22}' /proc/$$/stat)" > ` + shellQuote(session.RemotePIDFile) + `; exec ` + remote
	_, err = d.rootShell(ctx, "sh", "-c", "nohup sh -c "+shellQuote(child)+" >/dev/null 2>&1 </dev/null &")
	if err != nil {
		return session, fmt.Errorf("start owned frida-server: %w", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if ps, _ := d.shell(ctx, "ps", "-A"); strings.Contains(ps, "frida-server") {
			_, err := d.CheckFrida(ctx)
			return session, err
		}
		select {
		case <-ctx.Done():
			return session, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return session, fmt.Errorf("frida-server did not start")
}

// FridaSpawn launches the approved package under Frida with the given script,
// collects ANDROIDLAB_EVENT lines for the window, and returns parsed events. It
// retries once with backoff on an infrastructure failure (no "ready" event).
func (d *Device) FridaSpawn(ctx context.Context, script string, seconds int, extraConfig map[string]any) ([]FridaEvent, string, error) {
	if seconds < 3 || seconds > 300 {
		return nil, "", fmt.Errorf("instrumentation window must be 3–300 seconds")
	}
	prelude := ""
	if extraConfig != nil {
		cfg, _ := json.Marshal(extraConfig)
		prelude = "const ANDROIDLAB_CONFIG = " + string(cfg) + ";\n"
	}
	tmp, err := os.CreateTemp("", "devicelab-frida-*.js")
	if err != nil {
		return nil, "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(prelude + script); err != nil {
		tmp.Close()
		return nil, "", err
	}
	tmp.Close()
	var lastOut string
	for attempt := 0; attempt < 2; attempt++ {
		runCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds+20)*time.Second)
		out, commandErr := d.Run(runCtx, "frida", "-D", d.Serial, "-f", d.Package, "-l", tmp.Name(), "-q", "-t", strconv.Itoa(seconds), "--runtime=v8")
		cancel()
		lastOut = out
		events := parseFridaEvents(out)
		ready := false
		for _, e := range events {
			groups, _ := e["groups"].(float64)
			if e["kind"] == "hooks_ready" && groups > 0 {
				ready = true
			}
		}
		if ready {
			if commandErr != nil {
				return events, out, fmt.Errorf("observer process did not complete: %w", commandErr)
			}
			return events, out, nil
		}
		if ctx.Err() != nil {
			return events, out, ctx.Err()
		}
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	return parseFridaEvents(lastOut), lastOut, fmt.Errorf("frida observer did not initialize")
}

func parseFridaEvents(out string) []FridaEvent {
	events := []FridaEvent{}
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, "ANDROIDLAB_EVENT ")
		if i < 0 || len(events) >= 2000 {
			continue
		}
		var e FridaEvent
		if json.Unmarshal([]byte(line[i+len("ANDROIDLAB_EVENT "):]), &e) == nil {
			events = append(events, e)
		}
	}
	return events
}

// EventsOfKind filters events by kind.
func EventsOfKind(events []FridaEvent, kind string) []FridaEvent {
	out := []FridaEvent{}
	for _, e := range events {
		if e["kind"] == kind {
			out = append(out, e)
		}
	}
	return out
}
