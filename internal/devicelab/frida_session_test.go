package devicelab

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFridaReusesExistingDaemonWithoutOwnership(t *testing.T) {
	d, _ := New("device", "com.example", "", func(_ context.Context, name string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		if name == "frida" || strings.Contains(line, "--version") {
			return "17.22.2", nil
		}
		if strings.Contains(line, "ps -A") {
			return "root 123 frida-server", nil
		}
		if strings.Contains(line, "getprop") {
			return "x86_64", nil
		}
		t.Fatal("changed an existing daemon: " + line)
		return "", nil
	})
	d.rootMode = "su"
	dir := t.TempDir()
	s, err := d.startFridaServer(t.Context(), "", dir)
	if err != nil || s != nil {
		t.Fatal("preexisting server was not reused without ownership")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("preexisting daemon was added to cleanup journal")
	}
}

func TestFridaFailedCleanupRetainsJournalAndRejectsCorruptIdentity(t *testing.T) {
	d, _ := New("device", "com.example", "", func(context.Context, string, ...string) (string, error) {
		return "", errors.New("offline")
	})
	d.rootMode = "su"
	dir := t.TempDir()
	s, err := d.newFridaSession(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(t.Context()); !errors.Is(err, errOwnedFridaCleanup) {
		t.Fatal("cleanup failure was not reported")
	}
	if _, err := os.Stat(s.journal); err != nil {
		t.Fatal("lost crash-recovery journal")
	}
	if err = os.WriteFile(s.journal, []byte(`{"serial":"other","remote_pid_file":"/proc/1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	d.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("corrupt recovery issued device commands")
		return "", nil
	}
	if d.RecoverFrida(t.Context(), dir) == nil {
		t.Fatal("corrupt recovery identity accepted")
	}
}

// Execute the actual cleanup script against disposable host processes, verifying
// PID reuse and a different executable cannot cause an unrelated process kill.
func TestFridaCleanupChecksKernelStartTimeAndExecutable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux /proc process fixture")
	}
	fixturePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"owned", "reused-pid", "foreign-executable"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			binary := filepath.Join(dir, "frida-server")
			raw, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(binary, raw, 0700); err != nil {
				t.Fatal(err)
			}
			program := binary
			if kind == "foreign-executable" {
				program = fixturePath
			}
			proc := exec.Command(program, "-test.run=^TestFridaDaemonFixture$")
			proc.Env = append(os.Environ(), "ARTEX_TEST_FRIDA_DAEMON=1")
			var diagnostic bytes.Buffer
			proc.Stderr = &diagnostic
			if err = proc.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- proc.Wait() }()
			t.Cleanup(func() { _ = proc.Process.Kill() })
			stat, err := os.ReadFile("/proc/" + strconv.Itoa(proc.Process.Pid) + "/stat")
			if err != nil {
				t.Fatal(err)
			}
			start := strings.Fields(string(stat))[21]
			if kind == "reused-pid" {
				start = "0"
			}
			s := &FridaSession{RemotePIDFile: "/data/local/tmp/artex-frida-" + strings.Repeat("a", 32) + ".pid"}
			pidFile := strings.ReplaceAll(s.RemotePIDFile, "/data/local/tmp", dir)
			if err = os.WriteFile(pidFile, []byte(strconv.Itoa(proc.Process.Pid)+" "+start+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			script := strings.ReplaceAll(s.cleanupScript(), "/data/local/tmp", dir)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput(); err != nil {
				t.Fatalf("cleanup script failed: %v %s", err, out)
			}
			select {
			case exitErr := <-done:
				if kind != "owned" {
					t.Fatalf("unrelated process exited: %v %s", exitErr, diagnostic.String())
				}
			default:
				if kind == "owned" {
					t.Fatal("owned daemon survived cleanup")
				}
				_ = proc.Process.Kill()
				<-done
			}
		})
	}
}

func TestFridaDaemonFixture(t *testing.T) {
	if os.Getenv("ARTEX_TEST_FRIDA_DAEMON") == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}
