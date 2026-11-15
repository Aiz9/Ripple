package devicelease

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestLeaseHelperProcess(t *testing.T) {
	mode := os.Getenv("ARTEX_LEASE_HELPER")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	lease, err := Acquire(ctx, os.Getenv("ARTEX_LEASE_SERIAL"))
	if mode == "busy" {
		if err == nil {
			lease.Release()
			os.Exit(3)
		}
		return
	}
	if err != nil {
		os.Exit(4)
	}
	defer lease.Release()
	if mode == "hold" {
		fmt.Println("locked")
		time.Sleep(30 * time.Second)
	}
}

func helper(t *testing.T, mode, serial string) *exec.Cmd {
	t.Helper()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-test.run=^TestLeaseHelperProcess$")
	cmd.Env = append(os.Environ(), "ARTEX_LEASE_HELPER="+mode, "ARTEX_LEASE_SERIAL="+serial)
	return cmd
}

func isolatedCache(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("LOCALAPPDATA", dir)
	// macOS UserCacheDir uses HOME/Library/Caches.
	// XDG_CACHE_HOME and LOCALAPPDATA cover the supported CI hosts without
	// repurposing the user's HOME environment variable.
}

func TestLeaseSerializesProcessesAndCancellation(t *testing.T) {
	isolatedCache(t)
	serial := fmt.Sprintf("test-%d", time.Now().UnixNano())
	lease, err := Acquire(context.Background(), serial)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if out, err := helper(t, "busy", serial).CombinedOutput(); err != nil {
		t.Fatalf("second process did not respect lease: %v %s", err, out)
	}
	other, err := Acquire(context.Background(), serial+"-other")
	if err != nil {
		t.Fatal(err)
	}
	other.Release()
	lease.Release()
	lease.Release()
	if out, err := helper(t, "free", serial).CombinedOutput(); err != nil {
		t.Fatalf("release did not free device: %v %s", err, out)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if l, err := Acquire(ctx, serial); err == nil {
		l.Release()
		t.Fatal("cancelled acquisition succeeded")
	}
}

func TestLeaseRecoversAfterOwnerProcessDies(t *testing.T) {
	isolatedCache(t)
	serial := fmt.Sprintf("crash-%d", time.Now().UnixNano())
	cmd := helper(t, "hold", serial)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	ready := make(chan bool, 1)
	go func() { scanner := bufio.NewScanner(stdout); ready <- scanner.Scan() && scanner.Text() == "locked" }()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("owner did not acquire lease")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owner startup timed out")
	}
	cmd.Process.Kill()
	cmd.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := Acquire(ctx, serial)
	if err != nil {
		t.Fatalf("process death left a stale device lease: %v", err)
	}
	lease.Release()
}
