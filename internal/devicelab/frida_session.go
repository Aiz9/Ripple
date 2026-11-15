package devicelab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// FridaSession owns only a daemon started by this run. Preexisting servers
// never receive a session and are never stopped by cleanup.
type FridaSession struct {
	Serial        string `json:"serial"`
	RemotePIDFile string `json:"remote_pid_file"`
	device        *Device
	journal       string
}

var fridaPIDPath = regexp.MustCompile(`^/data/local/tmp/artex-frida-[a-f0-9]{32}\.pid$`)
var errOwnedFridaCleanup = errors.New("owned Frida cleanup incomplete")

func (d *Device) newFridaSession(dir string) (*FridaSession, error) {
	if dir == "" {
		return nil, fmt.Errorf("Frida startup requires a recovery directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	s := &FridaSession{Serial: d.Serial, RemotePIDFile: "/data/local/tmp/artex-frida-" + hex.EncodeToString(nonce[:]) + ".pid", device: d, journal: statePath(dir, d.Serial) + ".frida"}
	raw, _ := json.Marshal(s)
	f, err := os.CreateTemp(dir, ".frida-state-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, err
	}
	if err = os.Rename(f.Name(), s.journal); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FridaSession) Close(ctx context.Context) error {
	if _, err := s.device.rootShell(ctx, "sh", "-c", s.cleanupScript()); err != nil {
		return fmt.Errorf("%w; recovery journal retained: %v", errOwnedFridaCleanup, err)
	}
	if err := os.Remove(s.journal); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %v", errOwnedFridaCleanup, err)
	}
	return nil
}

func (s *FridaSession) cleanupScript() string {
	// The identity comparison and signal occur in one fixed device-side script,
	// using no caller-provided PID or shell text.
	script := `set -e
P=` + shellQuote(s.RemotePIDFile) + `
if [ -f "$P" ]; then
  read PID START < "$P"
  case "$PID" in ''|*[!0-9]*) exit 1;; esac
  case "$START" in ''|*[!0-9]*) exit 1;; esac
  if [ -r "/proc/$PID/stat" ]; then
    CURRENT=$(awk '{print $22}' "/proc/$PID/stat" 2>/dev/null || true)
    EXE=$(readlink "/proc/$PID/exe" || true)
    if [ "$CURRENT" = "$START" ] && [ "$EXE" = /data/local/tmp/frida-server ]; then
      kill -TERM "$PID" || [ ! -r "/proc/$PID/stat" ]
      N=0
      while [ -r "/proc/$PID/stat" ] && [ "$(awk '{print $22}' "/proc/$PID/stat" 2>/dev/null || true)" = "$START" ]; do
        N=$((N+1)); [ "$N" -lt 20 ] || exit 1
        sleep 0.1
      done
    fi
  fi
  rm -f "$P"
fi`
	return script
}

func (d *Device) RecoverFrida(ctx context.Context, dir string) error {
	journal := statePath(dir, d.Serial) + ".frida"
	raw, err := os.ReadFile(journal)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var s FridaSession
	if json.Unmarshal(raw, &s) != nil || s.Serial != d.Serial || !fridaPIDPath.MatchString(s.RemotePIDFile) || strings.Contains(s.RemotePIDFile, "..") {
		return fmt.Errorf("invalid Frida recovery identity")
	}
	s.device, s.journal = d, journal
	return s.Close(ctx)
}
