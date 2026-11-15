// Package selfupdate downloads, verifies, and stages GitHub release binaries for one-click
// ARTEX updates, atomically installing them at next startup.
//
// Responsibilities (start.sh/start.bat):
//
// Supervisor scripts only relaunch by process exit code.
// This package owns downloads, checksums, smoke tests, replacement, and rollback.
//
// Keeping replacement in Go avoids separate sh/bat checksum/smoke implementations
// (sha256sum/shasum/certutil) in the most failure-sensitive step.
// An unexecutable replacement loops under the supervisor until manually repaired.
//
// A complete upgrade uses three starts:
//
// 1. Old server handles apply: download/verify, stage artex.new, exit 75.
// 2. Old binary restarts, Bootstrap verifies/smokes/replaces, exit 75.
// 3. New binary starts, Bootstrap counts attempt, then clears marker after stability.
//
// Stage 2 failure discards staged data and retains old; three failed stage-3 starts before
// settlement automatically restore artex.old.
package selfupdate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ExitRestart (EX_TEMPFAIL) requests immediate supervisor relaunch without crash backoff.
// 0 ends the loop normally; other exits count as crashes.
const ExitRestart = 75

// maxAttempts bounds post-replacement starts: each increments marker count; survival beyond
// settleDelay clears it; repeated crashes restore the old binary.
const maxAttempts = 3

// Paths places all update files alongside the executable.
// Never use CWD, which may be / or arbitrary under service managers, otherwise staging and
// replacement operate in different locations.
type Paths struct {
	Dir     string // Executable directory.
	Current string // Running binary: artex / artex.exe.
	New     string // Staged binary: artex.new / artex.new.exe.
	Sum     string // Staged SHA256 hex: artex.new.sha256 / artex.new.exe.sha256.
	Old     string // Previous backup: artex.old / artex.old.exe.
	Marker  string // Upgrade-state marker: artex.upgrade.json.
}

// ResolvePaths derives paths from the current executable.
//
// Windows staged/backups need .exe too; strip then reappend the suffix for symmetric names,
// preserving smoke-test and installed-binary execution.
func ResolvePaths() (Paths, error) {
	exe, err := os.Executable()
	if err != nil {
		return Paths{}, fmt.Errorf("Locate executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	name := filepath.Base(exe)
	ext := filepath.Ext(name) // .exe on Windows, usually empty on Unix.
	stem := strings.TrimSuffix(name, ext)

	join := func(suffix string) string { return filepath.Join(dir, stem+suffix+ext) }
	return Paths{
		Dir:     dir,
		Current: exe,
		New:     join(".new"),
		Sum:     join(".new") + ".sha256",
		Old:     join(".old"),
		Marker:  filepath.Join(dir, stem+".upgrade.json"),
	}, nil
}

// marker tracks replacement progress to trigger automatic rollback after failed starts.
type marker struct {
	From     string `json:"from"`     // Previous version.
	To       string `json:"to"`       // Target version.
	Attempts int    `json:"attempts"` // Start attempts since replacement.
	StagedAt int64  `json:"staged_at"`
}

func readMarker(path string) (marker, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return marker{}, false
	}
	var m marker
	if json.Unmarshal(b, &m) != nil {
		return marker{}, false
	}
	return m, true
}

func writeMarker(path string, m marker) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// cleanStaged removes staging after success/validation failure/cancellation, preventing leftover
// artex.new from being retried at subsequent startup.
func cleanStaged(p Paths) {
	_ = os.Remove(p.New)
	_ = os.Remove(p.Sum)
}

// CompareVersions returns -1/0/1 for a<b/a==b/a>b.
// ok=false for noncomparable dev or git-describe versions such as 0.3.7-2-gabc1234-dirty;
// disable one-click updates rather than replacing a development build and uncommitted changes
// with a stable release.
func CompareVersions(a, b string) (int, bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range 3 {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// parseVersion accepts v0.3.7/0.3.7 as [3]int.
//
// Require clean three-component versions; non-tag git-describe suffixes must remain
// noncomparable rather than collapsing to 0.3.7, otherwise development builds look current
// or get overwritten by stable binaries.
func parseVersion(s string) ([3]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// InDocker detects containers. Replacement writes their writable layer; compose recreation
// returns to the image version, expected when fetching new images, but the UI must explain
// this persistence boundary.
func InDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	b, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "docker") || strings.Contains(s, "containerd")
}
