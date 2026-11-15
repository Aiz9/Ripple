package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// smokeEnv makes smoke-test child processes skip Bootstrap explicitly.
//
// Children run artex.new and otherwise derive .new-prefixed paths that happen not to touch
// real update files, but relying on that coincidence is brittle.
// Explicit bypass is clearer and avoids unnecessary child disk probes.
const smokeEnv = "ANDROIDLAB_SELFUPDATE_SMOKE"

// Action is Bootstrap's instruction to main.
type Action int

const (
	// Continue starts the server normally.
	Continue Action = iota
	// Restart exits immediately with ExitRestart for supervisor relaunch.
	Restart
)

// State describes this startup's upgrade status for /api/update/check,
// accurately reporting previous success or rollback to the UI.
type State struct {
	Pending     bool   // Replaced binary not yet confirmed stable.
	RolledBack  bool   // Automatic rollback performed at this startup.
	FailedStage bool   // Staged version discarded after validation/smoke failure.
	Detail      string // One-sentence user explanation.
}

// Run Bootstrap at the beginning of main, before listeners or DB connections.
//
// Three startup cases:
//
// 1. artex.new exists: verify/smoke, replace and restart on success, otherwise discard and continue old.
// 2. Marker only: replacement just occurred; count attempt and roll back after repeated failures.
// 3. Neither exists: normal startup.
func Bootstrap() (Action, State) {
	if os.Getenv(smokeEnv) != "" {
		return Continue, State{}
	}
	p, err := ResolvePaths()
	if err != nil {
		log.Printf("[update] skipping bootstrap: %v", err)
		return Continue, State{}
	}

	if _, err := os.Stat(p.New); err == nil {
		return applyStaged(p)
	}

	m, ok := readMarker(p.Marker)
	if !ok {
		return Continue, State{}
	}
	return confirmOrRollback(p, m)
}

// applyStaged validates/replaces staged binaries or discards invalid ones.
//
// Sole executable-overwrite point and final gate: smoke testing blocks corruption, wrong
// architecture, and missing dynamic dependencies. An unexecutable replacement would loop
// forever under the supervisor without Go code ever running to roll back.
func applyStaged(p Paths) (Action, State) {
	m, _ := readMarker(p.Marker)

	if err := verifyStaged(p); err != nil {
		log.Printf("[update] staged version failed validation; discarded, continuing with current version: %v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "New version failed validation and was discarded: " + err.Error()}
	}

	if err := swap(p); err != nil {
		log.Printf("[update] replacement failed; continuing with current version: %v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "Replacement failed: " + err.Error()}
	}

	// Replacement succeeded; retain marker for the new version's next startup to confirm stability.
	m.Attempts = 0
	if m.StagedAt == 0 {
		m.StagedAt = time.Now().Unix()
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] failed to write upgrade marker (automatic rollback unavailable): %v", err)
	}
	log.Printf("[update] replaced with %s; exiting to restart (exit %d)", orUnknown(m.To), ExitRestart)
	return Restart, State{Pending: true}
}

// confirmOrRollback counts post-replacement starts and restores the backup after the limit.
//
// Go must execute to increment the count; this covers initialization crashes from incompatible
// config, busy ports, or migration failures. Pre-replacement smoke tests cover inability to exec,
// completing the two-stage protection.
func confirmOrRollback(p Paths, m marker) (Action, State) {
	m.Attempts++
	if m.Attempts > maxAttempts {
		if err := rollback(p); err != nil {
			// If rollback itself fails, clear marker and avoid infinite restarts; start current state so
			// users can see the actual failure in logs.
			log.Printf("[update] new version failed %d consecutive starts and rollback failed: %v", maxAttempts, err)
			_ = os.Remove(p.Marker)
			return Continue, State{Detail: "New version failed to start and rollback failed: " + err.Error()}
		}
		log.Printf("[update] new version failed %d consecutive starts; rolled back to %s, exiting to restart (exit %d)",
			maxAttempts, orUnknown(m.From), ExitRestart)
		_ = os.Remove(p.Marker)
		return Restart, State{RolledBack: true, Detail: fmt.Sprintf("New version failed to start; rolled back to %s", orUnknown(m.From))}
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] failed to update upgrade marker: %v", err)
	}
	log.Printf("[update] new version starting (attempt %d/%d); upgrade will be confirmed after stable operation",
		m.Attempts, maxAttempts)
	return Continue, State{Pending: true}
}

// Settle confirms stable operation and clears the upgrade marker.
//
// main calls it after HTTP has listened long enough; early crashes preserve marker so starts
// continue counting toward rollback.
func Settle() {
	p, err := ResolvePaths()
	if err != nil {
		return
	}
	settle(p)
}

func settle(p Paths) {
	if _, ok := readMarker(p.Marker); !ok {
		return // Ordinary non-upgrade start has nothing to settle.
	}
	if err := os.Remove(p.Marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("[update] failed to clear upgrade marker: %v", err)
		return
	}
	log.Printf("[update] new version is stable; upgrade complete (previous version retained at %s)", p.Old)
}

// SettleDelay is the required survival time for confirming a new version.
const SettleDelay = 30 * time.Second

// verifyStaged checks SHA256 then actually executes the staged binary.
func verifyStaged(p Paths) error {
	want, err := os.ReadFile(p.Sum)
	if err != nil {
		return fmt.Errorf("Read checksum: %w", err)
	}
	got, err := fileSHA256(p.New)
	if err != nil {
		return fmt.Errorf("Calculate checksum: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(want)), got) {
		return errors.New("SHA256 mismatch (download corrupted or tampered with)")
	}
	return smokeTest(p.New)
}

// smokeTest runs -h to verify execution on this system.
// Catches truncated downloads, wrong architecture/exec format, and missing dependencies.
func smokeTest(bin string) error {
	if err := os.Chmod(bin, 0o755); err != nil {
		return fmt.Errorf("Set executable permission: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "-h")
	cmd.Env = append(os.Environ(), smokeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return errors.New("Smoke test timed out (new binary unresponsive)")
	}
	if err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 300 {
			snippet = snippet[:300] + "…"
		}
		return fmt.Errorf("Smoke test failed: %v: %s", err, snippet)
	}
	return nil
}

// swap replaces current binary with staged version.
//
// Both Unix and Windows permit renaming running executables; Windows forbids deletion/overwrite,
// not rename, so no platform split or pre-emptive self-stop is needed.
func swap(p Paths) error {
	// Windows rename cannot overwrite destinations; remove .old left from the prior upgrade first.
	if err := os.Remove(p.Old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Remove old backup %s: %w", p.Old, err)
	}
	if err := os.Rename(p.Current, p.Old); err != nil {
		return fmt.Errorf("Back up current version: %w", err)
	}
	if err := os.Rename(p.New, p.Current); err != nil {
		// If installation fails after moving current aside, restore it so the next start has an executable.
		if rerr := os.Rename(p.Old, p.Current); rerr != nil {
			return fmt.Errorf("Failed to install new version (%v) and restore current version: %w", err, rerr)
		}
		return fmt.Errorf("Install new version: %w", err)
	}
	_ = os.Remove(p.Sum)
	return nil
}

// rollback reinstalls the old version backed up by swap.
func rollback(p Paths) error {
	if _, err := os.Stat(p.Old); err != nil {
		return fmt.Errorf("No rollback backup %s: %w", p.Old, err)
	}
	// Retain failed new binaries at .failed for diagnosis instead of deleting them.
	failed := p.Current + ".failed"
	_ = os.Remove(failed)
	if err := os.Rename(p.Current, failed); err != nil {
		return fmt.Errorf("Move failed version aside: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		return fmt.Errorf("Restore old version: %w", err)
	}
	return nil
}

// Rollback implements manual /api/update/rollback.
// Replace only; caller then exits ExitRestart and supervisor relaunches.
func Rollback() error {
	p, err := ResolvePaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p.Old); err != nil {
		return errors.New("No previous version to roll back to (" + p.Old + " does not exist)")
	}
	cleanStaged(p)
	if err := smokeTest(p.Old); err != nil {
		return fmt.Errorf("Previous version is not executable; refusing rollback: %w", err)
	}
	// Exchange current/backup to permit rolling forward again after rollback.
	tmp := p.Current + ".swap"
	_ = os.Remove(tmp)
	if err := os.Rename(p.Current, tmp); err != nil {
		return fmt.Errorf("Move current version aside: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		_ = os.Rename(tmp, p.Current)
		return fmt.Errorf("Install previous version: %w", err)
	}
	if err := os.Rename(tmp, p.Old); err != nil {
		log.Printf("[update] failed to organize backups after rollback (operation unaffected): %v", err)
	}
	_ = os.Remove(p.Marker)
	return nil
}

// HasBackup controls whether the UI offers manual rollback.
func HasBackup() bool {
	p, err := ResolvePaths()
	if err != nil {
		return false
	}
	_, err = os.Stat(p.Old)
	return err == nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "Unknown version"
	}
	return s
}
