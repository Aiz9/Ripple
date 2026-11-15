package selfupdate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"
)

// sumsAsset is release.yml's checksum manifest covering every release ZIP.
const sumsAsset = "SHA256SUMS"

// maxBinarySize prevents malformed ZIPs filling disk during extraction.
const maxBinarySize = 512 << 20 // 512 MiB

// Phase is exposed directly in SSE event phase.
type Phase string

const (
	PhaseIdle     Phase = "idle"
	PhaseDownload Phase = "downloading"
	PhaseVerify   Phase = "verifying"
	PhaseExtract  Phase = "extracting"
	PhaseStaged   Phase = "staged"
	PhaseFailed   Phase = "failed"
)

// Progress sends frontend updates; pct is 0-100 for downloads,
// -1 for other stages.
type Progress func(ph Phase, pct int, msg string)

// Stage downloads/verifies the current-platform release and stages its binary as artex.new.
//
// Download ZIP rather than bare executable because existing SHA256SUMS covers only ZIPs,
// preserving CI/historical releases, and ZIP skills/ permits future skill synchronization.
// Cost is only a few hundred extra KB of skills.
//
// Success means fully staged; caller then gracefully exits ExitRestart.
func Stage(ctx context.Context, c *http.Client, rel *Release, currentVersion string, prog Progress) error {
	if prog == nil {
		prog = func(Phase, int, string) {}
	}
	p, err := ResolvePaths()
	if err != nil {
		return err
	}
	if err := checkWritable(p.Dir); err != nil {
		return err
	}

	name := AssetName(rel.TagName, runtime.GOOS, runtime.GOARCH)
	asset, ok := rel.FindAsset(name)
	if !ok {
		return fmt.Errorf("This version has no release package for %s/%s (missing %s)", runtime.GOOS, runtime.GOARCH, name)
	}

	prog(PhaseDownload, 0, "Fetching checksum manifest...")
	sums, err := fetchSums(ctx, c, rel)
	if err != nil {
		return err
	}
	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("%s does not list %s; refusing to install an unverified binary", sumsAsset, name)
	}

	// Keep temporary files in destination directory for atomic same-filesystem rename;
	// /tmp may be a separate mount and cross-device rename fails.
	zipPath := p.New + ".zip.part"
	binPath := p.New + ".part"
	defer func() {
		_ = os.Remove(zipPath)
		_ = os.Remove(binPath)
	}()

	prog(PhaseDownload, 0, fmt.Sprintf("Downloading %s (%s)...", name, humanSize(asset.Size)))
	got, err := download(ctx, c, asset, zipPath, prog)
	if err != nil {
		return err
	}

	prog(PhaseVerify, -1, "Verifying SHA256...")
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("SHA256 mismatch: expected %s, got %s (download corrupted or tampered with)", short(want), short(got))
	}

	prog(PhaseExtract, -1, "Extracting and smoke testing...")
	if err := extractBinary(zipPath, binPath); err != nil {
		return err
	}
	if err := smokeTest(binPath); err != nil {
		return fmt.Errorf("New version cannot run on this system: %w", err)
	}

	// Store the staged binary's own checksum for revalidation at next startup, guarding changes
	// or corruption between staging and restart.
	binSum, err := fileSHA256(binPath)
	if err != nil {
		return fmt.Errorf("Calculate new binary checksum: %w", err)
	}
	if err := os.WriteFile(p.Sum, []byte(binSum), 0o644); err != nil {
		return fmt.Errorf("Write checksum: %w", err)
	}
	if err := os.Rename(binPath, p.New); err != nil {
		_ = os.Remove(p.Sum)
		return fmt.Errorf("Stage new version: %w", err)
	}

	if err := writeMarker(p.Marker, marker{
		From:     currentVersion,
		To:       strings.TrimPrefix(rel.TagName, "v"),
		StagedAt: time.Now().Unix(),
	}); err != nil {
		// Marker failure removes rollback protection but does not invalidate staged binary or stop upgrade.
		prog(PhaseStaged, -1, "Warning: failed to write upgrade marker; automatic rollback protection unavailable")
	}

	prog(PhaseStaged, 100, "New version ready; restarting...")
	return nil
}

// fetchSums downloads/parses SHA256SUMS as filename -> hex digest.
func fetchSums(ctx context.Context, c *http.Client, rel *Release) (map[string]string, error) {
	asset, ok := rel.FindAsset(sumsAsset)
	if !ok {
		return nil, fmt.Errorf("Release has no %s; integrity cannot be verified, refusing upgrade", sumsAsset)
	}
	body, err := get(ctx, c, asset.URL)
	if err != nil {
		return nil, fmt.Errorf("Download %s: %w", sumsAsset, err)
	}
	defer body.Close()

	raw, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("Read %s: %w", sumsAsset, err)
	}
	out := parseSums(string(raw))
	if len(out) == 0 {
		return nil, fmt.Errorf("%s is empty or has an unrecognized format", sumsAsset)
	}
	return out, nil
}

// parseSums parses sha256sum-style manifests into filename -> hex digest.
//
// Require a 64-digit hex first field; exactly two fields alone could accept arbitrary prose,
// polluting the digest map and assigning wrong checksums to real assets.
// Validate digest syntax before recording entries.
func parseSums(raw string) map[string]string {
	out := map[string]string{}
	for line := range strings.Lines(raw) {
		// Format: digest, two spaces, filename; shasum binary mode may prefix filename with *.
		// Support both checksum-tool conventions.
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || !isHexSHA256(fields[0]) {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == "" {
			continue
		}
		out[name] = strings.ToLower(fields[0])
	}
	return out
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// download writes dst while hashing SHA256 and reporting Content-Length progress.
func download(ctx context.Context, c *http.Client, a Asset, dst string, prog Progress) (string, error) {
	body, err := get(ctx, c, a.URL)
	if err != nil {
		return "", fmt.Errorf("Download %s: %w", a.Name, err)
	}
	defer body.Close()

	f, err := os.Create(dst)
	if err != nil {
		return "", fmt.Errorf("Create temporary file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	pw := &progressWriter{total: a.Size, prog: prog, name: a.Name, last: time.Now()}
	if _, err := io.Copy(io.MultiWriter(f, h, pw), body); err != nil {
		return "", fmt.Errorf("Download interrupted: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("Failed to save to disk: %w", err)
	}
	if a.Size > 0 && pw.written != a.Size {
		return "", fmt.Errorf("Incomplete download: expected %d bytes, got %d bytes", a.Size, pw.written)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// get issues allowlist-constrained GET and returns its body.
func get(ctx context.Context, c *http.Client, rawURL string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if err := checkURL(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "artex-selfupdate")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// extractBinary retrieves the artex executable from the release ZIP.
//
// Layout is artex-<version>-<os>-<arch>/artex; match basename rather than reconstructing full
// paths with duplicated version text, making extraction resilient to naming changes.
func extractBinary(zipPath, dst string) error {
	want := "artex"
	if runtime.GOOS == "windows" {
		want = "artex.exe"
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("Open release package: %w", err)
	}
	defer zr.Close()

	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() || !strings.EqualFold(path.Base(entry.Name), want) {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return fmt.Errorf("Read %s: %w", entry.Name, err)
		}
		defer rc.Close()

		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return fmt.Errorf("Write new binary: %w", err)
		}
		defer f.Close()

		n, err := io.Copy(f, io.LimitReader(rc, maxBinarySize+1))
		if err != nil {
			return fmt.Errorf("Extract %s: %w", entry.Name, err)
		}
		if n > maxBinarySize {
			return fmt.Errorf("Executable in release package exceeds %s; refusing extraction", humanSize(maxBinarySize))
		}
		if n == 0 {
			return fmt.Errorf("%s in release package is empty", want)
		}
		return f.Sync()
	}
	return fmt.Errorf("%s not found in release package", want)
}

// checkWritable fails early for nonroot/system-directory installs instead of waiting until
// tens of MB have downloaded before discovering replacement cannot write.
func checkWritable(dir string) error {
	probe, err := os.CreateTemp(dir, ".artex-update-probe-*")
	if err != nil {
		return fmt.Errorf("Program directory %s is not writable; automatic update unavailable (check permissions or update manually): %w", dir, err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

// progressWriter counts bytes and rate-limits SSE updates instead of one per 32KiB chunk.
type progressWriter struct {
	total   int64
	written int64
	name    string
	prog    Progress
	last    time.Time
}

func (w *progressWriter) Write(b []byte) (int, error) {
	w.written += int64(len(b))
	if time.Since(w.last) < 300*time.Millisecond {
		return len(b), nil
	}
	w.last = time.Now()
	pct := -1
	if w.total > 0 {
		pct = int(w.written * 100 / w.total)
	}
	w.prog(PhaseDownload, pct, fmt.Sprintf("Downloading %s / %s", humanSize(w.written), humanSize(w.total)))
	return len(b), nil
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12] + "…"
	}
	return sum
}
