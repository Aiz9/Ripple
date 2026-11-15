package devicelab

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// StoredFile is one file from the approved package's storage areas.
type StoredFile struct {
	Path        string `json:"path"`
	Size        int    `json:"size"`
	Mode        string `json:"mode"`
	WorldAccess bool   `json:"world_access"`
	External    bool   `json:"external"`
	Content     []byte `json:"-"`
}

// StorageRoots lists only the approved package's own storage locations.
func (d *Device) StorageRoots() []string {
	return []string{
		"/data/data/" + d.Package + "/shared_prefs",
		"/data/data/" + d.Package + "/databases",
		"/data/data/" + d.Package + "/files",
		"/sdcard/Android/data/" + d.Package,
	}
}

func (d *Device) allowedPath(p string) bool {
	p = path.Clean(p)
	for _, root := range d.StorageRoots() {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

var lsLine = regexp.MustCompile(`^([-dlrwxsStT]{10})\S*\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+(.+)$`)

// SnapshotStorage reads files (each ≤ 2 MiB, total ≤ 32 MiB) from the approved
// package's storage roots. Private roots need root; external storage does not.
func (d *Device) SnapshotStorage(ctx context.Context) ([]StoredFile, []string) {
	files := []StoredFile{}
	notes := []string{}
	total := 0
	for _, root := range d.StorageRoots() {
		external := strings.HasPrefix(root, "/sdcard/")
		run := d.rootShell
		if external && !d.HasRoot() {
			run = d.shell
		}
		out, err := run(ctx, "find", root, "-type", "f", "-size", "-2048k")
		if err != nil {
			if !strings.Contains(out, "No such file") {
				notes = append(notes, fmt.Sprintf("%s not readable: %v", root, err))
			}
			continue
		}
		for _, p := range strings.Split(strings.TrimSpace(out), "\n") {
			p = strings.TrimSpace(p)
			if p == "" || !d.allowedPath(p) || len(files) >= 400 {
				continue
			}
			f := StoredFile{Path: p, External: external}
			if ls, err := run(ctx, "ls", "-ln", p); err == nil {
				if m := lsLine.FindStringSubmatch(strings.TrimSpace(ls)); m != nil {
					f.Mode = m[1]
					f.Size, _ = strconv.Atoi(m[2])
					f.WorldAccess = m[1][7] == 'r' || m[1][8] == 'w'
				}
			}
			content, err := d.readFile(ctx, p)
			if err != nil {
				notes = append(notes, "cannot read "+p)
				continue
			}
			if total+len(content) > 32<<20 {
				notes = append(notes, "storage snapshot budget reached")
				return files, notes
			}
			total += len(content)
			f.Content = content
			if f.Size == 0 {
				f.Size = len(content)
			}
			files = append(files, f)
		}
	}
	return files, notes
}

func (d *Device) readFile(ctx context.Context, p string) ([]byte, error) {
	if !d.allowedPath(p) {
		return nil, fmt.Errorf("path outside the approved package")
	}
	args := []string{"exec-out", "cat", shellQuote(p)}
	if d.rootMode == "su" {
		args = []string{"exec-out", "su", "0", "cat", shellQuote(p)}
	}
	out, err := d.ADB(ctx, 30*time.Second, args...)
	return []byte(out), err
}

// CanaryHit is one occurrence of a known marker in collected data.
type CanaryHit struct {
	Hash     string `json:"hash"`
	Location string `json:"location"`
	Excerpt  string `json:"excerpt"`
}

// FindCanaries returns every known canary found in data, with a bounded,
// redacted excerpt around each hit.
func FindCanaries(data []byte, location string, canaries map[string]string, redact func(string) string) []CanaryHit {
	hits := []CanaryHit{}
	for value, hash := range canaries {
		i := bytes.Index(data, []byte(value))
		if i < 0 {
			continue
		}
		// Adjacent bytes may contain credentials unrelated to this canary.
		// Persist only the synthetic marker and its offset, never those bytes.
		excerpt := fmt.Sprintf("canary %s matched at byte %d", value, i)
		if redact != nil {
			excerpt = redact(excerpt)
		}
		hits = append(hits, CanaryHit{Hash: hash, Location: location, Excerpt: excerpt})
	}
	return hits
}

// IsJavaSerialized reports the Java serialization stream magic.
func IsJavaSerialized(b []byte) bool { return len(b) > 4 && b[0] == 0xAC && b[1] == 0xED }

// DumpSQLite renders up to 200 rows per table of a pulled SQLite database.
func DumpSQLite(content []byte) (string, error) {
	if !bytes.HasPrefix(content, []byte("SQLite format 3\x00")) {
		return "", fmt.Errorf("not a SQLite database")
	}
	tmp, err := os.CreateTemp("", "devicelab-db-*.sqlite")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()
	db, err := sql.Open("sqlite", "file:"+tmp.Name()+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer db.Close()
	tables, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'android_metadata' ORDER BY name`)
	if err != nil {
		return "", err
	}
	names := []string{}
	for tables.Next() {
		var n string
		if tables.Scan(&n) == nil {
			names = append(names, n)
		}
	}
	tables.Close()
	var b strings.Builder
	for _, n := range names {
		rows, err := db.Query(`SELECT * FROM "` + strings.ReplaceAll(n, `"`, `""`) + `" LIMIT 200`)
		if err != nil {
			continue
		}
		cols, _ := rows.Columns()
		fmt.Fprintf(&b, "table %s (%s)\n", n, strings.Join(cols, ", "))
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if rows.Scan(ptrs...) != nil {
				continue
			}
			parts := make([]string, len(vals))
			for i, v := range vals {
				parts[i] = clip(fmt.Sprint(v), 200)
				if bs, ok := v.([]byte); ok {
					parts[i] = clip(string(bs), 200)
				}
			}
			b.WriteString("  " + strings.Join(parts, " | ") + "\n")
		}
		rows.Close()
	}
	return b.String(), nil
}

// LogcatForApp returns log lines written by the approved package's UID.
// Unique per-run canaries distinguish this assessment without clearing or
// resizing the device-wide log buffers.
func (d *Device) LogcatForApp(ctx context.Context, uid int) (string, error) {
	if uid <= 0 {
		return "", fmt.Errorf("unknown app uid")
	}
	out, err := d.ADB(ctx, 30*time.Second, "logcat", "-d", "--uid="+strconv.Itoa(uid), "-v", "threadtime")
	if err != nil && out == "" {
		// Older logcat without --uid: fall back to the current PID.
		if pid := d.PID(ctx); pid > 0 {
			return d.ADB(ctx, 30*time.Second, "logcat", "-d", "--pid="+strconv.Itoa(pid), "-v", "threadtime")
		}
	}
	return out, err
}
