// Package devicelease coordinates device ownership across host processes.
package devicelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var serialPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type Lease struct {
	file *os.File
	once sync.Once
	err  error
}

// Acquire holds an OS lock for one serial until Release or process death. Lock
// files remain in place: deleting one would let waiters lock different inodes.
// A shared host cache makes CLI and server runs use the same ownership domain,
// independently of their report/data directories.
func Acquire(ctx context.Context, serial string) (*Lease, error) {
	if !serialPattern.MatchString(serial) {
		return nil, fmt.Errorf("invalid device serial")
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(cache, "artex-android", "device-leases")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(serial))
	f, err := os.OpenFile(filepath.Join(dir, hex.EncodeToString(digest[:])+".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			f.Close()
			return nil, fmt.Errorf("device lease wait interrupted: %w", err)
		}
		locked, err := tryLock(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("device lease unavailable: %w", err)
		}
		if locked {
			return &Lease{file: f}, nil
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (l *Lease) Release() error {
	l.once.Do(func() { l.err = errors.Join(unlock(l.file), l.file.Close()) })
	return l.err
}
