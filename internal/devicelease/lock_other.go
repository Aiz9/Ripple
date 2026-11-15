//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package devicelease

import (
	"fmt"
	"os"
)

func tryLock(*os.File) (bool, error) {
	return false, fmt.Errorf("device locking is unsupported on this operating system")
}
func unlock(*os.File) error { return nil }
