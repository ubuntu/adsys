package testutils

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// WaitForWrites waits for test I/O to be picked up.
//
// Windows doesn't have a syscall.Sync function, so the next best thing to do is
// to force a walk of the directory to make sure the writes are picked up.
// Otherwise the watcher could detect changes just as soon as it starts walking
// paths.
func WaitForWrites(t *testing.T, dirs ...string) {
	t.Helper()

	for _, dir := range dirs {
		filepath.WalkDir(dir, func(_ string, _ os.DirEntry, _ error) error { return nil })
	}
	time.Sleep(time.Millisecond * 100)
}
