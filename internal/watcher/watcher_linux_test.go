package watcher_test

import (
	"syscall"
	"testing"
	"time"
)

// waitForWrites waits for test I/O to be picked up.
func waitForWrites(t *testing.T, _ ...string) {
	t.Helper()

	// Give time for the writes to be picked up
	syscall.Sync()
	time.Sleep(time.Millisecond * 100)
}
