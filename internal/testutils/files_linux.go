package testutils

import (
	"syscall"
	"testing"
	"time"
)

// WaitForWrites waits for test I/O to be picked up.
func WaitForWrites(t *testing.T, _ ...string) {
	t.Helper()

	// Give time for the writes to be picked up
	syscall.Sync()
	time.Sleep(time.Millisecond * 100)
}
