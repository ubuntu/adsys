// TiCS: disabled // Test helpers.

package testutils

import (
	"os"
	"testing"
)

// SkipUnlessRoot skips the test if the current user is not root.
// The function is a no-op on Windows.
func SkipUnlessRoot(t *testing.T) {
	t.Helper()

	// We use > 0 to allow Windows to pass through
	if os.Geteuid() > 0 {
		t.Skip("Test has to be run as root, skipping...")
	}
}
