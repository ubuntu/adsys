package testutils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
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

// WantError asserts the error value depending if an error is wanted and stops the test if requested.
func WantError(t *testing.T, err error, wantErr, stopOnError bool) {
	t.Helper()

	if wantErr {
		require.Error(t, err, "Expected %s to return an error, but it didn't", t.Name())
		if stopOnError {
			t.SkipNow()
		}
		return
	}
	require.NoError(t, err, "Expected %s to not return an error, but it did", t.Name())
}
