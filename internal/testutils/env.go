package testutils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Setenv sets and restore an env variable upon test completion.
func Setenv(t *testing.T, k, v string) {
	t.Helper()

	orig, existed := os.LookupEnv(k)

	err := os.Setenv(k, v)
	require.NoError(t, err, "Setup: can’t set environment for %s", k)
	t.Cleanup(func() {
		if !existed {
			err = os.Unsetenv(k)
			require.NoError(t, err, "Teardown: can’t unset environment for %s", k)
			return
		}
		err = os.Setenv(k, orig)
		require.NoError(t, err, "Teardown: can’t restore current environment for %s", k)
	})
}
