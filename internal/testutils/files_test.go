package testutils_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestCompareTreesWithFilteringIgnoresDconfDatabases(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		signature string
	}{
		"Ignores little-endian dconf database":           {signature: "GVariant"},
		"Ignores big-endian dconf database, as on s390x": {signature: "raVGtnai"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, gold := t.TempDir(), t.TempDir()
			for _, root := range []string{got, gold} {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "db", "machine.d"), 0750), "Setup: can't create keyfile directory")
				require.NoError(t, os.WriteFile(filepath.Join(root, "db", "machine.d", "adsys"), []byte("[org/example]\nkey=1\n"), 0600),
					"Setup: can't write keyfile")
			}
			require.NoError(t, os.WriteFile(filepath.Join(got, "db", "machine"), []byte(tc.signature+"compiled database"), 0600),
				"Setup: can't write compiled database")

			testutils.CompareTreesWithFiltering(t, got, gold, false)

			updatedGold := filepath.Join(t.TempDir(), "golden")
			testutils.CompareTreesWithFiltering(t, got, updatedGold, true)
			require.NoFileExists(t, filepath.Join(updatedGold, "db", "machine"), "Compiled database should not be added to golden files")
		})
	}
}
