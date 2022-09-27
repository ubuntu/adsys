package mount

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var update bool

func TestWriteMountsFile(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path     string
		nEntries int
		nErrored int

		wantErr bool
	}{
		"write mounts file":                   {nEntries: 5},
		"errored entries should not be added": {nEntries: 5, nErrored: 3},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mountsPath := filepath.Join(t.TempDir(), "mounts")

			err := writeMountsFile(context.Background(), GetEntries(tc.nEntries, tc.nErrored), WithMountsFilePath(mountsPath))
			require.NoError(t, err, "Expected no error but got one")

			b, err := os.ReadFile(mountsPath)
			require.NoError(t, err, "Expected to read the mounts file with no error")

			got := string(b)
			if update {
				dir := filepath.Join("testdata", t.Name())
				err := os.MkdirAll(dir, os.ModePerm)
				require.NoError(t, err, "Expected no error when creating dir for golden files")

				err = os.WriteFile(filepath.Join(dir, "mounts"), b, os.ModePerm)
				require.NoError(t, err, "Expected no error but got one")
			}

			b, err = os.ReadFile(filepath.Join("testdata", t.Name(), "mounts"))
			require.NoError(t, err, "Expected no error but got one")

			want := string(b)
			require.Equal(t, want, got, "Expected files to be the same")
		})
	}
}
