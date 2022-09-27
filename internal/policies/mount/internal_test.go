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
		path        string
		nEntries    int
		nErrored    int
		nValues     int
		nDuplicated int
		separators  []string

		wantErr bool
	}{
		"write mounts file with multiple entries":                          {nEntries: 5, nValues: 1},
		"write mounts file with values separated by ','":                   {nEntries: 1, nValues: 5, separators: []string{","}},
		"write mounts file with values separated by '\n'":                  {nEntries: 1, nValues: 5},
		"write mounts file with values separated by ',' and '\n'":          {nEntries: 1, nValues: 5, separators: []string{",", "\n"}},
		"write mounts file with values deduplicated from values":           {nEntries: 1, nValues: 5, nDuplicated: 3},
		"write mounts file with values deduplicated from multiple entries": {nEntries: 3, nValues: 5, nDuplicated: 3},

		// "errored entries should not be added": {nEntries: 5, nErrored: 3, nValues: 2},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mountsPath := filepath.Join(t.TempDir(), "mounts")

			if len(tc.separators) == 0 {
				tc.separators = append(tc.separators, "\n")
			}

			err := writeMountsFile(context.Background(), GetEntries(tc.nEntries, tc.nErrored, tc.nValues, tc.nDuplicated, tc.separators), WithMountsFilePath(mountsPath))
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
