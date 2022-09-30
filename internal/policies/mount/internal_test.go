package mount

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/testutils"
)

var Update bool

func TestWriteMountsFile(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path    string
		entries string

		readOnlyDir bool

		wantErr bool
	}{
		// Single entry cases.
		"write mounts file with one entry with one value":        {entries: "one entry with one value"},
		"write mounts file with one entry with multiple values":  {entries: "one entry with multiple values"},
		"write mounts file with one entry with repeatead values": {entries: "one entry with repeatead values"},

		// Multiple entries cases.
		"write mounts file with multiple entries with one value":       {entries: "multiple entries with one value"},
		"write mounts file with multiple entries with multiple values": {entries: "multiple entries with multiple values"},
		"write mounts file with multiple entries with the same value":  {entries: "multiple entries with the same value"},
		"write mounts file with multiple entries with repeated values": {entries: "multiple entries with repeated values"},

		// Badly formatted entries.
		"write mounts file trimming whitespaces":           {entries: "entry with linebreaks and spaces"},
		"write mounts file trimming sequential linebreaks": {entries: "entry with multiple linebreaks"},

		// Special cases.
		"write mounts file with anonymous tags":                                  {entries: "entry with anonymous tags"},
		"write mounts file with values from errored entries should not be added": {entries: "errored entries"},
		"write an empty file if the entry is empty":                              {entries: "one entry with no value"},
		"write an empty file if all entries are empty":                           {entries: "multiple entries with no value"},

		// Error cases.
		"fails when writing on a dir with invalid permissions": {entries: "one entry with one value", readOnlyDir: true, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gotPath := t.TempDir()

			if tc.readOnlyDir {
				err := os.Chmod(gotPath, 0100)
				require.NoError(t, err, "Setup: Expected to change directory permissions for the tests.")

				// Ensures that the test dir will be cleaned after the test.
				defer func(p string) error {
					// nolint:errcheck
					_ = os.Chmod(p, 0750)
					return os.RemoveAll(p)
				}(gotPath)
			}

			err := writeMountsFile(gotPath+"/mounts", EntriesForTests[tc.entries])
			if tc.wantErr {
				require.Error(t, err, "Expected an error when writing mounts file but got none")
				return
			}
			require.NoError(t, err, "Expected no error when writing mounts file but got one")

			goldenPath := filepath.Join("testdata", t.Name(), "golden")
			testutils.CompareTreesWithFiltering(t, gotPath, goldenPath, Update)
		})
	}
}

func TestMain(m *testing.M) {
	flag.BoolVar(&Update, "update", false, "Update the golden files")
	flag.Parse()
	m.Run()
}
