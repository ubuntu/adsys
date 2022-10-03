package mount

import (
	"flag"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/testutils"
	"gopkg.in/yaml.v3"
)

var Update bool

func TestParseEntryValues(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entry string
	}{
		// Single entry cases.
		"parse values from entry with one value":        {entry: "entry with one value"},
		"parse values from entry with multiple values":  {entry: "entry with multiple values"},
		"parse values from entry with repeatead values": {entry: "entry with repeatead values"},

		// Badly formatted entries.
		"parse values trimming whitespaces":           {entry: "entry with spaces"},
		"parse values trimming sequential linebreaks": {entry: "entry with multiple linebreaks"},

		// Special cases.
		"parse values from entry with anonymous tags": {entry: "entry with anonymous tags"},
		"returns empty slice if the entry is empty":   {entry: "entry with no value"},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := parseEntryValues(EntriesForTests[tc.entry])

			gotPath := t.TempDir()
			m, err := yaml.Marshal(c)
			require.NoError(t, err, "Setup: Failed to marshal the result")

			err = os.WriteFile(filepath.Join(gotPath, "parsed_values"), m, 0600)
			require.NoError(t, err, "Setup: Failed to write the result")

			goldenPath := filepath.Join("testdata", t.Name(), "golden")
			testutils.CompareTreesWithFiltering(t, gotPath, goldenPath, Update)
		})
	}
}

func TestWriteFileWithUIDGID(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		uid     string
		gid     string
		content string

		readOnlyDir       bool
		pathAlreadyExists bool

		wantErr bool
	}{
		"write file with current user ownership": {},

		"error when invalid uid":                               {uid: "-150", wantErr: true},
		"error when invalid gid":                               {gid: "-150", wantErr: true},
		"fails when writing on a dir with invalid permissions": {readOnlyDir: true, wantErr: true},
		// "error when path already exists and has different ownership": {pathAlreadyExists: true, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			u, err := user.Current()
			require.NoError(t, err, "Setup: failed to get current user")

			path := t.TempDir()

			uid := u.Uid
			if tc.uid != "" {
				uid = tc.uid
			}

			gid := u.Gid
			if tc.gid != "" {
				gid = tc.gid
			}

			if tc.readOnlyDir {
				testutils.MakeReadOnly(t, path)
			}

			iUID, err := strconv.Atoi(uid)
			require.NoError(t, err, "Setup: Failed to convert uid to int")
			iGID, err := strconv.Atoi(gid)
			require.NoError(t, err, "Setup: Failed to convert gid to int")

			filePath := filepath.Join(path, "test_write")

			if tc.pathAlreadyExists {
				err = os.WriteFile(filePath, []byte("file already existed"), 0600)
				require.NoError(t, err, "Setup: Failed to set up pre existent file for testing")

				err = os.Chown(filePath, iUID+1, iGID+1)
				require.NoError(t, err, "Setup: Failed to change file ownership for testing")

				t.Cleanup(func() {
					//nolint:errcheck // This happens in a controlled environment
					_ = os.Chown(filePath, iUID, iGID)
					//nolint:errcheck // This happens in a controlled environment
					_ = os.Remove(filePath)
				})
			}

			err = writeFileWithUIDGID(filePath, iUID, iGID, "testing writeFileWithUIDGID file")
			if tc.wantErr {
				require.Error(t, err, "Expected an error but got none")
				return
			}
			require.NoError(t, err, "Expected no error but got one")

			s, err := os.Stat(filePath)
			require.NoError(t, err, "Failed when fetching info of the written file")

			//nolint:forcetypeassert // This happens in a controlled environment
			gotUID := s.Sys().(*syscall.Stat_t).Uid
			//nolint:forcetypeassert // This happens in a controlled environment
			gotGID := s.Sys().(*syscall.Stat_t).Gid

			require.Equal(t, iUID, int(gotUID), "Expected UID to be the same")
			require.Equal(t, iGID, int(gotGID), "Expected GID to be the same")

			testutils.CompareTreesWithFiltering(t, path, filepath.Join("testdata", t.Name(), "golden"), Update)
		})
	}
}

func TestMain(m *testing.M) {
	flag.BoolVar(&Update, "update", false, "Update the golden files")
	flag.Parse()
	m.Run()
}
