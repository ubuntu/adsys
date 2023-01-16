package mount

import (
	"context"
	"flag"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestParseEntryValues(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entry string

		wantErr bool
	}{
		// Single entry cases.
		"Parse values from entry with one value":       {entry: "entry with one value"},
		"Parse values from entry with multiple values": {entry: "entry with multiple values"},
		"Parse values from entry with repeated values": {entry: "entry with repeated values"},

		// Badly formatted entries.
		"Parse values trimming whitespaces":           {entry: "entry with spaces"},
		"Parse values trimming sequential linebreaks": {entry: "entry with multiple linebreaks"},

		// Special cases.
		"Parse values from entry with kerberos auth tags": {entry: "entry with kerberos auth tags"},
		"Returns empty slice if the entry is empty":       {entry: "entry with no value"},

		// Error cases
		"Error when parsing entry with badly formatted values": {entry: "entry with badly formatted value", wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := parseEntryValues(context.Background(), EntriesForTests[tc.entry])
			if tc.wantErr {
				require.Error(t, err, "Expected an error but got none.")
				return
			}
			require.NoError(t, err, "Expected no error but got one.")

			gotStr := strings.Join(got, "\n")
			want := testutils.LoadWithUpdateFromGolden(t, gotStr)
			require.Equal(t, want, gotStr, "Returned value is not what was expected.")
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
		"Write file with current user ownership": {},

		"Error when invalid uid":                               {uid: "-150", wantErr: true},
		"Error when invalid gid":                               {gid: "-150", wantErr: true},
		"Error when writing on a dir with invalid permissions": {readOnlyDir: true, wantErr: true},
		"Error when path already exists as a directory":        {pathAlreadyExists: true, wantErr: true},
	}

	u, err := user.Current()
	require.NoError(t, err, "Setup: failed to get current user")

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

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
				err = os.MkdirAll(filePath, 0750)
				require.NoError(t, err, "Setup: Failed to set up pre existent directory for testing")

				t.Cleanup(func() {
					//nolint:errcheck // We created the folder for the test, so we know this function will not return an error.
					_ = os.Remove(filePath)
				})
			}

			err = writeFileWithUIDGID(filePath, iUID, iGID, "testing writeFileWithUIDGID file")
			if tc.wantErr {
				require.Error(t, err, "writeFileWithUIDGID should have returned an error but didn't")
				return
			}
			require.NoError(t, err, "writeFileWithUIDGID should not have returned an error but did")
			testutils.CompareTreesWithFiltering(t, path, testutils.GoldenPath(t), testutils.Update())
		})
	}
}

func TestCreateUnits(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entry string
	}{
		"Write single unit":      {entry: "entry with one value"},
		"Write multiple units":   {entry: "entry with multiple values"},
		"Write krb5 tagged unit": {entry: "entry with kerberos auth tag"},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parsedValues, err := parseEntryValues(context.Background(), EntriesForTests[tc.entry])
			require.NoError(t, err, "Setup: failed to parse entries for TestCreateUnits.")

			unitPath := t.TempDir()
			units := createUnits(parsedValues)

			for name, content := range units {
				err := os.WriteFile(filepath.Join(unitPath, name), []byte(content), 0600)
				require.NoError(t, err, "Setup: Failed to write unit file for comparison.")
			}

			testutils.CompareTreesWithFiltering(t, unitPath, testutils.GoldenPath(t), testutils.Update())
		})
	}
}

func TestMain(m *testing.M) {
	testutils.InstallUpdateFlag()
	flag.Parse()
	m.Run()
}
