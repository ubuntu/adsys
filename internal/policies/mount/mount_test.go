package mount_test

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/mount"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		invalidPerm bool

		wantErr bool
	}{
		"creates manager successfully": {},

		"creation fails with invalid runDir permissions": {invalidPerm: true, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			runDir := t.TempDir()
			if tc.invalidPerm {
				err := os.Chmod(runDir, 0100)
				require.NoError(t, err, "Expected to be able to change permissions but got an error instead.")
			}

			_, err := mount.New(mount.WithRunDir(runDir))
			if tc.wantErr {
				require.Error(t, err, "Expected an error when creating manager but got none.")
				return
			}
			require.NoError(t, err, "Expected no error when creating manager but got one.")
		})
	}
}

func TestApplyPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entries    string
		objectName string
		computer   bool

		readOnlyUserDir bool

		secondCall      string
		userReturnedUID string
		userReturnedGID string

		wantErr bool
	}{
		// Single entry cases.
		"successfully generates mounts file for one entry with one value":        {},
		"successfully generates mounts file for one entry with multiple values":  {entries: "one entry with multiple values"},
		"successfully generates mounts file for one entry with repeatead values": {entries: "one entry with repeatead values"},

		// Multiple entries cases.
		"successfully generates mounts file for multiple entries with one value":       {entries: "multiple entries with one value"},
		"successfully generates mounts file for multiple entries with multiple values": {entries: "multiple entries with multiple values"},
		"successfully generates mounts file for multiple entries with the same value":  {entries: "multiple entries with the same value"},
		"successfully generates mounts file for multiple entries with repeated values": {entries: "multiple entries with repeated values"},

		// Special cases.
		"successfully generates mounts file for errored entries":   {entries: "errored entries"},
		"successfully generates mounts file with anonymous values": {entries: "entry with anonymous tags"},

		// Badly formatted entries.
		"successfully generates mounts file trimming whitespaces":           {entries: "entry with linebreaks and spaces"},
		"successfully generates mounts file trimming sequential linebreaks": {entries: "entry with multiple linebreaks"},
		"generates an empty file if the entry is empty":                     {entries: "one entry with no value"},
		"generates no file if there are no entries":                         {entries: "no entries"},

		// Policy refresh.
		"mount file is removed on refreshing policy with no entries": {secondCall: "no entries"},
		"mount file is updated on refreshing policy with one entry":  {secondCall: "one entry with multiple values"},

		// Error cases.
		"error when user is not found":              {objectName: "dont exist", wantErr: true},
		"error when user has invalid uid":           {userReturnedUID: "invalid", wantErr: true},
		"error when user has invalid gid":           {userReturnedGID: "invalid", wantErr: true},
		"error when usrDir has invalid permissions": {readOnlyUserDir: true, wantErr: true},

		// To be removed when computer policies get implemented.
		"error when trying to apply computer policies": {computer: true, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testRunDir := t.TempDir()

			opts := []mount.Option{mount.WithRunDir(testRunDir)}

			usr, _ := user.Current()
			if tc.objectName == "" {
				if tc.userReturnedUID == "" {
					tc.userReturnedUID = usr.Uid
				}
				if tc.userReturnedGID == "" {
					tc.userReturnedGID = usr.Gid
				}

				tc.objectName = "ubuntu"

				opts = append(opts, mount.WithUserLookup(func(string) (*user.User, error) {
					return &user.User{Uid: tc.userReturnedUID, Gid: tc.userReturnedGID}, nil
				}))
			}

			entries := mount.EntriesForTests["one entry with one value"]
			if tc.entries != "" {
				entries = mount.EntriesForTests[tc.entries]
			}

			if tc.readOnlyUserDir {
				opts = append(opts, mount.WithPerm(0100))

				// Ensures that the test dir will be cleaned after the test.
				defer func(p string) {
					//nolint:errcheck,gosec
					os.Chmod(p, 0750)
					//nolint:errcheck
					os.RemoveAll(p)
				}(testRunDir)
			}

			m, err := mount.New(opts...)
			require.NoError(t, err, "Setup: Expected no error when creating manager but got one.")

			err = m.ApplyPolicy(context.Background(), tc.objectName, tc.computer, entries)
			if tc.wantErr {
				require.Error(t, err, "Expected an error but got none")
				return
			}
			require.NoError(t, err, "Expected no error but got one")

			if tc.secondCall != "" {
				err = m.ApplyPolicy(context.Background(), tc.objectName, tc.computer, mount.EntriesForTests[tc.secondCall])
				require.NoError(t, err, "Expected no error on second apply call but got one")
			}

			goldenPath := filepath.Join("testdata", t.Name(), "golden")

			makeIndependentOfCurrentUID(t, testRunDir, usr.Uid)
			testutils.CompareTreesWithFiltering(t, testRunDir, goldenPath, mount.Update)
		})
	}
}

// makeIndependentOfCurrentUID renames any file or directory which exactly match uid in path and replace it with 4242.
func makeIndependentOfCurrentUID(t *testing.T, path string, uid string) {
	t.Helper()

	// We need to rename at the end, starting from the leaf to the start so that we don’t fail filepath.Walk()
	// walking in currently renamed directory.
	var toRename []string
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Base(path) != uid {
			return nil
		}
		toRename = append([]string{path}, toRename...)
		return nil
	})
	require.NoError(t, err, "Setup: failed walk in generated directory")

	for _, path := range toRename {
		err := os.Rename(path, filepath.Join(filepath.Dir(path), "4242"))
		require.NoError(t, err, "Setup: failed to generated path independent of current Uid")
	}
}
