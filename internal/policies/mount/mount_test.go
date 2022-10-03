package mount_test

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/policies/mount"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		readOnlyPerm bool

		wantErr bool
	}{
		"creates manager successfully": {},

		"creation fails with invalid runDir permissions": {readOnlyPerm: true, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			runDir := t.TempDir()
			if tc.readOnlyPerm {
				testutils.MakeReadOnly(t, runDir)
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
		entries    []entry.Entry
		key        string
		isComputer bool

		noEntries bool
	}{
		"successfully applies policy with valid key": {key: "user-mounts"},

		"does nothing when trying to apply policy with user key and isComputer is set": {key: "user-mounts", isComputer: true},
		"does nothing when trying to policy with unsupported key":                      {key: "not-supported-yet"},
		"does nothing when trying to apply policy with no entries":                     {noEntries: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tc.entries == nil && !tc.noEntries {
				e := mount.EntriesForTests["entry with one value"]
				e.Key = tc.key
				tc.entries = []entry.Entry{e}
			}

			runDir := t.TempDir()
			opts := []mount.Option{mount.WithRunDir(runDir)}

			// nolint:errcheck // This happens in a controlled test environment.
			u, _ := user.Current()

			if tc.key == "user-mounts" {
				opts = append(opts, mount.WithUserLookup(func(s string) (*user.User, error) {
					return &user.User{Uid: u.Uid, Gid: u.Gid}, nil
				}))
			}

			m, err := mount.New(opts...)
			require.NoError(t, err, "Setup: Failed to create manager for the tests.")

			err = m.ApplyPolicy(context.Background(), "ubuntu", tc.isComputer, tc.entries)
			require.NoError(t, err, "Expected no error but got one")

			if tc.key == "user-mounts" {
				makeIndependentOfCurrentUID(t, runDir, u.Uid)
			}
			testutils.CompareTreesWithFiltering(t, runDir, filepath.Join("testdata", t.Name(), "users"), mount.Update)
		})
	}
}

func TestApplyUserPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entry      string
		objectName string
		computer   bool

		readOnlyUserDir bool
		secondCall      string
		userReturnedUID string
		userReturnedGID string

		wantErr bool
	}{
		// Single entry cases.
		"successfully generates mounts file for entry with value":            {},
		"successfully generates mounts file for entry with multiple values":  {entry: "entry with multiple values"},
		"successfully generates mounts file for entry with repeatead values": {entry: "entry with repeatead values"},

		// Special cases.
		"successfully generates mounts file with anonymous values": {entry: "entry with anonymous tags"},
		"generates no file for errored entry":                      {entry: "errored entry"},

		// Badly formatted entries.
		"successfully generates mounts file trimming whitespaces":           {entry: "entry with linebreaks and spaces"},
		"successfully generates mounts file trimming sequential linebreaks": {entry: "entry with multiple linebreaks"},
		"generates no file if the entry is empty":                           {entry: "entry with no value"},
		"generates no file if there are no entries":                         {entry: "no entries"},

		// Policy refresh.
		"mount file is removed on refreshing policy with no entries": {secondCall: "no entries"},
		"mount file is updated on refreshing policy with an entry":   {secondCall: "entry with multiple values"},

		// Error cases.
		"error when user is not found":               {objectName: "dont exist", wantErr: true},
		"error when user has invalid uid":            {userReturnedUID: "invalid", wantErr: true},
		"error when user has invalid gid":            {userReturnedGID: "invalid", wantErr: true},
		"error when userDir has invalid permissions": {readOnlyUserDir: true, wantErr: true},

		// "error when updating policy and file already exists with wrong ownership": {secondCall: "entry with multiple values", wantErr: true},
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

			testEntry := mount.EntriesForTests["entry with one value"]
			if tc.entry != "" {
				testEntry = mount.EntriesForTests[tc.entry]
			}

			if tc.readOnlyUserDir {
				err := os.MkdirAll(filepath.Join(testRunDir, "users"), 0750)
				require.NoError(t, err, "Setup: Expected no error when creating users dir for tests.")
				testutils.MakeReadOnly(t, filepath.Join(testRunDir, "users"))
			}

			m, err := mount.New(opts...)
			require.NoError(t, err, "Setup: Expected no error when creating manager but got one.")

			err = m.ApplyUserPolicy(context.Background(), tc.objectName, testEntry)
			if tc.wantErr {
				require.Error(t, err, "Expected an error but got none")
				return
			}
			require.NoError(t, err, "Expected no error but got one")

			if tc.secondCall != "" {
				if tc.wantErr {
					iUID, err := strconv.Atoi(tc.userReturnedUID)
					require.NoError(t, err, "Setup: Failed to convert uid to int")
					iGID, err := strconv.Atoi(tc.userReturnedGID)
					require.NoError(t, err, "Setup: Failed to convert gid to int")

					os.Chown(filepath.Join(testRunDir, "users", tc.userReturnedGID, "mounts"), iUID+1, iGID+1)
					t.Cleanup(func() {
						//nolint:errcheck // This happens in a controlled environment
						_ = os.Chown(filepath.Join(testRunDir, "users", tc.userReturnedGID, "mounts"), iUID, iGID)
					})
				}

				err = m.ApplyUserPolicy(context.Background(), tc.objectName, mount.EntriesForTests[tc.secondCall])
				if tc.wantErr {
					require.Error(t, err, "Expected an error but got none")
					return
				}
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
