package mount_test

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
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

			_, err := mount.New(runDir)
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
		entries    []string
		key        string
		objectName string
		isComputer bool

		secondCall []string

		// User specific
		readOnlyUsersDir  bool
		userReturnedUID   string
		userReturnedGID   string
		pathAlreadyExists bool

		wantErr bool
	}{
		/***************************** USER ****************************/
		// Single entry cases.
		"successfully apply policy for entry with one value":        {},
		"successfully apply policy for entry with multiple values":  {entries: []string{"entry with multiple values"}},
		"successfully apply policy for entry with repeatead values": {entries: []string{"entry with repeatead values"}},

		// Special cases.
		"successfully apply policy with anonymous values":     {entries: []string{"entry with anonymous tags"}},
		"creates only users_user dir if the entry is errored": {entries: []string{"errored entry"}},

		// Badly formatted entries.
		"successfully apply policy trimming whitespaces":           {entries: []string{"entry with spaces"}},
		"successfully apply policy trimming sequential linebreaks": {entries: []string{"entry with multiple linebreaks"}},
		"creates only users_user dir if the entry is empty":        {entries: []string{"entry with no value"}},
		"creates only users dir if there are no entries":           {entries: []string{"no entries"}},

		// Policy refresh.
		"mount file is removed on refreshing policy with no entries": {secondCall: []string{"no entries"}},
		"mount file is updated on refreshing policy with an entry":   {secondCall: []string{"entry with multiple values"}},

		/**************************** GENERIC **************************/
		// Special cases.
		"creates only users dir when trying to policy with unsupported key":  {key: "not-supported"},
		"creates only users dir when trying to apply policy with no entries": {entries: []string{"no entries"}},

		/***************************** USER ****************************/
		// Error cases.
		"error when user is not found":                  {objectName: "dont exist", wantErr: true},
		"error when user has invalid uid":               {userReturnedUID: "invalid", wantErr: true},
		"error when user has invalid gid":               {userReturnedGID: "invalid", wantErr: true},
		"error when userDir has invalid permissions":    {readOnlyUsersDir: true, wantErr: true},
		"error when path already exists as a directory": {pathAlreadyExists: true, wantErr: true},
	}

	u, err := user.Current()
	require.NoError(t, err, "Setup: failed to get current user")

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			entries := []entry.Entry{}
			if tc.entries == nil {
				tc.entries = []string{"entry with one value"}
			}

			if tc.key == "" {
				tc.key = "user-mounts"
			}

			for _, v := range tc.entries {
				if v == "no entries" {
					break
				}
				e := mount.EntriesForTests[v]
				e.Key = tc.key
				entries = append(entries, e)
			}

			opts := []mount.Option{}
			if tc.key == "user-mounts" && tc.objectName == "" {
				if tc.userReturnedUID == "" {
					tc.userReturnedUID = u.Uid
				}
				if tc.userReturnedGID == "" {
					tc.userReturnedGID = u.Gid
				}

				tc.objectName = "ubuntu"
				opts = append(opts, mount.WithUserLookup(func(string) (*user.User, error) {
					return &user.User{Uid: tc.userReturnedUID, Gid: tc.userReturnedGID}, nil
				}))
			}

			runDir := t.TempDir()
			if tc.readOnlyUsersDir {
				err := os.MkdirAll(filepath.Join(runDir, "users"), 0750)
				require.NoError(t, err, "Setup: Expected no error when creating users dir for tests.")
				testutils.MakeReadOnly(t, filepath.Join(runDir, "users"))
			}

			if tc.pathAlreadyExists {
				err := os.MkdirAll(filepath.Join(runDir, "users", u.Uid, "mounts"), 0750)
				require.NoError(t, err, "Setup: Expected no error when creating mounts dir for tests.")
			}

			m, err := mount.New(runDir, opts...)
			require.NoError(t, err, "Setup: Failed to create manager for the tests.")

			err = m.ApplyPolicy(context.Background(), "ubuntu", tc.isComputer, entries)
			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should have returned an error but did not")
				return
			}
			require.NoError(t, err, "ApplyPolicy should not have returned an error but did")

			if tc.secondCall != nil {
				secondEntries := []entry.Entry{}
				for _, v := range tc.secondCall {
					if v == "no entries" {
						break
					}
					e := mount.EntriesForTests[v]
					e.Key = tc.key
					secondEntries = append(secondEntries, e)
				}

				err = m.ApplyPolicy(context.Background(), tc.objectName, tc.isComputer, secondEntries)
				require.NoError(t, err, "Second call of ApplyPolicy should not have returned an error but did")
			}

			if tc.key == "user-mounts" {
				makeIndependentOfCurrentUID(t, runDir, u.Uid)
			}
			goldPath := filepath.Join("testdata", t.Name())
			testutils.CompareTreesWithFiltering(t, runDir, goldPath, mount.Update)
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
