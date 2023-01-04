package mount_test

import (
	"context"
	"fmt"
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
		readOnlyRunDir     bool
		readOnlySystemdDir bool

		wantErr bool
	}{
		"creates manager successfully": {},

		"creation fails with invalid runDir permissions":        {readOnlyRunDir: true, wantErr: true},
		"creation fails with invalid systemUnitDir permissions": {readOnlySystemdDir: true, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rootDir := t.TempDir()
			runDir := filepath.Join(rootDir, "run/adsys")
			if tc.readOnlyRunDir {
				err := os.MkdirAll(runDir, 0750)
				require.NoError(t, err, "Setup: Failed to create directory for tests")
				testutils.MakeReadOnly(t, runDir)
			}

			systemdDir := filepath.Join(rootDir, "etc/systemd")
			if tc.readOnlySystemdDir {
				err := os.MkdirAll(systemdDir, 0750)
				require.NoError(t, err, "Setup: Failed to create directory for tests")
				testutils.MakeReadOnly(t, systemdDir)
			}

			_, err := mount.New(runDir, filepath.Join(systemdDir, "system"))
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

	u, err := user.Current()
	require.NoError(t, err, "Setup: failed to get current user")

	tests := map[string]struct {
		entries    []string
		keys       []string
		isDisabled bool
		objectName string
		isComputer bool

		secondCall           []string
		isDisabledSecondCall bool

		// User specific
		readOnlyUsersDir  bool
		userReturnedUID   string
		userReturnedGID   string
		pathAlreadyExists bool

		// System specific
		firstSystemCtlFailingArgs   []string
		secondSystemCtlFailingArgs  []string
		pathAlreadyExistsSecondCall bool

		wantErr           bool
		wantErrSecondCall bool
	}{
		/***************************** USER ****************************/
		// Success cases.
		"user, successfully apply policy for entry with one value":              {},
		"user, successfully apply policy for entry with multiple values":        {entries: []string{"entry with multiple values"}},
		"user, successfully apply policy for entry with repeated values":        {entries: []string{"entry with repeated values"}},
		"user, successfully apply policy for entry with repeated tagged values": {entries: []string{"entry with repeated tagged values"}},
		"user, successfully apply policy filtering out unsupported keys":        {entries: []string{"entry with multiple values", "entry with one value"}, keys: []string{"unsupported", "user-mounts"}},

		// Special cases.
		"user, successfully apply policy with kerberos auth tags":                             {entries: []string{"entry with kerberos auth tags"}},
		"user, successfully apply policy prioritizing the first value found, despite the tag": {entries: []string{"entry with same values tagged and untagged"}},
		"user, does nothing if the entry is disabled":                                         {isDisabled: true},

		// Badly formatted entries.
		"user, successfully apply policy trimming whitespaces":           {entries: []string{"entry with spaces"}},
		"user, successfully apply policy trimming sequential linebreaks": {entries: []string{"entry with multiple linebreaks"}},
		"user, creates only dirs if the entry is empty":                  {entries: []string{"entry with no value"}},
		"user, creates only dirs if there are no entries":                {entries: []string{"no entries"}},

		// Policy refresh.
		"user, mount file is removed on refreshing policy with no entries":                    {secondCall: []string{"no entries"}},
		"user, mount file is removed on refreshing policy with an empty entry":                {secondCall: []string{"entry with no value"}},
		"user, mount file is removed on refreshing policy with a disabled entry":              {secondCall: []string{"entry with one value"}, isDisabledSecondCall: true},
		"user, mount file is updated on refreshing policy with an entry with multiple values": {secondCall: []string{"entry with multiple values"}},

		/**************************** SYSTEM ***************************/
		// Success cases.
		"system, successfully apply policy for entry with one value":              {isComputer: true},
		"system, successfully apply policy for entry with multiple values":        {entries: []string{"entry with multiple values"}, isComputer: true},
		"system, successfully apply policy for entry with repeated values":        {entries: []string{"entry with repeated values"}, isComputer: true},
		"system, successfully apply policy for entry with repeated tagged values": {entries: []string{"entry with repeated tagged values"}, isComputer: true},
		"system, successfully apply policy filtering out unsupported keys":        {entries: []string{"entry with multiple values", "entry with one value"}, keys: []string{"unsupported", "system-mounts"}, isComputer: true},

		// Special cases.
		"system, successfully apply policy with kerberos tagged values":                         {entries: []string{"entry with kerberos auth tags"}, isComputer: true},
		"system, successfully apply policy prioritizing the first value found, despite the tag": {entries: []string{"entry with same values tagged and untagged"}, isComputer: true},
		"system, only emit a warning when starting new units and systemctl fails":               {isComputer: true, firstSystemCtlFailingArgs: []string{"start"}},
		"system, only emit a warning when disabling previous units and systemctl fails":         {isComputer: true, secondCall: []string{"entry with multiple values"}, secondSystemCtlFailingArgs: []string{"stop"}},
		"system, does nothing if the entry is disabled":                                         {isComputer: true, isDisabled: true},

		// Badly formatted entries.
		"system, successfully apply policy trimming whitespaces":           {entries: []string{"entry with spaces"}, isComputer: true},
		"system, successfully apply policy trimming sequential linebreaks": {entries: []string{"entry with multiple linebreaks"}, isComputer: true},
		"system, does nothing if the entry is empty":                       {entries: []string{"entry with no value"}, isComputer: true},
		"system, does nothing if there are no entries":                     {entries: []string{"no entries"}, isComputer: true},

		// Policy refresh.
		"system, mount units are added on refreshing policy with some matching values":            {entries: []string{"entry with multiple values"}, secondCall: []string{"entry with multiple matching values"}, isComputer: true},
		"system, mount units are updated on refreshing policy with an entry with multiple values": {secondCall: []string{"entry with multiple values"}, isComputer: true},
		"system, mount units are removed on refreshing policy with no entries":                    {secondCall: []string{"no entries"}, isComputer: true},
		"system, mount units are removed on refreshing policy with an empty entry":                {secondCall: []string{"entry with no value"}, isComputer: true},
		"system, mount units are removed on refreshing policy with disabled entry":                {secondCall: []string{"entry with one value"}, isDisabledSecondCall: true},

		/**************************** GENERIC **************************/
		// Special cases.
		"creates only dirs when trying to policy with unsupported key":  {keys: []string{"unsupported"}},
		"creates only dirs when trying to apply policy with no entries": {entries: []string{"no entries"}},

		/***************************** USER ****************************/
		// Error cases.
		"error when user is not found":                                                               {objectName: "dont exist", wantErr: true},
		"error when user has invalid uid":                                                            {userReturnedUID: "invalid", wantErr: true},
		"error when user has invalid gid":                                                            {userReturnedGID: "invalid", wantErr: true},
		"error when users-userDir has invalid permissions":                                           {readOnlyUsersDir: true, wantErr: true},
		"error when mounts file path already exists as a directory":                                  {pathAlreadyExists: true, wantErr: true},
		"error when entry is errored":                                                                {entries: []string{"errored entry"}, wantErr: true},
		"error when cleaning up user policy with invalid user":                                       {entries: []string{"no entries"}, objectName: "dont exist", wantErr: true},
		"error when cleaning up user policy with no entries and path already exists as a directory":  {entries: []string{"no entries"}, pathAlreadyExists: true, wantErr: true},
		"error when cleaning up user policy with empty entry and path already exists as a directory": {entries: []string{"entry with no value"}, pathAlreadyExists: true, wantErr: true},
		"error when applying policy with entry containing badly formatted value":                     {entries: []string{"entry with badly formatted value"}, wantErr: true},

		/**************************** SYSTEM ***************************/
		// Error cases.
		"error when creating units with bad entry values":                        {entries: []string{"entry with badly formatted value"}, isComputer: true, wantErr: true},
		"error when daemon-reload fails":                                         {firstSystemCtlFailingArgs: []string{"daemon-reload"}, isComputer: true, wantErr: true},
		"error when disabling units for clean up and systemctl fails":            {secondCall: []string{"entry with multiple values"}, isComputer: true, secondSystemCtlFailingArgs: []string{"disable"}, wantErrSecondCall: true},
		"error when enabling new units and systemctl fails":                      {isComputer: true, firstSystemCtlFailingArgs: []string{"enable"}, wantErr: true},
		"error when trying to update policy with badly formatted entry":          {secondCall: []string{"entry with badly formatted value"}, wantErrSecondCall: true, isComputer: true},
		"error when applying policy and system mount unit already exists as dir": {isComputer: true, pathAlreadyExists: true, wantErr: true},
		"error when updating policy and system mount unit to remove is a dir":    {secondCall: []string{"entry with multiple values"}, isComputer: true, pathAlreadyExistsSecondCall: true, wantErrSecondCall: true},
		"error when applying system policy and the entry is errored":             {entries: []string{"errored entry"}, isComputer: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rootDir := t.TempDir()
			runDir := filepath.Join(rootDir, "run", "adsys")
			systemUnitDir := filepath.Join(rootDir, "etc", "systemd", "system")

			entries := []entry.Entry{}
			if tc.entries == nil {
				tc.entries = []string{"entry with one value"}
			}

			if tc.keys == nil {
				tc.keys = []string{"user-mounts"}
				if tc.isComputer {
					tc.keys = []string{"system-mounts"}
				}
			}

			for i, v := range tc.entries {
				if v == "no entries" {
					break
				}
				e := mount.EntriesForTests[v]
				e.Key = tc.keys[i]
				e.Disabled = tc.isDisabled
				entries = append(entries, e)
			}

			opts := []mount.Option{}
			if !tc.isComputer && tc.objectName == "" {
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

			if tc.readOnlyUsersDir {
				err := os.MkdirAll(filepath.Join(runDir, "users"), 0750)
				require.NoError(t, err, "Setup: Expected no error when creating users dir for tests.")
				testutils.MakeReadOnly(t, filepath.Join(runDir, "users"))
			}

			if tc.pathAlreadyExists {
				p := filepath.Join(runDir, "users", u.Uid, "mounts")
				if tc.isComputer {
					p = filepath.Join(systemUnitDir, "adsys-protocol-domain.com-mountpath.mount")
				}
				testutils.CreatePath(t, filepath.Join(p, "not_empty"))
			}

			m, err := mount.New(runDir, systemUnitDir, opts...)
			require.NoError(t, err, "Setup: Failed to create manager for the tests.")
			m.SetSystemCtlCmd(mockSystemCtlCmd(t, tc.firstSystemCtlFailingArgs...))

			err = m.ApplyPolicy(context.Background(), "ubuntu", tc.isComputer, entries)
			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should have returned an error but did not")
				return
			}
			require.NoError(t, err, "ApplyPolicy should not have returned an error but did")

			if tc.secondCall != nil {
				secondEntries := []entry.Entry{}
				for i, v := range tc.secondCall {
					if v == "no entries" {
						break
					}
					e := mount.EntriesForTests[v]
					e.Key = tc.keys[i]
					e.Disabled = tc.isDisabledSecondCall
					secondEntries = append(secondEntries, e)
				}
				m.SetSystemCtlCmd(mockSystemCtlCmd(t, tc.secondSystemCtlFailingArgs...))

				if tc.pathAlreadyExistsSecondCall {
					p := filepath.Join(systemUnitDir, "adsys-protocol-domain.com-mountpath.mount")
					err := os.Remove(p)
					require.NoError(t, err, "Setup: failed to remove file for tests.")
					testutils.CreatePath(t, filepath.Join(p, "not_empty"))
				}

				err = m.ApplyPolicy(context.Background(), tc.objectName, tc.isComputer, secondEntries)
				if tc.wantErrSecondCall {
					require.Error(t, err, "Second call should have returned an error but didn't")
				} else {
					require.NoError(t, err, "Second call of ApplyPolicy should not have returned an error but did")
				}
			}

			if !tc.isComputer {
				makeIndependentOfCurrentUID(t, runDir, u.Uid)
			}
			goldPath := filepath.Join("testdata", "golden", t.Name())
			testutils.CompareTreesWithFiltering(t, rootDir, goldPath, mount.Update)
		})
	}
}

func TestMockSystemCtl(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	found := false
	failingArgs := make(map[string]struct{})
	// Consumes args until the first --. Args after it (up until the next --)
	// are marked as disabled and will fail if used in the mock.
	for len(args) > 0 {
		if args[0] == "--" {
			if found {
				args = args[1:]
				break
			}
			found = true
		} else {
			if found {
				failingArgs[args[0]] = struct{}{}
			}
		}
		args = args[1:]
	}

	for len(args) > 0 {
		if _, ok := failingArgs[args[0]]; ok {
			fmt.Printf("Arg %q was disabled in the mock\n", args[0])
			os.Exit(1)
		}
		args = args[1:]
	}
}

func mockSystemCtlCmd(t *testing.T, args ...string) []string {
	t.Helper()

	cmdArgs := []string{"env", "GO_WANT_HELPER_PROCESS=1", os.Args[0], "-test.run=TestMockSystemCtl", "--"}
	cmdArgs = append(cmdArgs, args...)
	cmdArgs = append(cmdArgs, "--")
	return cmdArgs
}

// makeIndependentOfCurrentUID renames any file or directory which exactly match uid in path and replace it with 4242.
func makeIndependentOfCurrentUID(t *testing.T, path string, uid string) {
	t.Helper()

	// We need to rename at the end, starting from the leaf to the start so that we don’t fail filepath.Walk()
	// walking in currently renamed directory.
	var toRename []string
	err := filepath.Walk(path, func(path string, _ os.FileInfo, err error) error {
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
