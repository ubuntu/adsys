package scripts_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/policies/scripts"
	"github.com/ubuntu/adsys/internal/testutils"
)

var update bool

func TestNew(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		makeReadOnly bool

		wantErr bool
	}{
		// user cases
		"create manager": {},

		"error on read only rundir": {makeReadOnly: true, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			runDir := t.TempDir()

			if tc.makeReadOnly {
				testutils.MakeReadOnly(t, runDir)
			}
			_, err := scripts.New(runDir)
			if tc.wantErr {
				require.NotNil(t, err, "New should have failed but didn't")
				return
			}
			require.NoError(t, err, "New failed but shouldn't have")
		})
	}
}

func TestApplyPolicy(t *testing.T) {
	t.Parallel()

	u, err := user.Current()
	require.NoError(t, err, "Setup: failed to get current user")

	defaultSingleScript := []entry.Entry{{Key: "s", Value: "script1.sh"}}

	tests := map[string]struct {
		entries  []entry.Entry
		computer bool

		saveAssetsError     bool
		userReturnedUID     string
		userReturnedGID     string
		systemctlShouldFail bool
		destAlreadyExists   string
		makeReadOnly        bool

		wantErr bool
	}{
		// user cases -> setuid/setgid to current user in tests
		"one script": {entries: defaultSingleScript},
		"one directory, multiple scripts in order": {entries: []entry.Entry{{Key: "s", Value: "script3.sh\nscript1.sh\nscript2.sh"}}},
		"multiple directories:": {entries: []entry.Entry{
			{Key: "s", Value: "script3.sh\nscript1.sh\nscript2.sh"},
			{Key: "e", Value: "script93.sh\nscript91.sh\nscript92.sh"}}},
		"same script is used multiple times": {entries: []entry.Entry{{Key: "s", Value: "script3.sh\nscript1.sh\nscript3.sh"}}},
		"subfolder with script":              {entries: []entry.Entry{{Key: "s", Value: "subfolder/script1.sh"}}},
		"subfolder with same script name":    {entries: []entry.Entry{{Key: "s", Value: "script1.sh\nsubfolder/script1.sh"}}},
		"no entries is an empty folder":      {},
		"empty entries are discared":         {entries: []entry.Entry{{Key: "s", Value: "script3.sh\n\nscript1.sh"}}},

		// computer cases -> no setuid/setgid (should be -1)
		"computer, no systemctl with other directory than startup":       {computer: true, systemctlShouldFail: true, entries: defaultSingleScript},
		"startup script for computer runs systemctl (systemctl success)": {computer: true, systemctlShouldFail: false, entries: []entry.Entry{{Key: "startup", Value: "script1.sh"}}},

		// Destination already exists. Using computer to be uid independent
		"destination is already running, no change":                   {destAlreadyExists: "already running", computer: true, entries: defaultSingleScript},
		"destination is already ready but not in session, refreshing": {destAlreadyExists: "already ready", computer: true, entries: defaultSingleScript},
		"destination is not ready, refreshing":                        {destAlreadyExists: "not ready", computer: true, entries: defaultSingleScript},
		"no entries update existing non ready folder":                 {destAlreadyExists: "not ready", computer: true},

		// Error cases
		"error on subfolder listed":              {entries: []entry.Entry{{Key: "s", Value: "subfolder"}}, wantErr: true},
		"error on script does not exist":         {entries: []entry.Entry{{Key: "s", Value: "doestnotexists"}}, wantErr: true},
		"error on users run directory Read Only": {makeReadOnly: true, entries: defaultSingleScript, wantErr: true},
		"error on save assets dumping failing":   {entries: defaultSingleScript, saveAssetsError: true, wantErr: true},

		// User error cases only
		"error on invalid UID":                               {userReturnedUID: "invalid", entries: defaultSingleScript, wantErr: true},
		"error on invalid GID":                               {userReturnedGID: "invalid", entries: defaultSingleScript, wantErr: true},
		"error on user lookup failing":                       {userReturnedUID: "userLookupError", entries: defaultSingleScript, wantErr: true},
		"user lookup failing does not impact machine update": {computer: true, userReturnedUID: "userLookupError", entries: defaultSingleScript, wantErr: false},

		// Machine error cases only
		"start script for computer runs systemctl (systemctl failed)": {computer: true, systemctlShouldFail: true, entries: []entry.Entry{{Key: "startup", Value: "script1.sh"}}, wantErr: true},
		"systemctl failing does not impact user scripts update":       {computer: false, systemctlShouldFail: true, entries: []entry.Entry{{Key: "startup", Value: "script1.sh"}}, wantErr: false},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			runDir := t.TempDir()

			if tc.userReturnedUID == "" {
				tc.userReturnedUID = u.Uid
			}
			if tc.userReturnedGID == "" {
				tc.userReturnedGID = u.Gid
			}
			userLookup := func(string) (*user.User, error) {
				return &user.User{Uid: tc.userReturnedUID, Gid: tc.userReturnedGID}, nil
			}
			if tc.userReturnedUID == "userLookupError" {
				userLookup = func(string) (*user.User, error) {
					return nil, errors.New("User error requested")
				}
			}

			if tc.destAlreadyExists != "" {
				require.NoError(t, os.RemoveAll(runDir), "Setup: can't remove run dir before filing it")
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "ApplyPolicy", "run_dir", tc.destAlreadyExists), runDir,
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't create initial run dir scripts content")
			}

			systemctlCmd := mockSystemCtlCmd(t)
			if tc.systemctlShouldFail {
				systemctlCmd = append(systemctlCmd, "-Exit1-")
			}

			sat := sat{err: tc.saveAssetsError}

			m, err := scripts.New(runDir,
				scripts.WithSystemCtlCmd(systemctlCmd),
				scripts.WithUserLookup(userLookup),
			)
			require.NoError(t, err, "Setup: can't create scripts manager")

			if tc.makeReadOnly {
				testutils.MakeReadOnly(t, filepath.Join(runDir, "users"))
			}

			err = m.ApplyPolicy(context.Background(), "ubuntu", tc.computer, tc.entries, sat.mockSaveAssetsTo)
			if tc.wantErr {
				require.NotNil(t, err, "ApplyPolicy should have failed but didn't")
				return
			}
			require.NoError(t, err, "ApplyPolicy failed but shouldn't have")

			makeIndependentOfCurrentUID(t, runDir, u.Uid)

			testutils.CompareTreesWithFiltering(t, runDir, filepath.Join("testdata", "ApplyPolicy", "golden", testutils.NormalizeGoldenName(t, name)), update)
		})
	}
}

// makeCurrentUIDIndepmakeIndependentOfCurrentUIDendent renames any file or directory which exactly match uid in path and replace it with 4242.
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

func TestRunScripts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		stageDir          string
		allowOrderMissing bool
		scriptObjectName  string

		wantSessionFlagFileRemoved bool
		wantErr                    bool
	}{
		"one script":                                  {},
		"multiple scripts are run in order":           {},
		"scripts that are not executable are skipped": {},
		"scripts not listed are not run":              {},
		"scripts referenced in subdirectories":        {},

		// logoff cases
		"has no session running flag after user logoff":                                       {stageDir: "logoff", wantSessionFlagFileRemoved: true},
		"still executes without existing running flag on user logoff":                         {stageDir: "logoff", wantSessionFlagFileRemoved: true},
		"script directory without logoff order has no session running flag after user logoff": {stageDir: "logoff", wantSessionFlagFileRemoved: true, allowOrderMissing: true},
		"keeps running flag after non user logoff":                                            {stageDir: "logoff", scriptObjectName: "machine", wantSessionFlagFileRemoved: false},

		// shutdown cases
		"has no session running flag after machine shutdown":                                         {stageDir: "shutdown", scriptObjectName: "machine", wantSessionFlagFileRemoved: true},
		"still executes without existing running flag on machine shutdown":                           {stageDir: "shutdown", scriptObjectName: "machine", wantSessionFlagFileRemoved: true},
		"script directory without shutdown order has no session running flag after machine shutdown": {stageDir: "shutdown", scriptObjectName: "machine", wantSessionFlagFileRemoved: true, allowOrderMissing: true},
		"keeps running flag after non machine shutdown":                                              {stageDir: "shutdown", scriptObjectName: "users", wantSessionFlagFileRemoved: false},

		"allow order file missing":           {allowOrderMissing: true},
		"spaces and empty lines are skipped": {},

		// Error cases
		"error on order file not existing": {wantErr: true},
		"error on not ready for execution": {wantErr: true},
		"error on argument not a file":     {wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			scriptDir := t.TempDir()
			require.NoError(t, os.RemoveAll(scriptDir), "Setup: can't remove script dir before filing it")

			if tc.stageDir == "" {
				tc.stageDir = "s"
			}
			if tc.scriptObjectName == "" {
				tc.scriptObjectName = "users"
			}
			scriptRootParentDir := filepath.Join(scriptDir, tc.scriptObjectName, "foo")
			scriptParentDir := filepath.Join(scriptRootParentDir, "scripts")
			scriptDir = filepath.Join(scriptParentDir, tc.stageDir)

			if _, err := os.Stat(filepath.Join("testdata", "RunScripts", "scripts", name)); err == nil {
				require.NoError(t, os.MkdirAll(scriptRootParentDir, 0700), "Setup: can't create user dir")
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "RunScripts", "scripts", name), scriptParentDir,
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't create script dir")
			}

			err := scripts.RunScripts(context.Background(), scriptDir, tc.allowOrderMissing)
			if tc.wantErr {
				require.NotNil(t, err, "RunScripts should have failed but didn't")
				_, err = os.Stat(filepath.Dir(scriptDir))
				require.NoError(t, err, "RunScripts should have kept scripts directory intact")
				return
			}
			require.NoError(t, err, "RunScripts failed but shouldn't have")

			_, err = os.Stat(filepath.Join(filepath.Dir(scriptDir), scripts.InSessionFlag))
			if tc.wantSessionFlagFileRemoved {
				require.True(t, errors.Is(err, fs.ErrNotExist), "In session flag should have been removed from user/machine scripts dir but didn't")
			} else {
				require.Nil(t, err, "RunScripts should have added in session flag file but didn’t")
			}

			// Get and compare oracle file to check order
			src := filepath.Join(scriptRootParentDir, "golden")
			testutils.CompareTreesWithFiltering(t, src, filepath.Join("testdata", "RunScripts", "golden", name), update)
		})
	}
}

func TestMockSystemCtl(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for len(args) > 0 {
		if args[0] != "--" {
			args = args[1:]
			continue
		}
		args = args[1:]
		break
	}
	if args[0] == "-Exit1-" {
		fmt.Println("EXIT 1 requested in mock")
		os.Exit(1)
	}
}

type sat struct {
	err bool
}

// mockSaveAssetsTo returns a static mock directory with scripts.
func (s sat) mockSaveAssetsTo(ctx context.Context, relSrc, dest string, uid int, gid int) (err error) {
	if s.err {
		return errors.New("mockSaveAssetsTo error")
	}
	if relSrc != "scripts/" {
		return fmt.Errorf("mockSaveAssetsTo: unexpected relSrc: %q", relSrc)
	}
	return shutil.CopyTree("testdata/sysvol-scripts", dest, nil)
}

func mockSystemCtlCmd(t *testing.T, args ...string) []string {
	t.Helper()

	cmdArgs := []string{"env", "GO_WANT_HELPER_PROCESS=1", os.Args[0], "-test.run=TestMockSystemCtl", "--"}
	cmdArgs = append(cmdArgs, args...)
	return cmdArgs
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
