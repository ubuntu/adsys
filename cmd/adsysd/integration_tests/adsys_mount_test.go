package adsys_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestUserMountHandler(t *testing.T) {
	fixtureDir := filepath.Join("testdata", t.Name())

	env, target := setupBinaryForTests(t)

	tests := map[string]struct {
		mountsFile    string
		sessionAnswer string
		noKrbTicket   bool

		wantStatus int
	}{
		// Single entries
		"mount successfully nfs share": {mountsFile: "mounts_with_nfs_entry"},
		"mount successfully smb share": {mountsFile: "mounts_with_smb_entry"},

		// Anonymous entries
		"mount successfully one anonymous nfs entry": {mountsFile: "mounts_with_anonymous_nfs_entry"},
		"mount successfully one anonymous smb entry": {mountsFile: "mounts_with_anonymous_smb_entry"},

		// Many entries
		"mount successfully many entries with different protocols": {mountsFile: "mounts_with_many_entries"},
		"mount successfully many anonymous entries":                {mountsFile: "mounts_with_many_anonymous_entries"},

		// File cases
		"exit code 0 when file is empty": {mountsFile: "mounts_with_no_entries"},

		// File errors
		"error when file has badly formated entries": {mountsFile: "mounts_with_bad_entries", wantStatus: 1},
		"error when file doesn't exist":              {mountsFile: "do_not_exist", wantStatus: 1},

		// Authentication errors
		"error when trying to mount smb without kerberos ticket": {mountsFile: "mounts_with_smb_entry", noKrbTicket: true, wantStatus: 1},
		"error when trying to mount nfs without kerberos ticket": {mountsFile: "mounts_with_nfs_entry", noKrbTicket: true, wantStatus: 1},

		// Bus errors
		"error when VFS bus is not available": {sessionAnswer: "no_vfs_bus", wantStatus: 1},
		"error during ListMountableInfo step": {sessionAnswer: "list_info_fail", wantStatus: 1},
		"error during MountLocation step":     {sessionAnswer: "mount_loc_fail", wantStatus: 1},

		// Generic errors
		"error when trying to mount unsupported protocol": {mountsFile: "mounts_with_unsupported_protocol", wantStatus: 1},
		"error during mount process":                      {mountsFile: "mounts_with_error", wantStatus: 1},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.mountsFile == "" {
				tc.mountsFile = "mounts_with_smb_entry"
			}

			if tc.sessionAnswer == "" {
				tc.sessionAnswer = "polkit_yes"
			}
			dbusAnswer(t, tc.sessionAnswer)

			// #nosec G204: we are in control of the arguments during the tests.
			cmd := exec.Command(filepath.Join(target, "debug", "adsys_mount"), filepath.Join(fixtureDir, tc.mountsFile))
			cmd.Stderr, cmd.Stdout = os.Stderr, os.Stdout
			cmd.Env = append(os.Environ(), env...)

			// Sets up the kerberos environment variable to emulate a kerberos ticket
			if !tc.noKrbTicket {
				cmd.Env = append(cmd.Env, "KRB5CCNAME=kerberos_ticket")
			}

			err := cmd.Run()
			if tc.wantStatus == 0 {
				require.NoError(t, err, "Expected no error but got one: %v", err)
			}
			require.Equal(t, tc.wantStatus, cmd.ProcessState.ExitCode(), "Exit code is not what was expected")
		})
	}
}

func setupBinaryForTests(t *testing.T) (env []string, target string) {
	t.Helper()

	t.Log("Setting up rust binary")

	rustDir := filepath.Join(rootProjectDir, "internal", "policies", "mount", "adsys_mount")

	testutils.MarkRustFilesForTestCache(t)
	env, target = testutils.TrackRustCoverage(t)

	// #nosec G204: we control the arguments.
	cmd := exec.Command("cargo", "build", "--verbose", "--target-dir", target)
	cmd.Dir = rustDir
	cmd.Env = append(os.Environ(), env...)

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Setup: Failed to compile rust binary for tests: %s", out)

	return env, target
}
