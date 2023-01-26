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

		addArgs []string

		wantStatus int
	}{
		// Single entries
		"Mount successfully nfs share":                     {mountsFile: "mounts_with_nfs_entry"},
		"Mount successfully smb share":                     {mountsFile: "mounts_with_smb_entry"},
		"Mount successfully ftp share":                     {mountsFile: "mounts_with_ftp_entry"},
		"Mount successfully entry without kerberos ticket": {mountsFile: "mounts_with_nfs_entry", noKrbTicket: true},

		// Kerberos authentication entries
		"Mount successfully krb auth entry": {mountsFile: "mounts_with_krb_auth_entry"},

		// Many entries
		"Mount successfully many entries with same protocol":       {mountsFile: "mounts_with_many_nfs_entries"},
		"Mount successfully many entries with different protocols": {mountsFile: "mounts_with_many_entries"},
		"Mount successfully many kerberos auth entries":            {mountsFile: "mounts_with_many_krb_auth_entries"},

		// File cases
		"Exit code 0 when file is empty": {mountsFile: "mounts_with_no_entries"},

		// File errors
		"Error when file has badly formated entries": {mountsFile: "mounts_with_bad_entries", wantStatus: 1},
		"Error when file doesn't exist":              {mountsFile: "do_not_exist", wantStatus: 1},

		// Authentication errors
		"Error when auth is needed but no kerberos ticket is available": {mountsFile: "mounts_with_krb_auth_entry", noKrbTicket: true, wantStatus: 1},
		"Error when anonymous auth is not supported by the server":      {mountsFile: "mounts_with_nfs_entry", sessionAnswer: "gvfs_anonymous_error", noKrbTicket: true, wantStatus: 1},

		// Bus errors
		"Error when VFS bus is not available": {mountsFile: "mounts_with_nfs_entry", sessionAnswer: "gvfs_no_vfs_bus", wantStatus: 1},
		"Error during ListMountableInfo step": {mountsFile: "mounts_with_nfs_entry", sessionAnswer: "gvfs_list_info_fail", wantStatus: 1},
		"Error during MountLocation step":     {mountsFile: "mounts_with_nfs_entry", sessionAnswer: "gvfs_mount_loc_fail", wantStatus: 1},

		// Generic errors
		"Error when trying to mount unsupported protocol": {mountsFile: "mounts_with_unsupported_protocol", wantStatus: 1},
		"Error during mount process":                      {mountsFile: "mounts_with_error", wantStatus: 1},

		// Binary usage cases
		"Correctly prints the help message": {addArgs: []string{"--help"}},

		// Binary usage errors
		"Errors out and prints usage message when executed with less than 2 arguments": {wantStatus: 2},
		"Errors out and prints usage message when executed with more than 2 arguments": {addArgs: []string{"more", "than", "two"}, wantStatus: 2},
		"Errors out and prints usage message even when --help is among the arguments":  {addArgs: []string{"i", "need", "--help"}, wantStatus: 2},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.sessionAnswer == "" {
				tc.sessionAnswer = "polkit_yes"
			}
			dbusAnswer(t, tc.sessionAnswer)

			args := []string{}
			if tc.mountsFile != "" {
				args = append(args, filepath.Join(fixtureDir, tc.mountsFile))
			}

			if tc.addArgs != nil {
				args = append(args, tc.addArgs...)
			}

			// #nosec G204: we are in control of the arguments during the tests.
			cmd := exec.Command(filepath.Join(target, "debug", "adsys_mount"), args...)
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

	testutils.MarkRustFilesForTestCache(t, rustDir)
	env, target = testutils.TrackRustCoverage(t, rustDir)

	// #nosec G204: we control the arguments.
	cmd := exec.Command("cargo", "build", "--verbose", "--target-dir", target)
	cmd.Dir = rustDir
	cmd.Env = append(os.Environ(), env...)

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Setup: Failed to compile rust binary for tests: %s", out)

	return env, target
}
