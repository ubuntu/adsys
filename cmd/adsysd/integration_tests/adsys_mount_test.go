package adsys_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserMountHandler(t *testing.T) {
	fixtureDir := filepath.Join("testdata", t.Name())

	binDir := os.Getenv("TEST_RUST_TARGET")
	if binDir == "" {
		binDir = t.TempDir()
	}
	binPath := setupBinaryForTests(t, binDir)

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

		// Errors
		"error when trying to mount smb without kerberos ticket": {mountsFile: "mounts_with_smb_entry", noKrbTicket: true, wantStatus: 1},
		"error when trying to mount nfs without kerberos ticket": {mountsFile: "mounts_with_nfs_entry", noKrbTicket: true, wantStatus: 1},
		"error when trying to mount unsupported protocol":        {mountsFile: "mounts_with_unsupported_protocol", wantStatus: 1},
		"error during mount process":                             {mountsFile: "mounts_with_error", wantStatus: 1},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.sessionAnswer == "" {
				tc.sessionAnswer = "polkit_yes"
			}
			dbusAnswer(t, tc.sessionAnswer)

			t.Log("Running the binary")

			// #nosec G204: we are in control of the arguments during the tests.
			cmd := exec.Command(binPath, filepath.Join(fixtureDir, tc.mountsFile))
			if !tc.noKrbTicket {
				cmd.Env = append(os.Environ(), "KRB5CCNAME=kerberos_ticket")
			}

			out, err := cmd.CombinedOutput()
			if tc.wantStatus == 0 {
				require.NoError(t, err, "Expected no error but got one: %v\n%s", err, out)
			}
			require.Equal(t, tc.wantStatus, cmd.ProcessState.ExitCode(), "Exit code is not what was expected:\n%s", out)
		})
	}
}

func setupBinaryForTests(t *testing.T, targetDir string) (binPath string) {
	t.Helper()

	t.Log("Setting up rust binary")

	// #nosec G204: we control the arguments.
	cmd := exec.Command("cargo", "build", "--verbose", "--target-dir", targetDir)
	cmd.Dir = filepath.Join(rootProjectDir, "internal", "policies", "mount", "adsys_mount")

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Setup: Failed to compile rust binary for tests: %v", string(out))

	return filepath.Join(targetDir, "debug", "adsys_mount")
}
