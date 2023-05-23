package adsys_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestAdsysdMount(t *testing.T) {
	tests := map[string]struct {
		mountsFile    string
		sessionAnswer string
		krbTicket     bool

		addArgs []string

		wantErr bool
	}{
		// Single entries
		"Mount successfully nfs share": {mountsFile: "mounts_with_nfs_entry"},
		"Mount successfully smb share": {mountsFile: "mounts_with_smb_entry"},
		"Mount successfully ftp share": {mountsFile: "mounts_with_ftp_entry"},

		// Kerberos authentication entries
		"Mount successfully krb auth entry": {mountsFile: "mounts_with_krb_auth_entry", krbTicket: true},

		// Many entries
		"Mount successfully many entries with same protocol":       {mountsFile: "mounts_with_many_nfs_entries"},
		"Mount successfully many entries with different protocols": {mountsFile: "mounts_with_many_entries"},
		"Mount successfully many kerberos auth entries":            {mountsFile: "mounts_with_many_krb_auth_entries", krbTicket: true},

		// File cases
		"Exit code 0 when file is empty": {mountsFile: "mounts_with_no_entries"},

		// File errors
		"Error when file has badly formated entries": {mountsFile: "mounts_with_bad_entries", wantErr: true},
		"Error when file doesn't exist":              {mountsFile: "do_not_exist", wantErr: true},

		// Authentication errors
		"Error when auth is needed but no kerberos ticket is available": {mountsFile: "mounts_with_krb_auth_entry", wantErr: true},
		"Error when anonymous auth is not supported by the server":      {mountsFile: "mounts_with_nfs_entry", sessionAnswer: "gvfs_anonymous_error", wantErr: true},

		// Bus errors
		"Error when VFS bus is not available": {mountsFile: "mounts_with_nfs_entry", sessionAnswer: "gvfs_no_vfs_bus", wantErr: true},
		"Error during ListMountableInfo step": {mountsFile: "mounts_with_nfs_entry", sessionAnswer: "gvfs_list_info_fail", wantErr: true},
		"Error during MountLocation step":     {mountsFile: "mounts_with_nfs_entry", sessionAnswer: "gvfs_mount_loc_fail", wantErr: true},

		// Generic errors
		"Error when trying to mount unsupported protocol": {mountsFile: "mounts_with_unsupported_protocol", wantErr: true},
		"Error during mount process":                      {mountsFile: "mounts_with_error", wantErr: true},

		// Command usage cases
		"Correctly prints the help message": {addArgs: []string{"--help"}},

		// Command usage errors
		"Errors out and prints usage message when executed with less than 2 arguments": {wantErr: true},
		"Errors out and prints usage message when executed with more than 2 arguments": {addArgs: []string{"more", "than", "two"}, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.sessionAnswer == "" {
				tc.sessionAnswer = "polkit_yes"
			}

			if setupSubprocessForMountTest(t, tc.sessionAnswer, tc.krbTicket) {
				t.SkipNow()
			}

			d := daemon.New()
			args := []string{"mount"}
			if tc.mountsFile != "" {
				args = append(args, filepath.Join(testutils.TestFamilyPath(t), tc.mountsFile))
			}
			changeAppArgs(t, d, "", append(args, tc.addArgs...)...)

			err := d.Run()
			if tc.wantErr {
				require.Error(t, err, "Client should exit with an error")
				return
			}
			require.NoError(t, err, "Client should exit with no error")
		})
	}
}

// setupSubprocessForMountTest prepares a subprocess with a mock passwd file for running the tests.
// Returns false if we are already in the subprocess and should continue.
// Returns true if we prepare the subprocess and reexec ourself.
func setupSubprocessForMountTest(t *testing.T, mode string, krbTicket bool) bool {
	t.Helper()

	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		return false
	}

	var subArgs []string
	// We are going to only reexec ourself: only take options (without -run)
	// and redirect coverage file
	for i, arg := range os.Args {
		if i != 0 && !strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.HasPrefix(arg, "-test.run=") {
			continue
		}
		if strings.HasPrefix(arg, "-test.coverprofile=") {
			continue
		}
		subArgs = append(subArgs, arg)
	}
	// Cover subprocess in a different file that we will merge when the test ends
	if testCoverFile := testutils.TrackTestCoverage(t); testCoverFile != "" {
		subArgs = append(subArgs, "-test.coverprofile="+testCoverFile)
	}

	subArgs = append(subArgs, fmt.Sprintf("-test.run=%s", t.Name()))

	// #nosec G204: this is only for tests, under controlled args
	cmd := exec.Command(subArgs[0], subArgs[1:]...)

	// Setup correct child environment
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=%s", filepath.Join(dbusSockets[mode], "session_bus_socket")),
	)
	if krbTicket {
		cmd.Env = append(cmd.Env, "KRB5CCNAME=kerberos_ticket")
	}

	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		t.Fail() // The real failure will be written by the child test process
	}

	return true
}
