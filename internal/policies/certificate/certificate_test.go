package certificate_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/certificate"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

const (
	enrollValue   = "7"     // string representation of 0b111
	unenrollValue = "6"     // string representation of 0b110
	disabledValue = "32768" // string representation of 0x8000
)

var enrollEntry = entry.Entry{Key: "autoenroll", Value: enrollValue}
var advancedConfigurationEntries = []entry.Entry{
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/AuthFlags", Value: "2"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/Cost", Value: "2147483645"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/Flags", Value: "20"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/FriendlyName", Value: "ActiveDirectoryEnrollmentPolicy"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/PolicyID", Value: "{A5E9BF57-71C6-443A-B7FC-79EFA6F73EBD}"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/URL", Value: "LDAP:"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/Flags", Value: "0"},
}

func TestPolicyApply(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entries []entry.Entry

		isUser    bool
		isOffline bool

		autoenrollScriptError bool
		runScript             bool

		wantErr bool
	}{
		"Computer, no entries":                                   {},
		"Computer, configured to enroll":                         {entries: []entry.Entry{enrollEntry}, runScript: true},
		"Computer, configured to enroll, advanced configuration": {entries: append(advancedConfigurationEntries, enrollEntry), runScript: true},
		"Computer, configured to unenroll":                       {entries: []entry.Entry{{Key: "autoenroll", Value: unenrollValue}}, runScript: true},
		"Computer, autoenroll disabled":                          {entries: []entry.Entry{{Key: "autoenroll", Value: disabledValue}}},
		"Computer, domain is offline":                            {entries: []entry.Entry{enrollEntry}, isOffline: true},

		"User, autoenroll not supported": {isUser: true, entries: []entry.Entry{enrollEntry}},

		// Error cases
		"Error on autoenroll script failure": {autoenrollScriptError: true, entries: []entry.Entry{enrollEntry}, wantErr: true},
		"Error on invalid autoenroll value":  {entries: []entry.Entry{{Key: "autoenroll", Value: "notanumber"}}, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tmpdir := t.TempDir()
			autoenrollCmdOutputFile := filepath.Join(tmpdir, "autoenroll-output")
			autoenrollCmd := mockAutoenrollScript(t, autoenrollCmdOutputFile, tc.autoenrollScriptError)

			m := certificate.New(
				"example.com",
				certificate.WithStateDir(filepath.Join(tmpdir, "statedir")),
				certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
				certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
				certificate.WithCertAutoenrollCmd(autoenrollCmd),
			)

			err := m.ApplyPolicy(context.Background(), "keypress", !tc.isUser, !tc.isOffline, tc.entries)
			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should fail")
				return
			}
			require.NoError(t, err, "ApplyPolicy should succeed")

			// Check that the autoenroll script was called with the expected arguments
			// and that the output file was created
			if !tc.runScript {
				return
			}

			got, err := os.ReadFile(autoenrollCmdOutputFile)
			require.NoError(t, err, "Setup: Autoenroll mock output should be readable")

			want := testutils.LoadWithUpdateFromGolden(t, string(got))
			require.Equal(t, want, string(got), "Unexpected output from autoenroll mock")
		})
	}
}

func mockAutoenrollScript(t *testing.T, scriptOutputFile string, autoenrollScriptError bool) []string {
	t.Helper()

	cmdArgs := []string{"env", "GO_WANT_HELPER_PROCESS=1", os.Args[0], "-test.run=TestMockAutoenrollScript", "--", scriptOutputFile}
	if autoenrollScriptError {
		cmdArgs = append(cmdArgs, "-Exit1-")
	}

	return cmdArgs
}

func TestMockAutoenrollScript(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	var outputFile string

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			outputFile = args[1]
			args = args[2:]
			break
		}
		args = args[1:]
	}

	if args[0] == "-Exit1-" {
		fmt.Fprintf(os.Stderr, "EXIT 1 requested in mock")
		os.Exit(1)
	}

	dataToWrite := strings.Join(args, " ") + "\n"
	dataToWrite += "KRB5CCNAME=" + os.Getenv("KRB5CCNAME") + "\n"
	dataToWrite += "PYTHONPATH=" + os.Getenv("PYTHONPATH") + "\n"

	// Replace tmpdir with a placeholder to avoid non-deterministic test failures
	tmpdir := filepath.Dir(outputFile)
	dataToWrite = strings.ReplaceAll(dataToWrite, tmpdir, "#TMPDIR#")

	err := os.WriteFile(outputFile, []byte(dataToWrite), 0600)
	require.NoError(t, err, "Setup: Can't write script args to output file")
}

func TestMain(m *testing.M) {
	testutils.InstallUpdateFlag()
	flag.Parse()

	m.Run()
	testutils.MergeCoverages()
}
