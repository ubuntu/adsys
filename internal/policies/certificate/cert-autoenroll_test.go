package certificate_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/testutils"
)

const advancedConfigurationJSON = `[
  {
    "keyname": "Software\\Policies\\Microsoft\\Cryptography\\PolicyServers\\37c9dc30f207f27f61a2f7c3aed598a6e2920b54",
    "valuename": "AuthFlags",
    "data": 2,
    "type": 4
  },
  {
    "keyname": "Software\\Policies\\Microsoft\\Cryptography\\PolicyServers\\37c9dc30f207f27f61a2f7c3aed598a6e2920b54",
    "valuename": "Cost",
    "data": 2147483645,
    "type": 4
  },
  {
    "keyname": "Software\\Policies\\Microsoft\\Cryptography\\PolicyServers\\37c9dc30f207f27f61a2f7c3aed598a6e2920b54",
    "valuename": "Flags",
    "data": 20,
    "type": 4
  },
  {
    "keyname": "Software\\Policies\\Microsoft\\Cryptography\\PolicyServers\\37c9dc30f207f27f61a2f7c3aed598a6e2920b54",
    "valuename": "FriendlyName",
    "data": "ActiveDirectoryEnrollmentPolicy",
    "type": 1
  },
  {
    "keyname": "Software\\Policies\\Microsoft\\Cryptography\\PolicyServers\\37c9dc30f207f27f61a2f7c3aed598a6e2920b54",
    "valuename": "PolicyID",
    "data": "{A5E9BF57-71C6-443A-B7FC-79EFA6F73EBD}",
    "type": 1
  },
  {
    "keyname": "Software\\Policies\\Microsoft\\Cryptography\\PolicyServers\\37c9dc30f207f27f61a2f7c3aed598a6e2920b54",
    "valuename": "URL",
    "data": "LDAP:",
    "type": 1
  },
  {
    "keyname": "Software\\Policies\\Microsoft\\Cryptography\\PolicyServers",
    "valuename": "Flags",
    "data": 0,
    "type": 4
  }
]`

func TestCertAutoenrollScript(t *testing.T) {
	coverageOn := testutils.PythonCoverageToGoFormat(t, "cert-autoenroll", false)
	certAutoenrollCmd := "./cert-autoenroll"
	if coverageOn {
		certAutoenrollCmd = "cert-autoenroll"
	}

	compactedJSON := &bytes.Buffer{}
	err := json.Compact(compactedJSON, []byte(advancedConfigurationJSON))
	require.NoError(t, err, "Failed to compact JSON")

	// Setup samba mock
	pythonPath, err := filepath.Abs("../../testutils/admock")
	require.NoError(t, err, "Setup: Failed to get current absolute path for mock")

	tests := map[string]struct {
		args []string

		readOnlyPath    bool
		autoenrollError bool

		missingCertmonger bool
		missingCepces     bool

		wantErr bool
	}{
		"Enroll with simple configuration":                   {args: []string{"enroll", "keypress", "example.com"}},
		"Enroll with simple configuration and debug enabled": {args: []string{"enroll", "keypress", "example.com", "--debug"}},
		"Enroll with empty advanced configuration":           {args: []string{"enroll", "keypress", "example.com", "--policy_servers_json", "null"}},
		"Enroll with valid advanced configuration":           {args: []string{"enroll", "keypress", "example.com", "--policy_servers_json", compactedJSON.String()}},

		"Unenroll": {args: []string{"unenroll", "keypress", "example.com"}},

		// Missing binary cases
		"Enroll with certmonger not installed": {args: []string{"enroll", "keypress", "example.com"}, missingCertmonger: true},
		"Enroll with cepces not installed":     {args: []string{"enroll", "keypress", "example.com"}, missingCepces: true},

		// Error cases
		"Error on missing arguments": {args: []string{"enroll"}, wantErr: true},
		"Error on invalid flags":     {args: []string{"enroll", "keypress", "example.com", "--invalid_flag"}, wantErr: true},
		"Error on invalid JSON":      {args: []string{"enroll", "keypress", "example.com", "--policy_servers_json", "invalid_json"}, wantErr: true},
		"Error on invalid JSON keys": {
			args: []string{"enroll", "keypress", "example.com", "--policy_servers_json", `[{"key":"Software\\Policies\\Microsoft","value":"MyValue"}]`}, wantErr: true},
		"Error on invalid JSON structure": {
			args: []string{"enroll", "keypress", "example.com", "--policy_servers_json", `{"key":"Software\\Policies\\Microsoft","value":"MyValue"}`}, wantErr: true},
		"Error on read-only path":   {readOnlyPath: true, args: []string{"enroll", "keypress", "example.com"}, wantErr: true},
		"Error on enroll failure":   {autoenrollError: true, args: []string{"enroll", "keypress", "example.com"}, wantErr: true},
		"Error on unenroll failure": {autoenrollError: true, args: []string{"unenroll", "keypress", "example.com"}, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir()
			sambaCacheDir := filepath.Join(stateDir, "samba")
			globalTrustDir := filepath.Join(stateDir, "ca-certificates")
			binDir := t.TempDir()
			if !tc.missingCertmonger {
				// #nosec G306. We want this asset to be executable.
				err := os.WriteFile(filepath.Join(binDir, "getcert"), []byte("#!/bin/sh\necho $@\n"), 0755)
				require.NoError(t, err, "Setup: could not create getcert binary")
			}
			if !tc.missingCepces {
				// #nosec G306. We want this asset to be executable.
				err := os.WriteFile(filepath.Join(binDir, "cepces-submit"), []byte("#!/bin/sh\necho $@\n"), 0755)
				require.NoError(t, err, "Setup: could not create cepces binary")
			}

			// Create a dummy cache file to ensure we don't fail when removing a non-empty directory
			testutils.CreatePath(t, filepath.Join(sambaCacheDir, "cert_gpo_state_HOST.tdb"))

			if tc.readOnlyPath {
				testutils.MakeReadOnly(t, stateDir)
			}

			args := append(tc.args, "--state_dir", stateDir, "--global_trust_dir", globalTrustDir)

			// #nosec G204: we control the command line name and only change it for tests
			cmd := exec.Command(certAutoenrollCmd, args...)
			cmd.Env = append(os.Environ(),
				"PYTHONPATH="+pythonPath,
				"PATH="+binDir+":"+os.Getenv("PATH"),
			)
			if tc.autoenrollError {
				cmd.Env = append(os.Environ(), "ADSYS_WANT_AUTOENROLL_ERROR=1")
			}
			out, err := cmd.CombinedOutput()
			if tc.wantErr {
				require.Error(t, err, "cert-autoenroll should have failed but didn’t")
				return
			}
			require.NoErrorf(t, err, "cert-autoenroll should have exited successfully: %s", string(out))

			got := strings.ReplaceAll(string(out), stateDir, "#STATEDIR#")
			want := testutils.LoadWithUpdateFromGolden(t, got)
			require.Equal(t, want, got, "Unexpected output from cert-autoenroll script")

			if slices.Contains(tc.args, "unenroll") {
				require.NoDirExists(t, sambaCacheDir, "Samba cache directory should have been removed on unenroll")
			}
		})
	}
}
