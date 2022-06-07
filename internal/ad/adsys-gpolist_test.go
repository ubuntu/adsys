package ad_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestAdsysGPOList(t *testing.T) {
	coverageOn := testutils.PythonCoverageToGoFormat(t, "adsys-gpolist", false)
	adsysGPOListcmd := "./adsys-gpolist"
	if coverageOn {
		adsysGPOListcmd = "adsys-gpolist"
	}

	// Setup samba mock
	p, err := filepath.Abs("../testutils/admock")
	require.NoError(t, err, "Setup: Failed to get current absolute path for mock")
	testutils.Setenv(t, "PYTHONPATH", p)
	testutils.Setenv(t, "ADSYS_TESTS_MOCK_SMBDOMAIN", "gpoonly.com")

	tests := map[string]struct {
		url             string
		accountName     string
		objectClass     string
		krb5ccNameState string

		wantErr        bool
		wantReturnCode int
	}{
		"Return one gpo": {
			accountName: "UserAtRoot@GPOONLY.COM",
		},

		"Return hierarchy": {
			accountName: "RnDUser@GPOONLY.COM",
		},
		"Multiple GPOs in same OU": {
			accountName: "RnDUserDep1@GPOONLY.COM",
		},

		"Machine GPOs": {
			accountName: "hostname1",
			objectClass: "computer",
		},

		"Disabled GPOs": {
			accountName: "RnDUserDep3@GPOONLY.COM",
		},

		// Empty GPOs return an empty bytes field or a space depending on the client
		// so we need to test both.
		"No GPO on OU - bytes": {
			accountName: "UserNoGPO@GPOONLY.COM",
		},

		"No GPO on OU - string": {
			accountName: "UserNoGPOString@GPOONLY.COM",
		},

		// Filtering cases
		"Filter user only GPOs": {
			accountName: "hostname2",
			objectClass: "computer",
		},
		"Filter machine only GPOs": {
			accountName: "RnDUserDep7@GPOONLY.COM",
		},

		// Forced GPOs and inheritance handling
		"Forced GPO are first by reverse order": {
			accountName: "RndUserSubDep2ForcedPolicy@GPOONLY.COM",
		},
		"Block inheritance": {
			accountName: "RnDUserWithBlockedInheritance@GPOONLY.COM",
		},
		"Forced GPO and blocked inheritance": {
			accountName: "RnDUserWithBlockedInheritanceAndForcedPolicies@GPOONLY.COM",
		},

		// Access cases
		"Security descriptor missing ignores GPO": { // AD is doing that for windows client
			accountName: "RnDUserDep4@GPOONLY.COM",
		},
		"Fail on security descriptor access failure": {
			accountName:    "RnDUserDep5@GPOONLY.COM",
			wantReturnCode: 3,
			wantErr:        true,
		},
		"Security descriptor access denied ignores GPO": {
			accountName: "RnDUserDep6@GPOONLY.COM",
		},
		"Security descriptor accepted is for another user": {
			accountName: "RnDUserDep8@GPOONLY.COM",
		},

		"No gPOptions fallbacks to 0": {
			accountName: "UserNogPOptions@GPOONLY.COM",
		},

		"KRB5CCNAME without FILE: is supported by the samba bindings": {
			accountName:     "UserAtRoot@GPOONLY.COM",
			krb5ccNameState: "invalidenvformat",
		},

		// Special object name cases
		"No @ in user name returns the same thing": {
			accountName: "UserAtRoot",
		},
		"Computers truncated at 15 characters": {
			accountName: "hostnameWithTruncatedLongName",
			objectClass: "computer",
		},
		"Long computer name, not truncated": {
			accountName: "hostnameWithLongName",
			objectClass: "computer",
		},

		// Error cases
		"Fail on no network": {
			url:            "ldap://NT_STATUS_NETWORK_UNREACHABLE",
			accountName:    "UserAtRoot@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},
		"Fail on unreachable ldap host": {
			url:            "ldap://NT_STATUS_HOST_UNREACHABLE",
			accountName:    "UserAtRoot@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},
		"Fail on ldap connection refused": {
			url:            "ldap://NT_STATUS_CONNECTION_REFUSED",
			accountName:    "UserAtRoot@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},
		"Fail on machine with no ldap": {
			url:            "ldap://NT_STATUS_OBJECT_NAME_NOT_FOUND",
			accountName:    "UserAtRoot@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},

		"Fail on non existent account": {
			accountName:    "nonexistent@GPOONLY.COM",
			wantReturnCode: 1,
			wantErr:        true,
		},
		"Fail on user requested but found machine": {
			accountName:    "hostname1",
			objectClass:    "user",
			wantReturnCode: 1,
			wantErr:        true,
		},
		"Fail on computer requested but found user": {
			accountName:    "UserAtRoot@GPOONLY.COM",
			objectClass:    "computer",
			wantReturnCode: 1,
			wantErr:        true,
		},
		"Fail invalid GPO link": {
			accountName:    "UserInvalidLink@GPOONLY.COM",
			wantReturnCode: 3,
			wantErr:        true,
		},

		"Fail on KRB5CCNAME unset": {
			accountName:     "UserAtRoot@GPOONLY.COM",
			krb5ccNameState: "unset",
			wantReturnCode:  1,
			wantErr:         true,
		},
		"Fail on invalid ticket": {
			accountName:     "UserAtRoot@GPOONLY.COM",
			krb5ccNameState: "invalid",
			wantReturnCode:  1,
			wantErr:         true,
		},
		"Fail on dangling ticket symlink": {
			accountName:     "UserAtRoot@GPOONLY.COM",
			krb5ccNameState: "dangling",
			wantReturnCode:  1,
			wantErr:         true,
		},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.objectClass == "" {
				tc.objectClass = "user"
			}
			if tc.url == "" {
				tc.url = "ldap://ldap_url"
			}

			// Ticket creation for mock
			if tc.krb5ccNameState != "unset" {
				krb5dir := t.TempDir()
				krb5file := filepath.Join(krb5dir, "krb5file")
				krb5symlink := filepath.Join(krb5dir, "krb5symlink")
				content := "Some data for the mock"
				if tc.krb5ccNameState == "invalid" {
					content = "Some invalid ticket content for the mock"
				}
				if tc.krb5ccNameState != "dangling" {
					err = os.WriteFile(krb5file, []byte(content), 0600)
					require.NoError(t, err, "Setup: could not set create krb5file")
				}

				err = os.Symlink(krb5file, krb5symlink)
				require.NoError(t, err, "Setup: could not set krb5 file adsys symlink")

				krb5ccname := fmt.Sprintf("FILE:%s", krb5symlink)
				if tc.krb5ccNameState == "invalidenvformat" {
					krb5ccname = krb5symlink
				}

				testutils.Setenv(t, "KRB5CCNAME", krb5ccname)
			}

			// #nosec G204: we control the command line name and only change it for tests
			cmd := exec.Command(adsysGPOListcmd, "--objectclass", tc.objectClass, tc.url, tc.accountName)
			got, err := cmd.CombinedOutput()
			if tc.wantErr {
				require.Error(t, err, "adsys-gpostlist should have failed but didn’t")
				return
			}
			require.NoErrorf(t, err, "adsys-gpostlist should exit successfully: %v", string(got))
			assert.Equal(t, tc.wantReturnCode, cmd.ProcessState.ExitCode(), "adsys-gpostlist returns expected exit code")

			// check collected output between FormatGPO calls
			goldPath := filepath.Join("testdata", "adsys-gpolist", "golden", testutils.NormalizeGoldenName(t, name))
			// Update golden file
			if ad.Update {
				t.Logf("updating golden file %s", goldPath)
				err = os.WriteFile(goldPath, got, 0600)
				require.NoError(t, err, "Cannot write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load policy golden file")

			require.Equal(t, string(want), string(got), "adsys-gpolist expected output")
		})
	}
}
