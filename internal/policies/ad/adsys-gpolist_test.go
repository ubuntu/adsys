package ad_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/ad"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestAdsysGPOList(t *testing.T) {
	coverageOn := testutils.CoverageToGoFormat(t, "adsys-gpolist")
	adsysGPOListcmd := "./adsys-gpolist"
	if coverageOn {
		adsysGPOListcmd = "adsys-gpolist"
	}

	// Setup samba mock
	orig := os.Getenv("PYTHONPATH")
	p, err := filepath.Abs("testdata/adsys-gpolist/mock")
	require.NoError(t, err, "Setup: Failed to get current absolute path for mock")
	require.NoError(t, os.Setenv("PYTHONPATH", p), "Setup: Failed to set $PYTHONPATH")
	t.Cleanup(func() {
		require.NoError(t, os.Setenv("PYTHONPATH", orig), "Teardown: can't restore PYTHONPATH to original value")
	})

	tests := map[string]struct {
		url         string
		accountName string
		objectClass string

		wantErr bool
	}{
		"Return one gpo": {
			accountName: "UserAtRoot",
		},

		"Return hierarchy": {
			accountName: "RnDUser",
		},
		"Multiple GPOs in same OU": {
			accountName: "RnDUserDep1",
		},

		"Machine GPOs": {
			accountName: "hostname1",
			objectClass: "computer",
		},

		"Disabled GPOs": {
			accountName: "RnDUserDep3",
		},

		"No GPO on OU": {
			accountName: "UserNoGPO",
		},

		// Filtering cases
		"Filter user only GPOs": {
			accountName: "hostname2",
			objectClass: "computer",
		},
		"Filter machine only GPOs": {
			accountName: "RnDUserDep7",
		},

		// Forced GPOs and inheritance handling
		"Forced GPO are first by reverse order": {
			accountName: "RndUserSubDep2ForcedPolicy",
		},
		"Block inheritance": {
			accountName: "RnDUserWithBlockedInheritance",
		},
		"Forced GPO and blocked inheritance": {
			accountName: "RnDUserWithBlockedInheritanceAndForcedPolicies",
		},

		// Access cases
		"Security descriptor missing ignores GPO": { // AD is doing that for windows client
			accountName: "RnDUserDep4",
		},
		"Fail on security descriptor access failure": {
			accountName: "RnDUserDep5",
			wantErr:     true,
		},
		"Security descriptor access denied ignores GPO": {
			accountName: "RnDUserDep6",
		},
		"Security descriptor accepted is for another user": {
			accountName: "RnDUserDep8",
		},

		"No gPOptions fallbacks to 0": {
			accountName: "UserNogPOptions",
		},

		// Error cases
		"Fail on unreachable ldap": {
			url:         "ldap://unreachable_url",
			accountName: "bob",
			wantErr:     true,
		},
		"Fail on non existent account": {
			accountName: "nonexistent",
			wantErr:     true,
		},
		"Fail on user requested but found machine": {
			accountName: "hostname1",
			objectClass: "user",
			wantErr:     true,
		},
		"Fail on computer requested but found user": {
			accountName: "UserAtRoot",
			objectClass: "computer",
			wantErr:     true,
		},
		"Fail invalid GPO link": {
			accountName: "UserInvalidLink",
			wantErr:     true,
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

			got, err := exec.Command(adsysGPOListcmd, "--objectclass", tc.objectClass, tc.url, tc.accountName).CombinedOutput()
			if tc.wantErr {
				require.Error(t, err, "adsys-gpostlist should have failed but didn’t")
				return
			}
			require.NoErrorf(t, err, "adsys-gpostlist should exit successfully: %v", string(got))

			// check collected output between FormatGPO calls
			goldPath := filepath.Join("testdata", "adsys-gpolist", "golden", name)
			// Update golden file
			if ad.Update {
				t.Logf("updating golden file %s", goldPath)
				err = os.WriteFile(goldPath, got, 0644)
				require.NoError(t, err, "Cannot write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load policy golden file")

			require.Equal(t, string(want), string(got), "adsys-gpolist expected output")

		})
	}
}
