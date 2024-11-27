package privilege

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitAndNormalizeUsersAndGroups(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input string

		want []string
	}{
		// string cases
		"Simple one value":                            {input: "user@domain", want: []string{"user@domain"}},
		"Group one value":                             {input: "%group@domain", want: []string{"%group@domain"}},
		"Empty value":                                 {input: "", want: nil},
		"Multiple values separated by comma":          {input: "user1@domain,user2@domain", want: []string{"user1@domain", "user2@domain"}},
		"Multiple values separated by EOL":            {input: "user1@domain\nuser2@domain", want: []string{"user1@domain", "user2@domain"}},
		"Multiple values with a mix of comma and EOL": {input: "user1@domain,user2@domain\nuser3@domain", want: []string{"user1@domain", "user2@domain", "user3@domain"}},

		// domain handling
		`Handle domain\user`: {input: `domain\user`, want: []string{"user@domain"}},
		`Multiple \ only handling first one and ignore others`: {input: `domain\user\foo`, want: []string{`userfoo@domain`}},

		// edge cases
		"User name with space":                    {input: "user name@domain", want: []string{"user name@domain"}},
		"Empty value with comma":                  {input: ",", want: nil},
		"Empty value with EOL":                    {input: "\n", want: nil},
		"Multiple values with consecutives EOL":   {input: "user1@domain\n\nuser2@domain", want: []string{"user1@domain", "user2@domain"}},
		"Multiple values with consecutives comma": {input: "user1@domain,,user2@domain", want: []string{"user1@domain", "user2@domain"}},
		"Strip empty values":                      {input: "user1@domain,,", want: []string{"user1@domain"}},

		// forbidden characters: "/", "[", "]", ":", "|", "<", ">", "=", ";", "?", "*", "%"
		"Strip any /":                    {input: `u/s/er@domain`, want: []string{`user@domain`}},
		"Strip any [":                    {input: `u[s]er@domain`, want: []string{`user@domain`}},
		"Strip any ]":                    {input: `u]s]er@domain`, want: []string{`user@domain`}},
		"Strip any :":                    {input: `u:s:er@domain`, want: []string{`user@domain`}},
		"Strip any |":                    {input: `u|s|er@domain`, want: []string{`user@domain`}},
		"Strip any <":                    {input: `u<s<er@domain`, want: []string{`user@domain`}},
		"Strip any >":                    {input: `u>s>er@domain`, want: []string{`user@domain`}},
		"Strip any =":                    {input: `u=s=er@domain`, want: []string{`user@domain`}},
		"Strip any ;":                    {input: `u;s;er@domain`, want: []string{`user@domain`}},
		"Strip any ?":                    {input: `u?s?er@domain`, want: []string{`user@domain`}},
		"Strip any *":                    {input: `u*s*er@domain`, want: []string{`user@domain`}},
		"Strip any %":                    {input: `u%s%er@domain`, want: []string{`user@domain`}},
		"Don’t strip first % but others": {input: `%g%r%oup@domain`, want: []string{`%group@domain`}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := splitAndNormalizeUsersAndGroups(context.Background(), tc.input)
			assert.Equal(t, tc.want, got, "splitAndNormalizeUsersAndGroups returned expected value")
		})
	}
}

func TestGetSystemPolkitAdminIdentities(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		policyKitDir string

		want    string
		wantErr bool
	}{
		"Fetch previous admin identities": {policyKitDir: "testdata/existing-previous-local-admins-one/polkit-1",
			want: "unix-user:local50admin1;unix-user:local50admin2"},
		"Fetch previous admin identities from highest ascii file": {policyKitDir: "testdata/existing-previous-local-admins-multi/polkit-1",
			want: "unix-user:local50admin1;unix-user:local50admin2"},
		"Fetch previous admin identities ignoring adsys": {policyKitDir: "testdata/existing-previous-local-admins-with-adsys-file/polkit-1",
			want: "unix-user:local50admin1;unix-user:local50admin2"},

		// Edge cases
		"No previous admin identities but regular directory structure": {policyKitDir: "testdata/existing-other-files/polkit-1",
			want: ""},
		"Returns an empty string if directory does not exists": {policyKitDir: "testdata/doesnotexists",
			want: ""},
		"Directory instead of a conf file is ignored": {policyKitDir: "testdata/incorrect-policikit-conf-is-dir/polkit-1",
			want: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := getSystemPolkitAdminIdentities(context.Background(), tc.policyKitDir)
			if tc.wantErr {
				require.NotNil(t, err, "getSystemPolkitAdminIdentities should have failed but didn't")
				return
			}
			require.NoError(t, err, "ApplyPolicy failed but shouldn't have")

			assert.Equal(t, tc.want, got, "getSystemPolkitAdminIdentities returned expected value")
		})
	}
}

func TestPolkitAdminIdentitiesFromRules(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		policyKitDirs []string

		emptyReturn bool
	}{
		"Fetch previous admin identities": {
			policyKitDirs: []string{"existing-previous-local-admins-one/etc/polkit-1"},
		},
		"Fetch previous admin identities from lower ascii file": {
			policyKitDirs: []string{"existing-previous-local-admins-multi/etc/polkit-1"},
		},
		"Fetch previous admin identities ignoring adsys": {
			policyKitDirs: []string{"existing-previous-local-admins-with-adsys-file/etc/polkit-1"},
		},

		// Rules-specific cases
		"Consider only first returned value": {
			policyKitDirs: []string{"existing-previous-local-admins-return-early/etc/polkit-1"},
		},
		"Prioritize first specified directory if files have same ascii": {
			policyKitDirs: []string{"multiple-polkit-dirs-same-file/etc/polkit-1", "multiple-polkit-dirs-same-file/etc/polkit-2"},
		},
		"Prioritize lower ascii file even if on second directory": {
			policyKitDirs: []string{"multiple-polkit-dirs-diff-file/etc/polkit-1", "multiple-polkit-dirs-diff-file/etc/polkit-2"},
		},

		// Edge cases
		"No previous admin identities but regular directory structure": {
			policyKitDirs: []string{"existing-other-files/etc/polkit-1"},
			emptyReturn:   true,
		},
		"Returns an empty string if directory does not exists": {
			policyKitDirs: []string{"doesnotexists"},
			emptyReturn:   true,
		},
		"Directory instead of a conf file is ignored": {
			policyKitDirs: []string{"incorrect-policikit-conf-is-dir/etc/polkit-1"},
			emptyReturn:   true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for i, dir := range tc.policyKitDirs {
				tc.policyKitDirs[i] = filepath.Join("testdata", dir)
			}

			got, err := polkitAdminIdentitiesFromRules(context.Background(), tc.policyKitDirs)
			require.NoError(t, err, "getSystemPolkitAdminIdentities failed but shouldn't have")

			if tc.emptyReturn {
				require.Empty(t, got)
				return
			}
			want := testutils.LoadWithUpdateFromGolden(t, got)
			require.Equal(t, want, got)
		})
	}
}
