package privilege

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitAndNormalizeUsersAndGroups(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input string

		want []string
	}{
		// string cases
		"simple one value":                            {input: "user@domain", want: []string{"user@domain"}},
		"group one value":                             {input: "%group@domain", want: []string{"%group@domain"}},
		"empty value":                                 {input: "", want: nil},
		"multiple values separated by comma":          {input: "user1@domain,user2@domain", want: []string{"user1@domain", "user2@domain"}},
		"multiple values separated by EOL":            {input: "user1@domain\nuser2@domain", want: []string{"user1@domain", "user2@domain"}},
		"multiple values with a mix of comma and EOL": {input: "user1@domain,user2@domain\nuser3@domain", want: []string{"user1@domain", "user2@domain", "user3@domain"}},

		// domain handling
		`domain\user handling`:                                 {input: `domain\user`, want: []string{"user@domain"}},
		`multiple \ only handling first one and ignore others`: {input: `domain\user\foo`, want: []string{`userfoo@domain`}},

		// edge cases
		"user name with space":                    {input: "user name@domain", want: []string{"user name@domain"}},
		"empty value with comma":                  {input: ",", want: nil},
		"empty value with EOL":                    {input: "\n", want: nil},
		"multiple values with consecutives EOL":   {input: "user1@domain\n\nuser2@domain", want: []string{"user1@domain", "user2@domain"}},
		"multiple values with consecutives comma": {input: "user1@domain,,user2@domain", want: []string{"user1@domain", "user2@domain"}},
		"strip empty values":                      {input: "user1@domain,,", want: []string{"user1@domain"}},

		// forbidden characters: "/", "[", "]", ":", "|", "<", ">", "=", ";", "?", "*", "%"
		"strip any /":                    {input: `u/s/er@domain`, want: []string{`user@domain`}},
		"strip any [":                    {input: `u[s]er@domain`, want: []string{`user@domain`}},
		"strip any ]":                    {input: `u]s]er@domain`, want: []string{`user@domain`}},
		"strip any :":                    {input: `u:s:er@domain`, want: []string{`user@domain`}},
		"strip any |":                    {input: `u|s|er@domain`, want: []string{`user@domain`}},
		"strip any <":                    {input: `u<s<er@domain`, want: []string{`user@domain`}},
		"strip any >":                    {input: `u>s>er@domain`, want: []string{`user@domain`}},
		"strip any =":                    {input: `u=s=er@domain`, want: []string{`user@domain`}},
		"strip any ;":                    {input: `u;s;er@domain`, want: []string{`user@domain`}},
		"strip any ?":                    {input: `u?s?er@domain`, want: []string{`user@domain`}},
		"strip any *":                    {input: `u*s*er@domain`, want: []string{`user@domain`}},
		"strip any %":                    {input: `u%s%er@domain`, want: []string{`user@domain`}},
		"don’t strip first % but others": {input: `%g%r%oup@domain`, want: []string{`%group@domain`}},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := splitAndNormalizeUsersAndGroups(tc.input)
			assert.Equal(t, tc.want, got, "splitAndNormalizeUsersAndGroups returned expected value")
		})
	}
}
