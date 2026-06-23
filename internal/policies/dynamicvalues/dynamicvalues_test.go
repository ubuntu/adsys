package dynamicvalues_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/dynamicvalues"
)

func TestExpand(t *testing.T) {
	t.Parallel()

	userCtx := dynamicvalues.Context{
		User:         "bob",
		FQDNUser:     "bob@dom.com",
		Hostname:     "workstation01",
		FQDNHostname: "workstation01.dom.com",
		Domain:       "dom.com",
		IsComputer:   false,
	}
	computerCtx := dynamicvalues.Context{
		Hostname:     "workstation01",
		FQDNHostname: "workstation01.dom.com",
		Domain:       "dom.com",
		IsComputer:   true,
	}

	tests := map[string]struct {
		value string
		ctx   dynamicvalues.Context

		want    string
		wantErr bool
	}{
		// User context, each variable.
		"User variable":          {value: "smb://h/homes/${USER}", ctx: userCtx, want: "smb://h/homes/bob"},
		"FQDN user variable":     {value: "${FQDN_USER}", ctx: userCtx, want: "bob@dom.com"},
		"Hostname variable":      {value: "${HOSTNAME}", ctx: userCtx, want: "workstation01"},
		"FQDN hostname variable": {value: "${FQDN_HOSTNAME}", ctx: userCtx, want: "workstation01.dom.com"},
		"Domain variable":        {value: "${DOMAIN}", ctx: userCtx, want: "dom.com"},

		// Computer context.
		"Hostname in computer policy":      {value: "${HOSTNAME}", ctx: computerCtx, want: "workstation01"},
		"FQDN hostname in computer policy": {value: "${FQDN_HOSTNAME}", ctx: computerCtx, want: "workstation01.dom.com"},
		"Domain in computer policy":        {value: "${DOMAIN}", ctx: computerCtx, want: "dom.com"},

		// Case-insensitivity.
		"Lowercase variable name":  {value: "${user}", ctx: userCtx, want: "bob"},
		"Mixed case variable name": {value: "${User}", ctx: userCtx, want: "bob"},

		// Composition.
		"Multiple tokens in one value": {value: "${USER}@${DOMAIN}", ctx: userCtx, want: "bob@dom.com"},
		"Token adjacent to other text": {value: "/srv/${USER}/cache", ctx: userCtx, want: "/srv/bob/cache"},
		"Repeated tokens":              {value: "${USER}-${USER}", ctx: userCtx, want: "bob-bob"},
		"Value with no tokens":         {value: "smb://h/share", ctx: userCtx, want: "smb://h/share"},
		"Empty value":                  {value: "", ctx: userCtx, want: ""},
		"Value of only a token":        {value: "${USER}", ctx: userCtx, want: "bob"},

		// Things that must be left literal.
		"Lone dollar sign is literal":             {value: "cost is 5$", ctx: userCtx, want: "cost is 5$"},
		"Bare variable without braces literal":    {value: "$USER", ctx: userCtx, want: "$USER"},
		"Dollar then text without braces literal": {value: "a$b", ctx: userCtx, want: "a$b"},
		"URL percent-encoding preserved":          {value: "smb://h/a%20b%2Fc/${USER}", ctx: userCtx, want: "smb://h/a%20b%2Fc/bob"},

		// Error cases.
		"Error on unknown variable":              {value: "${TYPO}", ctx: userCtx, wantErr: true},
		"Error on unterminated placeholder":      {value: "${USER", ctx: userCtx, wantErr: true},
		"Error on empty placeholder":             {value: "${}", ctx: userCtx, wantErr: true},
		"Error on shell default expression":      {value: "${USER:-guest}", ctx: userCtx, wantErr: true},
		"Error on nested-looking placeholder":    {value: "${${USER}}", ctx: userCtx, wantErr: true},
		"Error on user var in computer policy":   {value: "${USER}", ctx: computerCtx, wantErr: true},
		"Error on FQDN user in computer policy":  {value: "${FQDN_USER}", ctx: computerCtx, wantErr: true},
		"Error reported even after valid tokens": {value: "${HOSTNAME}/${TYPO}", ctx: userCtx, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := dynamicvalues.Expand(tc.value, tc.ctx)
			if tc.wantErr {
				require.Error(t, err, "Expand should have returned an error but didn't")
				return
			}
			require.NoError(t, err, "Expand returned an unexpected error")
			require.Equal(t, tc.want, got, "Expand returned an unexpected value")
		})
	}
}
