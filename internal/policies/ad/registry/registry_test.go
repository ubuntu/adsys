package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/ad/registry"
)

func TestDecodePolicy(t *testing.T) {
	t.Parallel()

	defaultKey := `Software/Canonical/Ubuntu/ValueName`
	defaultData := "BA"
	tests := map[string]struct {
		want    []registry.PolicyEntry
		wantErr bool
	}{
		"one element, string value": {
			want: []registry.PolicyEntry{
				{
					Key:   defaultKey,
					Value: defaultData,
				},
			}},
		"one element, decimal value": {
			want: []registry.PolicyEntry{
				{
					Key:   defaultKey,
					Value: "1234",
				},
			}},
		"two elements": {
			want: []registry.PolicyEntry{
				{
					Key:   defaultKey,
					Value: "1",
				},
				{
					Key:   `Software/Policies/Canonical/Ubuntu/Directory UI/QueryLimit`,
					Value: "12345",
				},
			}},

		"semicolon in data": {
			want: []registry.PolicyEntry{
				{
					Key:   defaultKey,
					Value: "B;A",
				},
			}},

		"section separators in data": {
			want: []registry.PolicyEntry{
				{
					Key:   defaultKey,
					Value: "BA][C]",
				},
			}},
		"header only": {},

		"exotic return type":                  {wantErr: true},
		"invalid decimal value":               {wantErr: true},
		"invalid header, header doesnt match": {wantErr: true},
		"invalid header, header too short":    {wantErr: true},
		"invalid header, file truncated":      {wantErr: true},
		"no header":                           {wantErr: true},
		"empty file":                          {wantErr: true},
		"section not closed":                  {wantErr: true},
		"missing field":                       {wantErr: true},
		"key is not utf16":                    {wantErr: true},
		"value is not utf16":                  {wantErr: true},
		"empty key":                           {wantErr: true},
		"empty value":                         {wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			name := name
			t.Parallel()

			f, err := os.Open(policyFilePath(name))
			if err != nil {
				t.Fatalf("Can't open registry file: %s", policyFilePath(name))
			}
			defer f.Close()

			rules, err := registry.DecodePolicy(f)
			if tc.wantErr {
				require.NotNil(t, err, "readPolicy returned no error when expecting one")
			} else {
				require.NoError(t, err, "readPolicy returned an error when expecting none")
			}

			require.Equalf(t, tc.want, rules, "expected value from readPolicy doesn't match")
		})
	}
}

func policyFilePath(name string) string {
	return filepath.Join("testdata", strings.ReplaceAll(strings.ReplaceAll(name, ",", "_"), " ", "_")+".pol")
}
