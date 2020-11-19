package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/policy"
	"github.com/ubuntu/adsys/internal/policies/registry"
)

func TestDecodePolicy(t *testing.T) {
	t.Parallel()

	defaultKey := `Software/Canonical/Ubuntu/ValueName`
	defaultData := "BA"
	tests := map[string]struct {
		want    []policy.Entry
		wantErr bool
	}{
		"one element, string value": {
			want: []policy.Entry{
				{
					Key:   defaultKey,
					Value: defaultData,
				},
			}},
		"one element, decimal value": {
			want: []policy.Entry{
				{
					Key:   defaultKey,
					Value: "1234",
				},
			}},
		"two elements": {
			want: []policy.Entry{
				{
					Key:   defaultKey,
					Value: "1",
				},
				{
					Key:   `Software/Policies/Canonical/Ubuntu/Directory UI/QueryLimit`,
					Value: "12345",
				},
			}},
		"one element, disabled": {
			want: []policy.Entry{
				{
					Key:      defaultKey,
					Value:    "",
					Disabled: true,
				},
			}},

		// Container and options test cases
		"container with default elements override empty option values": {
			want: []policy.Entry{
				{
					Key:   `Software/Container/Child`,
					Value: "containerDefaultValueForChild",
				},
			}},
		"container with default elements are ignored on non empty option values": {
			want: []policy.Entry{
				{
					Key:   `Software/Container/Child`,
					Value: "MyValue",
				},
			}},
		"container with missing default element for option values have empty strings": {
			want: []policy.Entry{
				{
					Key:   `Software/Container/Child2`,
					Value: "",
				},
			}},
		"container with default elements are ignored on int option values (always have values)": {
			want: []policy.Entry{
				{
					Key:   `Software/Container/Child`,
					Value: "2",
				},
			}},
		"disabled container disables its option values": {
			want: []policy.Entry{
				{
					Key:      `Software/Container/Child`,
					Value:    "",
					Disabled: true,
				},
			}},
		"two containers don’t mix their default values when redefined": {
			want: []policy.Entry{
				{
					Key:   `Software/Container1/Child1`,
					Value: "container1DefaultValueForChild1",
				},
				{
					Key:   `Software/Container1/Child2`,
					Value: "container1DefaultValueForChild2",
				},
				{
					Key:   `Software/Container2/Child1`,
					Value: "container2DefaultValueForChild1",
				},
				{
					Key: `Software/Container2/Child2`,
					// we didn't set default values for Child2 on Container2: keep empty (no leftover for Child1)
					Value: "",
				},
			}},

		"semicolon in data": {
			want: []policy.Entry{
				{
					Key:   defaultKey,
					Value: "B;A",
				},
			}},

		"section separators in data": {
			want: []policy.Entry{
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
		"invalid container default values":    {wantErr: true},
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
