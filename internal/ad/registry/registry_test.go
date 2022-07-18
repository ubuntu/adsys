package registry_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad/registry"
	"github.com/ubuntu/adsys/internal/policies/entry"
)

func TestDecodePolicy(t *testing.T) {
	t.Parallel()

	defaultKey := `Software/Canonical/Ubuntu/ValueName`
	defaultData := "BA"
	tests := map[string]struct {
		want         []entry.Entry
		wantErr      bool
		wantEntryErr bool
	}{
		"one element, string value": {
			want: []entry.Entry{
				{
					Key:   defaultKey,
					Value: defaultData,
				},
			}},
		"one element, decimal value": {
			want: []entry.Entry{
				{
					Key:   defaultKey,
					Value: "1234",
				},
			}},
		"one element, multitext value": {
			want: []entry.Entry{
				{
					Key:   defaultKey,
					Value: "B\nA",
				},
			}},
		"two elements": {
			want: []entry.Entry{
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
			want: []entry.Entry{
				{
					Key:      defaultKey,
					Value:    "",
					Disabled: true,
				},
			}},

		// basic type: no container, no children
		"basic type, enabled": {
			want: []entry.Entry{
				{
					Key:      `Software/Policies/Ubuntu/privilege/allow-local-admins/all`,
					Value:    "",
					Disabled: false,
					Meta:     "foo",
				},
			}},
		"basic type, disabled": {
			want: []entry.Entry{
				{
					Key:      `Software/Policies/Ubuntu/privilege/allow-local-admins/all`,
					Value:    "",
					Disabled: true,
				},
			}},
		"basic type with default value has value filed in": {
			want: []entry.Entry{
				{
					Key:      `Software/Policies/Ubuntu/privilege/allow-local-admins/all`,
					Value:    "Default Value",
					Disabled: false,
					Meta:     "foo",
				},
			}},
		"basic type with default value needs a DISABLED marker": {
			want: []entry.Entry{
				{
					Key:      `Software/Policies/Ubuntu/privilege/allow-local-admins/all`,
					Value:    "", // Value is ignored
					Disabled: true,
				},
			}},
		"basic type with a DISABLED marker keeps meta and strategy": {
			want: []entry.Entry{
				{
					Key:      `Software/Policies/Ubuntu/privilege/allow-local-admins/all`,
					Disabled: true,
					Meta:     "foo",
					Strategy: "append",
				},
			}},
		"basic type with strategy": {
			want: []entry.Entry{
				{
					Key:      `Software/Policies/Ubuntu/privilege/allow-local-admins/all`,
					Value:    "",
					Meta:     "foo",
					Strategy: "override",
				},
			}},
		"basic type is ignored for meta of wrong type": {
			want: nil},

		// Container and options test cases
		"container with default elements override empty option values": {
			want: []entry.Entry{
				{
					Key:   `Software/Container/Child`,
					Value: "containerDefaultValueForChild",
				},
			}},
		"container with default elements are ignored on non empty option values": {
			want: []entry.Entry{
				{
					Key:   `Software/Container/Child`,
					Value: "MyValue",
				},
			}},
		"container with missing default element for option values have empty strings": {
			want: []entry.Entry{
				{
					Key:   `Software/Container/Child2`,
					Value: "",
				},
			}},
		"container with default elements are ignored on int option values (always have values)": {
			want: []entry.Entry{
				{
					Key:   `Software/Container/Child`,
					Value: "2",
				},
			}},
		"container strategy is reflected on child": {
			want: []entry.Entry{
				{
					Key:      `Software/Container/Child`,
					Value:    "MyValue",
					Strategy: "override",
				},
			}},
		// This ignores child value because container is disabled
		"disabled container with disabled option values": {
			want: []entry.Entry{
				{
					Key:      `Software/Container/Child`,
					Value:    "",
					Disabled: true,
				},
			}},
		// Both container and child are disabled
		"disabled container disables its option values": {
			want: []entry.Entry{
				{
					Key:      `Software/Container/Child`,
					Value:    "",
					Disabled: true,
				},
			}},
		"disabled container with values needs a DISABLED marker": {
			want: []entry.Entry{
				{
					Key:      `Software/Container/Child`,
					Value:    "", // Value is ignored
					Disabled: true,
				},
			}},
		"disabled container with values still keep meta and strategy with a DISABLED marker": {
			want: []entry.Entry{
				{
					Key:      `Software/Container/Child`,
					Disabled: true,
					Meta:     "foo",
					Strategy: "append",
				},
			}},
		"container with meta elements and default without value on options": {
			want: []entry.Entry{
				{
					Key:   `Software/Container/Child`,
					Value: "containerDefaultValueForChild",
					Meta:  "containerMetaValueForChild",
				},
			}},
		"container with meta elements and value on options": {
			want: []entry.Entry{
				{
					Key:   `Software/Container/Child`,
					Value: "MyValue",
					Meta:  "containerMetaValueForChild",
				},
			}},
		"container without metavalues": {
			want: []entry.Entry{
				{
					Key:   `Software/Container/Child`,
					Value: "MyValue",
					Meta:  "",
				},
			}},
		"policy container is ignored for meta of wrong type": {
			want: []entry.Entry{
				{
					Key:   `Software/Container/Child`,
					Value: "MyValue",
					Meta:  "",
				},
			}},

		"one container with 2 children don’t mix their default values": {
			want: []entry.Entry{
				{
					Key:   `Software/Container1/Child1`,
					Value: "container1DefaultValueForChild1",
				},
				{
					Key:   `Software/Container1/Child2`,
					Value: "container1DefaultValueForChild2",
				},
			}},
		"two containers don’t mix their default values when redefined": {
			want: []entry.Entry{
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
		"two containers don’t mix their default values even when second has none": {
			want: []entry.Entry{
				{
					Key:   `Software/Container1/Child1`,
					Value: "container1DefaultValueForChild1",
				},
				{
					Key:   `Software/Container1/Child2`,
					Value: "container1DefaultValueForChild2",
				},
				{
					Key: `Software/Container2/Child1`,
					// No empty value inherited from Container 1, as Container 2 meta is nil
					Value: "",
				},
				{
					Key: `Software/Container2/Child2`,
					// we didn't set default values for Child2 on Container2: keep empty (no leftover for Child1)
					Value: "",
				},
			}},
		"one container with 2 children don’t mix their meta values": {
			want: []entry.Entry{
				{
					Key:  `Software/Container1/Child1`,
					Meta: "container1MetaValueForChild1",
				},
				{
					Key:  `Software/Container1/Child2`,
					Meta: "container1MetaValueForChild2",
				},
			}},
		"two containers don’t mix their meta values, even if second has none": {
			want: []entry.Entry{
				{
					Key:  `Software/Container1/Child1`,
					Meta: "foo",
				},
				{
					Key:  `Software/Container1/Child2`,
					Meta: "bar",
				},
				{
					Key:  `Software/Container2/Child1`,
					Meta: "",
				},
				{
					Key:  `Software/Container2/Child2`,
					Meta: "",
				},
			}},

		"semicolon in data": {
			want: []entry.Entry{
				{
					Key:   defaultKey,
					Value: "B;A",
				},
			}},

		"section separators in data": {
			want: []entry.Entry{
				{
					Key:   defaultKey,
					Value: "BA][C]",
				},
			}},

		// Empty/void data cases
		"empty data": {
			want: []entry.Entry{
				{
					Key: defaultKey,
				},
			}},
		"null character in data": {
			want: []entry.Entry{
				{
					Key: defaultKey,
				},
			}},

		"header only": {},

		// Soft error cases
		"empty value": {
			wantEntryErr: true,
			want: []entry.Entry{
				{
					Key:   `Software/Canonical/Ubuntu`,
					Value: defaultData,
				},
			},
		},
		"exotic return type": {
			wantEntryErr: true,
			want: []entry.Entry{
				{
					Key: defaultKey,
				},
			},
		},

		// Error cases
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

			if tc.wantEntryErr {
				var found bool
				for i, r := range rules {
					if r.Err != nil {
						found = true

						// Don't serialize errors when comparing policy entries
						r.Err = nil
						rules[i] = r
					}
				}

				require.True(t, found, "readPolicy returned no entry error when expecting one")
			}

			require.Equalf(t, tc.want, rules, "expected value from readPolicy doesn't match")
		})
	}
}

func FuzzDecodePolicy(f *testing.F) {
	// To seed the corpus, we need to read the example files.
	policyfiles, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatalf("could not read testdata content: %v", err)
	}
	for _, pf := range policyfiles {
		if pf.IsDir() {
			continue
		}
		d, err := os.ReadFile(filepath.Join("testdata", pf.Name()))
		if err != nil {
			f.Fatalf("coudln't read policy file: %v", err)
		}
		f.Add(d)
	}

	f.Fuzz(func(t *testing.T, d []byte) {
		r := bytes.NewReader(d)
		_, _ = registry.DecodePolicy(r)
	})
}

func policyFilePath(name string) string {
	return filepath.Join("testdata", strings.ReplaceAll(strings.ReplaceAll(name, ",", "_"), " ", "_")+".pol")
}
