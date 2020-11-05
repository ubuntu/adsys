package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadPolicy(t *testing.T) {
	t.Parallel()

	defaultPath := `Software\Canonical\Ubuntu`
	defaultKey := `ValueName`
	defaultData := []byte("B\x00A\x00\x00\x00")
	tests := map[string]struct {
		want    []policyRawEntry
		wantErr bool
	}{
		"one element, string value": {
			want: []policyRawEntry{
				{
					path:  defaultPath,
					key:   defaultKey,
					dType: dataType(1),
					data:  defaultData,
				},
			}},
		"one element, decimal value": {
			want: []policyRawEntry{
				{
					path:  defaultPath,
					key:   defaultKey,
					dType: dataType(4),
					data:  []byte("\xd2\x04\x00\x00"),
				},
			}},
		"two elements": {
			want: []policyRawEntry{
				{
					path:  defaultPath,
					key:   defaultKey,
					dType: dataType(4),
					data:  []byte("\x01\x00\x00\x00"),
				},
				{
					path:  `Software\Policies\Canonical\Ubuntu\Directory UI`,
					key:   "QueryLimit",
					dType: dataType(4),
					data:  []byte("\x39\x30\x00\x00"),
				},
			}},

		"semicolon in data": {
			want: []policyRawEntry{
				{
					path:  defaultPath,
					key:   defaultKey,
					dType: dataType(1),
					data:  []byte("B\x00;\x00A\x00\x00\x00"),
				},
			}},

		"section separators in data": {
			want: []policyRawEntry{
				{
					path:  defaultPath,
					key:   defaultKey,
					dType: dataType(1),
					data:  []byte("B\x00A\x00]\x00[\x00C\x00]\x00\x00\x00"),
				},
			}},

		"exotic return type": {
			want: []policyRawEntry{
				{
					path:  defaultPath,
					key:   defaultKey,
					dType: dataType(153), //<- This is really 0x99
					data:  defaultData,
				},
			}},
		"header only": {},

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

			rules, err := readPolicy(f)
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
