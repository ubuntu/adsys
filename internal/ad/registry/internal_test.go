package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/unicode"
)

func TestReadPolicy(t *testing.T) {
	t.Parallel()

	defaultPath := `Software\Canonical\Ubuntu`
	defaultKey := `ValueName`
	defaultData := []byte("B\x00A\x00\x00\x00")
	tests := map[string]struct {
		want         []policyRawEntry
		wantErr      bool
		wantEntryErr bool
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
		// 4106 bytes file (-8 header bytes -> 4098)
		"memory on multiple elements dont overlap": {
			want: []policyRawEntry{
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-options`,
					key:   "metaValues",
					dType: dataType(1),
					data:  toUtf16(t, `{"20.04":{"empty":"''","meta":"s"},"21.04":{"empty":"''","meta":"s"},"all":{"empty":"''","meta":"s"}}`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-options`,
					key:   "all",
					dType: dataType(1),
					data:  toUtf16(t, `stretched`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-options`,
					key:   "Override21.04",
					dType: dataType(1),
					data:  toUtf16(t, `false`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-options`,
					key:   "21.04",
					dType: dataType(1),
					data:  toUtf16(t, `none`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-options`,
					key:   "Override20.04",
					dType: dataType(1),
					data:  toUtf16(t, `false`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-options`,
					key:   "20.04",
					dType: dataType(1),
					data:  toUtf16(t, `none`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-uri`,
					key:   "metaValues",
					dType: dataType(1),
					data:  toUtf16(t, `{"20.04":{"empty":"''","meta":"s"},"21.04":{"empty":"''","meta":"s"},"all":{"empty":"''","meta":"s"}}`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-uri`,
					key:   "all",
					dType: dataType(1),
					data:  toUtf16(t, `file:///usr/share/backgrounds/canonical.png`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-uri`,
					key:   "Override21.04",
					dType: dataType(1),
					data:  toUtf16(t, `false`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-uri`,
					key:   "21.04",
					dType: dataType(1),
					data:  toUtf16(t, `'file:///usr/backgrounds/warty-final-ubuntu.png'`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-uri`,
					key:   "Override20.04",
					dType: dataType(1),
					data:  toUtf16(t, `false`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\desktop\background\picture-uri`,
					key:   "20.04",
					dType: dataType(1),
					data:  toUtf16(t, `'file:///xxxxusrpng'`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\shell\favorite-apps`,
					key:   "metaValues",
					dType: dataType(1),
					data:  toUtf16(t, `{"20.04":{"empty":"","meta":"as"},"21.04":{"empty":"","meta":"as"},"all":{"empty":"","meta":"as"}}`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\shell\favorite-apps`,
					key:   "all",
					dType: dataType(7),
					data:  toUtf16(t, "'firefox.desktop'\x00'thunderbird.desktop'\x00'org.gnome.Nautilus.desktop'\x00"),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\shell\favorite-apps`,
					key:   "Override21.04",
					dType: dataType(1),
					data:  toUtf16(t, `true`),
				},
				{
					path:  `Software\Policies\Ubuntu\dconf\org\gnome\shell\favorite-apps`,
					key:   "21.04",
					dType: dataType(7),
					data:  toUtf16(t, "'firefox.desktop', 'thunderbird.desktop', 'yelp.desktop'\x00"),
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

		// Soft error cases
		"empty value": {
			wantEntryErr: true,
			want: []policyRawEntry{
				{
					path:  `Software\Canonical\Ubuntu`,
					dType: dataType(1),
					data:  []byte("B\x00A\x00\x00\x00"),
				},
			},
		},

		// Error cases
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

			if tc.wantEntryErr {
				var found bool
				for i, r := range rules {
					if r.err != nil {
						found = true

						// Don't serialize errors when comparing policy entries
						r.err = nil
						rules[i] = r
					}
				}

				require.True(t, found, "readPolicy returned no entry error when expecting one")
			}

			require.Equalf(t, tc.want, rules, "expected value from readPolicy doesn't match")
		})
	}
}

func policyFilePath(name string) string {
	return filepath.Join("testdata", strings.ReplaceAll(strings.ReplaceAll(name, ",", "_"), " ", "_")+".pol")
}

// toUtf16 is a utility function to convert test data from string to utf16 data.
func toUtf16(t *testing.T, s string) []byte {
	t.Helper()

	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	r, err := encoder.Bytes([]byte(s))
	require.NoError(t, err, "Setup: string converted to utf16 should not error out")
	r = append(r, '\x00', '\x00')
	return r
}
