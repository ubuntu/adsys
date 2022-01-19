package dconf_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad/admxgen/common"
	"github.com/ubuntu/adsys/internal/ad/admxgen/dconf"
	"gopkg.in/yaml.v3"
)

var update bool

func TestGenerate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		root            string
		currentSessions string

		wantErr bool
	}{
		"One text key":             {root: "simple"},
		"Key with class":           {root: "simple"},
		"Relocatable key":          {root: "simple"},
		"Same key relocated twice": {root: "simple"},

		// Different types
		"One boolean key":                      {root: "simple"},
		"One decimal key":                      {root: "simple"},
		"One decimal key with range":           {root: "simple"},
		"One decimal key with min only":        {root: "simple"},
		"One decimal key with max only":        {root: "simple"},
		"Long decimal key":                     {root: "simple"},
		"Long decimal key with range min lt 0": {root: "simple"},
		"Long decimal key with range min gt 0": {root: "simple"},
		"Array of strings":                     {root: "simple"},
		"Array of integers":                    {root: "simple"},
		"Double key":                           {root: "simple"},
		"Double key with range":                {root: "simple"},

		// Override cases
		"Override without session":                                    {root: "simple", currentSessions: "-"},
		"Override with no matching session defaults to root override": {root: "simple", currentSessions: "doesnotmatch"},
		"Override with session takes session override":                {root: "simple", currentSessions: "ubuntu"},
		"Override takes first session":                                {root: "simple", currentSessions: "ubuntu:GNOME"},
		"Override default to second if first not present":             {root: "simple", currentSessions: "ubuntu:GNOME"},
		"Override without session takes default":                      {root: "simple", currentSessions: "-"},
		"Overridden by multiple files, last wins":                     {root: "simple", currentSessions: "-"},
		"Relocatable key overridden":                                  {root: "simple"},

		// Choices and enum
		"Choices are loaded":                            {root: "simple"},
		"Inlined Enums are converted to choices":        {root: "simple"},
		"Enums in other files are converted to choices": {root: "simple"},

		// Edge cases
		"No key on system":                   {root: "simple"},
		"Empty":                              {root: "simple"},
		"Invalid override files are skipped": {root: "broken_override"},
		"Valid class should be capitalized":  {root: "simple"},

		"Description starting with deprecated is ignored":                         {root: "deprecated_keys"},
		"Description starting with deprecated mixed case is ignored":              {root: "deprecated_keys"},
		"Description starting with obsolete is ignored":                           {root: "deprecated_keys"},
		"Description containing deprecated without starting by it is not ignored": {root: "deprecated_keys"},

		// Error cases
		"Unsupported key type": {root: "exotic_type", wantErr: true},
		"Enum does not exist":  {root: "nonexistent_enum", wantErr: true},
		"Invalid class":        {root: "simple", wantErr: true},
		"Invalid min":          {root: "invalid_min", wantErr: true},
		"NaN min":              {root: "nan_min", wantErr: true},
		"Invalid schema files": {root: "broken_schema", wantErr: true},
	}
	for name, tc := range tests {
		def := strings.ToLower(strings.ReplaceAll(name, " ", "_"))
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tc.root = filepath.Join("testdata", "system", tc.root)
			if tc.currentSessions == "" {
				tc.currentSessions = "ubuntu:GNOME"
			} else if tc.currentSessions == "-" {
				tc.currentSessions = ""
			}

			var dconfPolicies []dconf.Policy
			data, err := os.ReadFile(filepath.Join("testdata", "defs", def))
			require.NoError(t, err, "Setup: cannot load policy definition")
			err = yaml.Unmarshal(data, &dconfPolicies)
			require.NoError(t, err, "Setup: cannot create policy objects")

			got, err := dconf.Generate(dconfPolicies, "20.04", tc.root, tc.currentSessions)
			if tc.wantErr {
				require.Error(t, err, "Generate should have failed but didn't")
				return
			}
			require.NoError(t, err, "Generate should issue no error")

			goldPath := filepath.Join("testdata", "golden", def)
			// Update golden file
			if update {
				t.Logf("updating golden file %s", goldPath)
				data, err = yaml.Marshal(got)
				require.NoError(t, err, "Cannot marshal expanded policies to YAML")
				err = os.WriteFile(goldPath, data, 0600)
				require.NoError(t, err, "Cannot write golden file")
			}
			var want []common.ExpandedPolicy
			data, err = os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load policy golden file")
			err = yaml.Unmarshal(data, &want)
			require.NoError(t, err, "Cannot create expanded policy objects from golden file")
			if len(want) == 0 {
				want = nil
			}

			assert.Equal(t, want, got, "expected and got differs")
		})
	}
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
