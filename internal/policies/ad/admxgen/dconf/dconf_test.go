package dconf_test

import (
	"flag"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/ad/admxgen/common"
	"github.com/ubuntu/adsys/internal/policies/ad/admxgen/dconf"
	"gopkg.in/yaml.v2"
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

		// TODO: Different types

		// Override cases
		"Override without session":                                    {root: "simple", currentSessions: "-"},
		"Override with no matching session defaults to root override": {root: "simple", currentSessions: "doesnotmatch"},
		"Override with session takes session override":                {root: "simple", currentSessions: "ubuntu"},
		"Override takes first session":                                {root: "simple", currentSessions: "ubuntu:GNOME"},
		"Override default to second if first not present":             {root: "simple", currentSessions: "ubuntu:GNOME"},
		"Override without session takes default":                      {root: "simple", currentSessions: "-"},
		"Overridden by multiple files, last wins":                     {root: "simple", currentSessions: "-"},
		"Relocatable key overridden":                                  {root: "simple"},

		// Edge cases
		"No key on system":                   {root: "simple"},
		"Empty":                              {root: "simple"},
		"Invalid schema files are skipped":   {root: "broken_schema"},
		"Invalid override files are skipped": {root: "broken_override"},

		// Error cases
		"Unsupported key type": {root: "exotic_type", wantErr: true},
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
			data, err := ioutil.ReadFile(filepath.Join("testdata", "defs", def))
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
				err = ioutil.WriteFile(goldPath, data, 0644)
				require.NoError(t, err, "Cannot write golden file")
			}
			var want []common.ExpandedPolicy
			data, err = ioutil.ReadFile(goldPath)
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
