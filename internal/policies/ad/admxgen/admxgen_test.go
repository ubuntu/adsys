package main

import (
	"flag"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

var update bool

func TestGenerateExpandedCategories(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		wantErrLoadDefinitions bool
		wantErr                bool
	}{
		"simple":       {},
		"two policies": {},
		"use policy class instead of category default": {},

		// Multi releases tests
		"same default":                  {},
		"different defaults":            {},
		"available on one release only": {},
		// last one wins
		"different explain text": {},
		"different display name": {},

		// Cases with multiple categories
		"nested categories":                                              {},
		"same policy used in two categories":                             {},
		"same policy used in two categories but different default class": {},
		"multiple top categories":                                        {},

		// Error cases
		"one policy not used":          {wantErr: true},
		"unexisting policy referenced": {wantErr: true},
		"different meta":               {wantErr: true},
		"different element type":       {wantErr: true},
		"different policy type":        {wantErr: true},
		"different class":              {wantErr: true},
		"missing release":              {wantErr: true},
		"error on nested category":     {wantErr: true},

		"policy directory doesn't exist":    {wantErrLoadDefinitions: true},
		"category definition doesn't exist": {wantErrLoadDefinitions: true},
	}
	for name, tc := range tests {
		name := name
		categoryDefinition := name

		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			policies, catfs, err := loadDefinitions(
				filepath.Join("testdata", "generateExpandedCategories", "defs", categoryDefinition)+".yaml",
				filepath.Join("testdata", "generateExpandedCategories", "defs", name))

			if tc.wantErrLoadDefinitions {
				require.Error(t, err, "loadDefinitions should have errored out")
				return
			}
			require.NoError(t, err, "Setup: load definition failed but shouldn't have")

			g := generator{
				distroID:          catfs.DistroID,
				supportedReleases: catfs.SupportedReleases,
			}
			got, err := g.generateExpandedCategories(catfs.Categories, policies)
			if tc.wantErr {
				require.Error(t, err, "generateExpandedCategories should have errored out")
				return
			}
			require.NoError(t, err, "generateExpandedCategories failed but shouldn't have")

			goldPath := filepath.Join("testdata", "generateExpandedCategories", "golden", name)
			var want []expandedCategory
			wantFromGoldenFile(t, goldPath, got, &want)

			assert.Equal(t, want, got, "expected and got differs")
		})
	}
}

func wantFromGoldenFile(t *testing.T, goldPath string, got interface{}, want interface{}) {
	t.Helper()

	if update {
		t.Logf("updating golden file %s", goldPath)
		data, err := yaml.Marshal(got)
		require.NoError(t, err, "Cannot marshal expanded policies to YAML")
		err = ioutil.WriteFile(goldPath, data, 0644)
		require.NoError(t, err, "Cannot write golden file")
	}

	data, err := ioutil.ReadFile(goldPath)
	require.NoError(t, err, "Cannot load policy golden file")
	err = yaml.Unmarshal(data, want)
	require.NoError(t, err, "Cannot create expanded policy objects from golden file")
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
