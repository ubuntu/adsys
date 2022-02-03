package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad/admxgen/common"
	"gopkg.in/yaml.v3"
)

var update bool

func TestGenerateExpandedCategories(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		allowMissingKeys bool

		wantErrLoadDefinitions bool
		wantErr                bool
	}{
		"simple":       {},
		"basic":        {},
		"two policies": {},
		"use policy class instead of category default": {},

		// Multi releases tests
		"same default":                  {},
		"different defaults":            {},
		"available on one release only": {},
		// last one wins
		"different explain text":     {},
		"different display name":     {},
		"applicable to all releases": {},

		// Cases with multiple categories
		"nested categories":                                              {},
		"same policy used in two categories":                             {},
		"same policy used in two categories but different default class": {},
		"multiple top categories":                                        {},

		"with prefix": {},

		// Optional content
		"no defaults": {},
		"no note":     {},
		"range":       {},
		"choices":     {},

		"default policy class is capitalized": {},

		// Optional content and options varies
		"different element type": {},
		"different meta":         {},
		"different choices":      {},
		"different range":        {},

		"allow policy referenced but not available in any releases": {allowMissingKeys: true},

		// meta cases
		"no meta enabled":                    {},
		"no meta disabled":                   {},
		"meta entry only":                    {},
		"no meta at all":                     {},
		"meta is overridden by enabled key":  {},
		"meta is overridden by disabled key": {},

		// Error cases
		"error on one policy not used":                                               {wantErr: true},
		"error on unexisting policy referenced":                                      {allowMissingKeys: false, wantErr: true},
		"error on different policy type":                                             {wantErr: true},
		"error on different class":                                                   {wantErr: true},
		"error on missing release":                                                   {wantErr: true},
		"error on nested category":                                                   {wantErr: true},
		"error on invalid default policy class":                                      {wantErr: true},
		"error on empty default policy class":                                        {wantErr: true},
		"error on policy not attached to any releases":                               {wantErr: true},
		"error on key independent of any release key but with one release specified": {wantErr: true},

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
			got, err := g.generateExpandedCategories(catfs.Categories, policies, tc.allowMissingKeys)
			if tc.wantErr {
				require.Error(t, err, "generateExpandedCategories should have errored out")
				return
			}
			require.NoError(t, err, "generateExpandedCategories failed but shouldn't have")

			goldPath := filepath.Join("testdata", "generateExpandedCategories", "golden", name)
			var want []expandedCategory
			wantFromGoldenFileYAML(t, goldPath, got, &want)

			assert.Equal(t, want, got, "expected and got differs")
		})
	}
}

func TestExpandedCategoriesToADMX(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		distroID   string
		destIsFile bool

		wantErr bool
	}{
		"simple":              {},
		"nested categories":   {},
		"multiple categories": {},
		"other distro":        {distroID: "Debian"},

		// Basic keys: no options means a key with no children and no types on it
		"basic key": {},

		// Types
		"boolean":               {},
		"decimal":               {},
		"decimal with range":    {},
		"decimal with min only": {},
		"decimal with max only": {},
		// TODO: range with min or max < 0 -> text
		"long decimal":         {},
		"array of strings":     {},
		"array of integers":    {},
		"choices":              {},
		"choices with default": {},
		"double":               {},
		"double with range":    {},

		// Multiple releases
		"multiple releases for one key":                             {},
		"multiple releases with different widgettype":               {},
		"multiple releases with different choices":                  {},
		"multiple releases with different ranges":                   {},
		"multiple releases with all widgets and different defaults": {},

		// meta cases
		"no meta enabled":  {},
		"no meta disabled": {},
		"no meta at all":   {},

		// Error Cases
		"error on destination creation": {destIsFile: true, wantErr: true},
	}
	for name, tc := range tests {
		name := name

		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dst := t.TempDir()

			if tc.destIsFile {
				dst = filepath.Join(dst, "ThisIsAFile")
				f, err := os.Create(dst)
				f.Close()
				require.NoError(t, err, "Setup: should create a file as destination")
			}

			if tc.distroID == "" {
				tc.distroID = "Ubuntu"
			}

			var ec []expandedCategory
			ecF, err := os.ReadFile(filepath.Join("testdata", "expandedCategoriesToADMX", "defs", name+".yaml"))
			require.NoError(t, err, "Setup: failed to load expanded categories from file")
			err = yaml.Unmarshal(ecF, &ec)
			require.NoError(t, err, "Setup: failed to unmarshal expanded categories")

			g := generator{
				distroID: tc.distroID,
			}
			err = g.expandedCategoriesToADMX(ec, dst)
			if tc.wantErr {
				require.Error(t, err, "expandedCategoriesToADMX should have errored out")
				return
			}
			require.NoError(t, err, "expandedCategoriesToADMX failed but shouldn't have")

			goldPath := filepath.Join("testdata", "expandedCategoriesToADMX", "golden")
			gotADMX, err := os.ReadFile(filepath.Join(dst, tc.distroID+".admx"))
			require.NoError(t, err, "should be able to read destination admx file")
			gotADML, err := os.ReadFile(filepath.Join(dst, tc.distroID+".adml"))
			require.NoError(t, err, "should be able to read destination adml file")

			wantADMX := wantFromGoldenFile(t, filepath.Join(goldPath, fmt.Sprintf("%s-%s.admx", name, tc.distroID)), gotADMX)
			wantADML := wantFromGoldenFile(t, filepath.Join(goldPath, fmt.Sprintf("%s-%s.adml", name, tc.distroID)), gotADML)

			assert.Equal(t, string(wantADMX), string(gotADMX), "expected and got admx content differs")
			assert.Equal(t, string(wantADML), string(gotADML), "expected and got adml content differs")
		})
	}
}

func TestMainExpand(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		root string

		wantErr bool
	}{
		"dconf":                            {root: "simple"},
		"expanded policy":                  {root: "simple"},
		"expanded policy with meta":        {root: "simple"},
		"expanded policy with release any": {root: "simple"},

		"ignore categories and non yaml files": {root: "simple"},

		/* Error cases */
		"no release file":         {root: "no release file", wantErr: true},
		"no version_id":           {root: "no version id", wantErr: true},
		"unsupported policy type": {root: "simple", wantErr: true},
		"no source directory":     {root: "simple", wantErr: true},
		"invalid dconf.yaml":      {root: "simple", wantErr: true},
		"dconf generation fails":  {root: "unsupported dconf type", wantErr: true},
	}
	for name, tc := range tests {
		name := name

		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			src := filepath.Join("testdata", "expand", "defs", name)
			dst := t.TempDir()
			root := filepath.Join("testdata", "expand", "system", tc.root)

			currentSession := "ubuntu"
			err := expand(src, dst, root, currentSession)
			if tc.wantErr {
				require.Error(t, err, "expand should have errored out")
				return
			}
			require.NoError(t, err, "expand failed but shouldn't have")

			data, err := os.ReadFile(filepath.Join(dst, "20.04.yaml"))
			require.NoError(t, err, "failed to generate expanded policies file")
			goldPath := filepath.Join("testdata", "expand", "golden", name)
			var got, want []common.ExpandedPolicy
			err = yaml.Unmarshal(data, &got)

			// Order the policies (as we collect them as soon as the generator returns)
			// Finale admx is not impacted as we use categories definition to order policies
			expandedPoliciesByType := make(map[string][]common.ExpandedPolicy)
			var types []string
			for _, p := range got {
				types = append(types, p.Type)
				expandedPoliciesByType[p.Type] = append(expandedPoliciesByType[p.Type], p)
			}
			sort.Strings(types)
			var gotPolicies []common.ExpandedPolicy
			for _, t := range types {
				gotPolicies = append(gotPolicies, expandedPoliciesByType[t]...)
			}

			require.NoError(t, err, "created file is not a slice of expanded policy objects")
			wantFromGoldenFileYAML(t, goldPath, gotPolicies, &want)

			assert.Equal(t, want, gotPolicies, "expected and got differs")
		})
	}
}

func TestMainADMX(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		autoDetectReleases bool
		destIsFile         bool

		wantErr bool
	}{
		"releases from yaml":                      {},
		"autodetect overrides releases from yaml": {autoDetectReleases: true},

		// Error cases
		"invalid definition file":  {wantErr: true},
		"category expansion fails": {wantErr: true},
		"admx generation fails":    {destIsFile: true, wantErr: true},
	}
	for name, tc := range tests {
		name := name

		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			catDef := filepath.Join("testdata", "admx", name+".yaml")
			src := filepath.Join("testdata", "admx", "src")
			dst := t.TempDir()

			if tc.destIsFile {
				dst = filepath.Join(dst, "ThisIsAFile")
				f, err := os.Create(dst)
				f.Close()
				require.NoError(t, err, "Setup: should create a file as destination")
			}

			err := admx(catDef, src, dst, tc.autoDetectReleases, false)
			if tc.wantErr {
				require.Error(t, err, "admx should have errored out")
				return
			}
			require.NoError(t, err, "admx failed but shouldn't have")

			goldPath := filepath.Join("testdata", "admx", "golden")
			gotADMX, err := os.ReadFile(filepath.Join(dst, "Ubuntu.admx"))
			require.NoError(t, err, "should be able to read destination admx file")
			gotADML, err := os.ReadFile(filepath.Join(dst, "Ubuntu.adml"))
			require.NoError(t, err, "should be able to read destination adml file")

			wantADMX := wantFromGoldenFile(t, filepath.Join(goldPath, fmt.Sprintf("%s-%s.admx", name, "Ubuntu")), gotADMX)
			wantADML := wantFromGoldenFile(t, filepath.Join(goldPath, fmt.Sprintf("%s-%s.adml", name, "Ubuntu")), gotADML)

			assert.Equal(t, string(wantADMX), string(gotADMX), "expected and got admx content differs")
			assert.Equal(t, string(wantADML), string(gotADML), "expected and got adml content differs")
		})
	}
}

func wantFromGoldenFileYAML(t *testing.T, goldPath string, got interface{}, want interface{}) {
	t.Helper()

	if update {
		t.Logf("updating golden file %s", goldPath)
		data, err := yaml.Marshal(got)
		require.NoError(t, err, "Cannot marshal expanded policies to YAML")
		err = os.WriteFile(goldPath, data, 0600)
		require.NoError(t, err, "Cannot write golden file")
	}

	data, err := os.ReadFile(goldPath)
	require.NoError(t, err, "Cannot load policy golden file")
	err = yaml.Unmarshal(data, want)
	require.NoError(t, err, "Cannot create expanded policy objects from golden file")
}

func wantFromGoldenFile(t *testing.T, goldPath string, got []byte) (want []byte) {
	t.Helper()

	if update {
		t.Logf("updating golden file %s", goldPath)
		err := os.WriteFile(goldPath, got, 0600)
		require.NoError(t, err, "Cannot write golden file")
	}

	want, err := os.ReadFile(goldPath)
	require.NoError(t, err, "Cannot load policy golden file")

	return want
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
