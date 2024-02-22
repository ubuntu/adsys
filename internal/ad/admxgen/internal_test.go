package admxgen

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/testutils"
	"gopkg.in/yaml.v3"
)

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
		"no defaults":             {},
		"no note":                 {},
		"no note strategy append": {},
		"range":                   {},
		"choices":                 {},

		"default policy class is capitalized": {},
		"requires ubuntu pro":                 {},

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
		categoryDefinition := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			policies, catfs, err := loadDefinitions(
				filepath.Join(testutils.TestFamilyPath(t), "defs", categoryDefinition)+".yaml",
				filepath.Join(testutils.TestFamilyPath(t), "defs", name))

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

			want := testutils.LoadWithUpdateFromGoldenYAML(t, got)
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
			ecF, err := os.ReadFile(filepath.Join(testutils.TestFamilyPath(t), "defs", name+".yaml"))
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

			gotADMX, err := os.ReadFile(filepath.Join(dst, tc.distroID+".admx"))
			require.NoError(t, err, "should be able to read destination admx file")
			gotADML, err := os.ReadFile(filepath.Join(dst, tc.distroID+".adml"))
			require.NoError(t, err, "should be able to read destination adml file")

			goldenADMXPath := testutils.GoldenPath(t) + ".admx"
			goldenADMLPath := testutils.GoldenPath(t) + ".adml"

			wantADMX := testutils.LoadWithUpdateFromGolden(t, string(gotADMX), testutils.WithGoldenPath(goldenADMXPath))
			wantADML := testutils.LoadWithUpdateFromGolden(t, string(gotADML), testutils.WithGoldenPath(goldenADMLPath))

			assert.Equal(t, wantADMX, string(gotADMX), "expected and got admx content differs")
			assert.Equal(t, wantADML, string(gotADML), "expected and got adml content differs")
		})
	}
}

func TestExpandedCategoriesToMD(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		destIsFile bool

		wantErr bool
	}{
		"simple":              {},
		"nested categories":   {},
		"multiple categories": {},

		// Basic keys: no options means a key with no children and no types on it
		"basic key": {},

		"user policy":                          {},
		"nested categories, classes and empty": {},

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
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dst := filepath.Join(t.TempDir(), "subdir")

			if tc.destIsFile {
				f, err := os.Create(dst)
				f.Close()
				require.NoError(t, err, "Setup: should create a file as destination")
			}

			var ec []expandedCategory
			ecF, err := os.ReadFile(filepath.Join(testutils.TestFamilyPath(t), "defs", name+".yaml"))
			require.NoError(t, err, "Setup: failed to load expanded categories from file")
			err = yaml.Unmarshal(ecF, &ec)
			require.NoError(t, err, "Setup: failed to unmarshal expanded categories")

			err = expandedCategoriesToMD(ec, dst, ".")
			if tc.wantErr {
				require.Error(t, err, "expandedCategoriesToMD should have errored out")
				return
			}
			require.NoError(t, err, "expandedCategoriesToMD failed but shouldn't have")

			testutils.CompareTreesWithFiltering(t, dst, testutils.GoldenPath(t), testutils.Update())
		})
	}
}

func TestMain(m *testing.M) {
	testutils.InstallUpdateFlag()
	flag.Parse()

	m.Run()
}
