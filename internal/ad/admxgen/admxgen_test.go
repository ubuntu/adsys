package admxgen_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad/admxgen"
	"github.com/ubuntu/adsys/internal/ad/admxgen/common"
	"gopkg.in/yaml.v3"
)

func TestExpand(t *testing.T) {
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
			err := admxgen.Expand(src, dst, root, currentSession)
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
			admxgen.WantFromGoldenFileYAML(t, goldPath, gotPolicies, &want)

			assert.Equal(t, want, gotPolicies, "expected and got differs")
		})
	}
}

func TestGenerate(t *testing.T) {
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

			err := admxgen.Generate(catDef, src, dst, tc.autoDetectReleases, false)
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

			wantADMX := admxgen.WantFromGoldenFile(t, filepath.Join(goldPath, fmt.Sprintf("%s-%s.admx", name, "Ubuntu")), gotADMX)
			wantADML := admxgen.WantFromGoldenFile(t, filepath.Join(goldPath, fmt.Sprintf("%s-%s.adml", name, "Ubuntu")), gotADML)

			assert.Equal(t, string(wantADMX), string(gotADMX), "expected and got admx content differs")
			assert.Equal(t, string(wantADML), string(gotADML), "expected and got adml content differs")
		})
	}
}
