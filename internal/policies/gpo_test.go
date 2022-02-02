package policies_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies"
)

func TestFormat(t *testing.T) {
	t.Parallel()

	defaultProcessedRules := map[string]struct{}{
		"dconf/path/to/key1":   {},
		"dconf/path/to/key2":   {},
		"scripts/path/to/key3": {},
	}

	tests := map[string]struct {
		cachedPoliciesSrc string

		withRules             bool
		withOverridden        bool
		alreadyProcessedRules map[string]struct{}

		wantAlreadyProcessedRules map[string]struct{}
	}{
		"GPO summary":    {},
		"GPO with rules": {withRules: true, wantAlreadyProcessedRules: defaultProcessedRules},
		"GPO with rules and overrides, no rules processed": {withRules: true, withOverridden: true, wantAlreadyProcessedRules: defaultProcessedRules},
		"GPO with rules, appending to existing treated key": {
			withRules:             true,
			alreadyProcessedRules: map[string]struct{}{"dconf/non/matching/override": {}},
			wantAlreadyProcessedRules: map[string]struct{}{
				"dconf/path/to/key1":          {},
				"dconf/path/to/key2":          {},
				"scripts/path/to/key3":        {},
				"dconf/non/matching/override": {},
			}},

		// override cases
		"GPO with rules, override hidden": {
			withRules:                 true,
			alreadyProcessedRules:     map[string]struct{}{"dconf/path/to/key1": {}},
			wantAlreadyProcessedRules: defaultProcessedRules},
		"GPO with rules, override displayed": {
			withRules:                 true,
			withOverridden:            true,
			alreadyProcessedRules:     map[string]struct{}{"dconf/path/to/key1": {}},
			wantAlreadyProcessedRules: defaultProcessedRules},
		"GPO with rules, override disabled key": {
			withRules:                 true,
			withOverridden:            true,
			alreadyProcessedRules:     map[string]struct{}{"scripts/path/to/key3": {}},
			wantAlreadyProcessedRules: defaultProcessedRules},

		// append strategy cases
		"GPO and assets with rules, appending to same key do not add to processed rules": {
			cachedPoliciesSrc: "with_assets_other",
			withRules:         true,
			withOverridden:    true,
			wantAlreadyProcessedRules: map[string]struct{}{
				"dconf/path/to/key1": {},
				"dconf/path/to/key2": {},
				// key3 is not in the process rules as appended in term of strategy
			}},
		"GPO and assets with rules, append is overridden after a topmost override": {
			cachedPoliciesSrc: "with_assets",
			alreadyProcessedRules: map[string]struct{}{
				"scripts/path/to/key3": {}},
			withRules:      true,
			withOverridden: true,
			wantAlreadyProcessedRules: map[string]struct{}{
				"dconf/path/to/key1":   {},
				"dconf/path/to/key2":   {},
				"scripts/path/to/key3": {},
			}},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cachedPoliciesSrc := "simple"
			if tc.cachedPoliciesSrc != "" {
				cachedPoliciesSrc = tc.cachedPoliciesSrc
			}

			pols, err := policies.NewFromCache(context.Background(), filepath.Join("testdata", "cache", "policies", cachedPoliciesSrc))
			require.NoError(t, err, "Got policies without error")
			defer pols.Close()

			var out strings.Builder

			got := pols.GPOs[0].Format(&out, tc.withRules, tc.withOverridden, tc.alreadyProcessedRules)
			// check cache between Format calls
			require.Equal(t, tc.wantAlreadyProcessedRules, got, "Format returns expected alreadyProcessedRules cache")

			// check collected output between Format calls
			goldPath := filepath.Join("testdata", "golden", "format", name)
			// Update golden file
			if update {
				t.Logf("updating golden file %s", goldPath)
				err = os.WriteFile(goldPath, []byte(out.String()), 0600)
				require.NoError(t, err, "Cannot write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load policy golden file")

			require.Equal(t, string(want), out.String(), "Format write expected output")
		})
	}
}
