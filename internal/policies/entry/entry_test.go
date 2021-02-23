package entry_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/entry"
)

var update bool

func TestGetUniqueRules(t *testing.T) {
	t.Parallel()

	standardGPO := entry.GPO{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
		"dconf": {
			{Key: "A", Value: "standardA"},
			{Key: "B", Value: "standardB"},
			{Key: "C", Value: "standardC"},
		}}}

	tests := map[string]struct {
		gpos []entry.GPO

		want map[string][]entry.Entry
	}{
		"One GPO": {
			gpos: []entry.GPO{standardGPO},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},
		"Order key ascii": {
			gpos: []entry.GPO{{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "Z", Value: "standardZ"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
					{Key: "Z", Value: "standardZ"},
				},
			}},

		// Multiple domains cases
		"Multiple domains, same GPOs": {
			gpos: []entry.GPO{
				{ID: "gpomultidomain", Name: "gpomultidomain-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "B", Value: "standardB"},
						{Key: "C", Value: "standardC"},
					},
					"otherdomain": {
						{Key: "Key1", Value: "otherdomainKey1"},
						{Key: "Key2", Value: "otherdomainKey2"},
					}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
				"otherdomain": {
					{Key: "Key1", Value: "otherdomainKey1"},
					{Key: "Key2", Value: "otherdomainKey2"},
				},
			}},
		"Multiple domains, different GPOs": {
			gpos: []entry.GPO{standardGPO,
				{ID: "gpo2", Name: "gpo2-name", Rules: map[string][]entry.Entry{
					"otherdomain": {
						{Key: "Key1", Value: "otherdomainKey1"},
						{Key: "Key2", Value: "otherdomainKey2"},
					}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
				"otherdomain": {
					{Key: "Key1", Value: "otherdomainKey1"},
					{Key: "Key2", Value: "otherdomainKey2"},
				},
			}},
		"Same key in different domains are kept separated": {
			gpos: []entry.GPO{
				{ID: "gpoDomain1", Name: "gpoDomain1-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "Common", Value: "commonValueDconf"},
					},
					"otherdomain": {
						{Key: "Common", Value: "commonValueOtherDomain"},
					}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "Common", Value: "commonValueDconf"},
				},
				"otherdomain": {
					{Key: "Common", Value: "commonValueOtherDomain"},
				},
			}},

		// Override cases
		// This is ordered for each type by key ascii order
		"Two policies, with overrides": {
			gpos: []entry.GPO{
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "B", Value: "standardB"},
						// this value will be overridden with the higher one
						{Key: "C", Value: "standardC"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},
		"Two policies, with reversed overrides": {
			gpos: []entry.GPO{
				standardGPO,
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						// this value will be overridden with the higher one
						{Key: "C", Value: "oneValueC"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},
		"Two policies, no overrides": {
			gpos: []entry.GPO{
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},
		"Two policies, no overrides, reversed": {
			gpos: []entry.GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},

		"Disabled value overrides non disabled one": {
			gpos: []entry.GPO{
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
				standardGPO,
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Disabled: true},
				},
			}},
		"Disabled value is overridden": {
			gpos: []entry.GPO{
				standardGPO,
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},

		"More policies, with multiple overrides": {
			gpos: []entry.GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				standardGPO,
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := entry.GetUniqueRules(tc.gpos)
			require.Equal(t, tc.want, got, "GetUniqueRules returns expected policy entries with correct overrides")
		})
	}
}

func TestCacheGPOList(t *testing.T) {
	gpos := []entry.GPO{
		{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
			"dconf": {
				{Key: "C", Value: "oneValueC"},
			}}},
		{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
			"dconf": {
				{Key: "A", Value: "standardA", Meta: "My meta"},
				{Key: "B", Value: "standardB", Disabled: true},
				// this value will be overridden with the higher one
				{Key: "C", Value: "standardC"},
			}}},
	}

	p := filepath.Join(t.TempDir(), "gpos-list-cache")
	err := entry.SaveGPOs(gpos, p)
	require.NoError(t, err, "Save GPO without error")

	got, err := entry.NewGPOs(p)
	require.NoError(t, err, "Got GPOs without error")

	require.Equal(t, gpos, got, "Reloaded GPOs after caching should be the same")
}

func TestFormatGPO(t *testing.T) {
	t.Parallel()

	defaultProcessedRules := map[string]struct{}{
		"dconf/path/to/key1":   {},
		"dconf/path/to/key2":   {},
		"scripts/path/to/key3": {},
	}

	tests := map[string]struct {
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
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gpos, err := entry.NewGPOs("testdata/gpos.cache")
			require.NoError(t, err, "Got GPOs without error")

			var out strings.Builder

			got := gpos[0].FormatGPO(&out, tc.withRules, tc.withOverridden, tc.alreadyProcessedRules)

			// check cache between FormatGPO calls
			require.Equal(t, tc.wantAlreadyProcessedRules, got, "FormatGPO returns expected alreadyProcessedRules cache")

			// check collected output between FormatGPO calls
			goldPath := filepath.Join("testdata", "golden", name)
			// Update golden file
			if update {
				t.Logf("updating golden file %s", goldPath)
				err = os.WriteFile(goldPath, []byte(out.String()), 0644)
				require.NoError(t, err, "Cannot write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load policy golden file")

			require.Equal(t, string(want), out.String(), "FormatGPO write expected output")

		})
	}
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
