package entry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetUniqueRules(t *testing.T) {
	t.Parallel()

	standardGPO := GPO{ID: "standard", Name: "standard-name", Rules: map[string][]Entry{
		"dconf": {
			{Key: "A", Value: "standardA"},
			{Key: "B", Value: "standardB"},
			{Key: "C", Value: "standardC"},
		}}}

	tests := map[string]struct {
		gpos []GPO

		want map[string][]Entry
	}{
		"One GPO": {
			gpos: []GPO{standardGPO},
			want: map[string][]Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},
		"Order key ascii": {
			gpos: []GPO{{ID: "standard", Name: "standard-name", Rules: map[string][]Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "Z", Value: "standardZ"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				}}}},
			want: map[string][]Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
					{Key: "Z", Value: "standardZ"},
				},
			}},

		// Multiple domains cases
		"Multiple domains, same GPOs": {
			gpos: []GPO{
				{ID: "gpomultidomain", Name: "gpomultidomain-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "B", Value: "standardB"},
						{Key: "C", Value: "standardC"},
					},
					"otherdomain": {
						{Key: "Key1", Value: "otherdomainKey1"},
						{Key: "Key2", Value: "otherdomainKey2"},
					}}}},
			want: map[string][]Entry{
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
			gpos: []GPO{standardGPO,
				{ID: "gpo2", Name: "gpo2-name", Rules: map[string][]Entry{
					"otherdomain": {
						{Key: "Key1", Value: "otherdomainKey1"},
						{Key: "Key2", Value: "otherdomainKey2"},
					}}}},
			want: map[string][]Entry{
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
			gpos: []GPO{
				{ID: "gpoDomain1", Name: "gpoDomain1-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "Common", Value: "commonValueDconf"},
					},
					"otherdomain": {
						{Key: "Common", Value: "commonValueOtherDomain"},
					}}}},
			want: map[string][]Entry{
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
			gpos: []GPO{
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				{ID: "standard", Name: "standard-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "B", Value: "standardB"},
						// this value will be overriden with the higher one
						{Key: "C", Value: "standardC"},
					}}},
			},
			want: map[string][]Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},
		"Two policies, with reversed overrides": {
			gpos: []GPO{
				standardGPO,
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]Entry{
					"dconf": {
						// this value will be overriden with the higher one
						{Key: "C", Value: "oneValueC"},
					}}},
			},
			want: map[string][]Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},
		"Two policies, no overrides": {
			gpos: []GPO{
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
			},
			want: map[string][]Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},
		"Two policies, no overrides, reversed": {
			gpos: []GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
			},
			want: map[string][]Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},

		"Disabled value overrides non disabled one": {
			gpos: []GPO{
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
				standardGPO,
			},
			want: map[string][]Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Disabled: true},
				},
			}},
		"Disabled value is overridden": {
			gpos: []GPO{
				standardGPO,
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
			},
			want: map[string][]Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},

		"More policies, with multiple overrides": {
			gpos: []GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				standardGPO,
			},
			want: map[string][]Entry{
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

			got := GetUniqueRules(tc.gpos)
			require.Equal(t, tc.want, got, "GetUniqueRules returns expected policy entries with correct overrides")
		})
	}
}
