package policies_test

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

var update bool

func TestGetUniqueRules(t *testing.T) {
	t.Parallel()

	standardGPO := policies.GPO{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
		"dconf": {
			{Key: "A", Value: "standardA"},
			{Key: "B", Value: "standardB"},
			{Key: "C", Value: "standardC"},
		}}}

	tests := map[string]struct {
		gpos []policies.GPO

		want map[string][]entry.Entry
	}{
		"One GPO": {
			gpos: []policies.GPO{standardGPO},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},
		"Order key ascii": {
			gpos: []policies.GPO{{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
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
			gpos: []policies.GPO{
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
			gpos: []policies.GPO{standardGPO,
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
			gpos: []policies.GPO{
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
			gpos: []policies.GPO{
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
			gpos: []policies.GPO{
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
			gpos: []policies.GPO{
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
			gpos: []policies.GPO{
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
			gpos: []policies.GPO{
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
			gpos: []policies.GPO{
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
			gpos: []policies.GPO{
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

		// append/prepend cases
		"Append policy entry, one GPO": {
			gpos: []policies.GPO{
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "standardA", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "standardA", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, one GPO, disabled key is ignored": {
			gpos: []policies.GPO{
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "standardA", Strategy: entry.StrategyAppend, Disabled: true},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": nil,
			}},
		"Append policy entry, multiple GPOs": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "furthest value\nclosest value", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, multiple GPOs, disabled key is ignored, first": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend, Disabled: true},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, multiple GPOs, disabled key is ignored, second": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend, Disabled: true},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, closest meta wins": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Meta: "closest meta", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Meta: "furthest meta", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "furthest value\nclosest value", Meta: "closest meta", Strategy: entry.StrategyAppend},
				},
			}},

		// Mix append and override: closest win
		"Mix meta on GPOs, furthest policy entry is append, closest is override": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value"},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "closest value"},
				},
			}},
		"Mix meta on GPOs, closest policy entry is append, furthest override is ignored": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value"},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
				},
			}},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pols := policies.Policies{
				GPOs: tc.gpos,
			}
			got := pols.GetUniqueRules()
			require.Equal(t, tc.want, got, "GetUniqueRules returns expected policy entries with correct overrides")
		})
	}
}

func TestCachePolicies(t *testing.T) {
	pols := policies.Policies{
		GPOs: []policies.GPO{
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
		},
	}

	p := filepath.Join(t.TempDir(), "policies-cache")
	err := pols.Save(p)
	require.NoError(t, err, "Save policies without error")

	got, err := policies.NewFromCache(p)
	require.NoError(t, err, "Got policies without error")

	require.Equal(t, pols, got, "Reloaded policies after caching should be the same")
}

func TestDumpPolicies(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	tests := map[string]struct {
		cacheUser      string
		cacheMachine   string
		target         string
		withRules      bool
		withOverridden bool

		wantErr bool
	}{
		"One GPO User": {
			cacheUser: "one_gpo",
		},
		"One GPO Machine": {
			cacheMachine: "one_gpo",
			target:       hostname,
		},
		"One GPO User + Machine": {
			cacheUser:    "one_gpo",
			cacheMachine: "one_gpo_other",
		},
		"Multiple GPOs": {
			cacheUser: "two_gpos_no_override",
		},

		// Show rules
		"One GPO with rules": {
			cacheUser: "one_gpo",
			withRules: true,
		},
		"Machine only GPO with rules": {
			cacheMachine: "one_gpo",
			target:       hostname,
			withRules:    true,
		},
		"Multiple GPOs with rules, no override": {
			cacheUser: "two_gpos_no_override",
			withRules: true,
		},
		"Multiple GPOs with rules, override hidden": {
			cacheUser: "two_gpos_with_overrides",
			withRules: true,
		},
		"Multiple GPOs with rules, override, shown": {
			cacheUser:      "two_gpos_with_overrides",
			withRules:      true,
			withOverridden: true,
		},

		// machine and user GPO with overrides between machine and user
		"Overrides between machine and user GPOs, hidden": {
			cacheUser:    "one_gpo",
			cacheMachine: "two_gpos_override_one_gpo",
			withRules:    true,
		},
		"Overrides between machine and user GPOs, shown": {
			cacheUser:      "one_gpo",
			cacheMachine:   "two_gpos_override_one_gpo",
			withRules:      true,
			withOverridden: true,
		},

		// Edge cases
		"Same GPO Machine and User": {
			cacheUser:    "one_gpo",
			cacheMachine: "one_gpo",
		},
		"Same GPO Machine and User with rules": {
			cacheUser:    "one_gpo",
			cacheMachine: "one_gpo",
			withRules:    true,
		},
		"Same GPO Machine and User with rules and overrides": {
			cacheUser:      "one_gpo",
			cacheMachine:   "one_gpo",
			withRules:      true,
			withOverridden: true,
		},

		// Error cases
		"Error on missing target cache": {
			wantErr: true,
		},
		"Error on missing machine cache when targeting user": {
			cacheUser:    "one_gpo",
			cacheMachine: "-",
			wantErr:      true,
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cacheDir := t.TempDir()
			m, err := policies.NewManager(bus, policies.WithCacheDir(cacheDir))
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			err = os.MkdirAll(filepath.Join(cacheDir, policies.PoliciesCacheBaseName), 0750)
			require.NoError(t, err, "Setup: cant not create policies cache directory")

			if tc.cacheUser != "" {
				err := shutil.CopyFile(filepath.Join("testdata", "cache", tc.cacheUser), filepath.Join(cacheDir, policies.PoliciesCacheBaseName, "user"), false)
				require.NoError(t, err, "Setup: couldn’t copy user cache")
			}
			if tc.cacheMachine == "" {
				f, err := os.Create(filepath.Join(cacheDir, policies.PoliciesCacheBaseName, hostname))
				require.NoError(t, err, "Setup: failed to create empty machine cache file")
				f.Close()
			} else if tc.cacheMachine != "-" {
				err := shutil.CopyFile(filepath.Join("testdata", "cache", tc.cacheMachine), filepath.Join(cacheDir, policies.PoliciesCacheBaseName, hostname), false)
				require.NoError(t, err, "Setup: couldn’t copy machine cache")
			}

			if tc.target == "" {
				tc.target = "user"
			}
			got, err := m.DumpPolicies(context.Background(), tc.target, tc.withRules, tc.withOverridden)
			if tc.wantErr {
				require.Error(t, err, "DumpPolicies should return an error but got none")
				return
			}
			require.NoError(t, err, "DumpPolicies should return no error but got one")

			goldPath := filepath.Join("testdata", "golden", "dumppolicies", name)
			// Update golden file
			if update {
				t.Logf("updating golden file %s", goldPath)
				err = os.WriteFile(goldPath, []byte(got), 0600)
				require.NoError(t, err, "Cannot write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load policy golden file")

			require.Equal(t, string(want), got, "DumpPolicies returned expected output")
		})
	}
}

func TestApplyPolicies(t *testing.T) {
	//t.Parallel()

	bus := testutils.NewDbusConn(t)

	subscriptionDbus := bus.Object(consts.SubcriptionDbusRegisteredName,
		dbus.ObjectPath(consts.SubcriptionDbusObjectPath))

	tests := map[string]struct {
		policiesFile                 string
		secondCallWithNoRules        bool
		makeDirReadOnly              string
		isNotSubscribed              bool
		secondCallWithNoSubscription bool

		wantErr bool
	}{
		"succeed": {policiesFile: "all_entry_types.policies"},
		"second call with no rules deletes everything": {policiesFile: "all_entry_types.policies", secondCallWithNoRules: true},

		// no subscription filterings
		"no subscription is only dconf content":                                       {policiesFile: "all_entry_types.policies", isNotSubscribed: true},
		"second call with no subscription should remove everything but dconf content": {policiesFile: "all_entry_types.policies", secondCallWithNoSubscription: true},

		"dconf apply policy fails":     {policiesFile: "dconf_failing.policies", wantErr: true},
		"privilege apply policy fails": {makeDirReadOnly: "etc/sudoers.d", policiesFile: "all_entry_types.policies", wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			// We change the dbus returned values to simulate a subscription
			//t.Parallel()

			pols, err := policies.NewFromCache(filepath.Join("testdata", tc.policiesFile))
			require.NoError(t, err, "Setup: can not load policies list")

			fakeRootDir := t.TempDir()
			cacheDir := filepath.Join(fakeRootDir, "var", "cache", "adsys")
			dconfDir := filepath.Join(fakeRootDir, "etc", "dconf")
			policyKitDir := filepath.Join(fakeRootDir, "etc", "polkit-1")
			sudoersDir := filepath.Join(fakeRootDir, "etc", "sudoers.d")

			status := "enabled"
			if tc.isNotSubscribed {
				status = "disabled"
			}
			require.NoError(t, subscriptionDbus.SetProperty(consts.SubcriptionDbusInterface+".Status", status), "Setup: can not set subscription status to %q", status)
			defer func() {
				require.NoError(t, subscriptionDbus.SetProperty(consts.SubcriptionDbusInterface+".Status", ""), "Teardown: can not restore subscription status")
			}()

			m, err := policies.NewManager(bus,
				policies.WithCacheDir(cacheDir),
				policies.WithDconfDir(dconfDir),
				policies.WithPolicyKitDir(policyKitDir),
				policies.WithSudoersDir(sudoersDir),
			)
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			err = os.MkdirAll(filepath.Join(cacheDir, policies.PoliciesCacheBaseName), 0750)
			require.NoError(t, err, "Setup: cant not create policies cache directory")

			if tc.makeDirReadOnly != "" {
				require.NoError(t, os.MkdirAll(filepath.Join(fakeRootDir, tc.makeDirReadOnly), 0750), "Setup: can not create directory")
				testutils.MakeReadOnly(t, filepath.Join(fakeRootDir, tc.makeDirReadOnly))
			}

			err = m.ApplyPolicies(context.Background(), "hostname", true, pols)
			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should return an error but got none")
				return
			}
			require.NoError(t, err, "ApplyPolicy should return no error but got one")

			var runSecondCall bool
			if tc.secondCallWithNoRules {
				runSecondCall = true
				pols = policies.Policies{}
			} else if tc.secondCallWithNoSubscription {
				runSecondCall = true
				require.NoError(t, subscriptionDbus.SetProperty(consts.SubcriptionDbusInterface+".Status", "disabled"), "Setup: can not set subscription status for second call to disabled")
			}
			if runSecondCall {
				err = m.ApplyPolicies(context.Background(), "hostname", true, pols)
				require.NoError(t, err, "ApplyPolicy should return no error but got one")
			}

			testutils.CompareTreesWithFiltering(t, fakeRootDir, filepath.Join("testdata", "golden", "applypolicy", name), update)
		})
	}
}

func TestLastUpdateFor(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	tests := map[string]struct {
		target    string
		isMachine bool

		wantErr bool
	}{
		"Returns user's last update time":       {target: "user"},
		"Returns machine's last update time":    {target: hostname, isMachine: true},
		"Target is ignored for machine request": {target: "does_not_exit", isMachine: true},

		// Error cases
		"Target does not exist": {target: "does_not_exit", wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cacheDir := t.TempDir()
			m, err := policies.NewManager(bus, policies.WithCacheDir(cacheDir))
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			err = os.MkdirAll(filepath.Join(cacheDir, policies.PoliciesCacheBaseName), 0750)
			require.NoError(t, err, "Setup: cant not create policies cache directory")

			start := time.Now()
			// Starts and ends are monotic, while os.Stat is wall clock, we have to wait for measuring difference…
			time.Sleep(100 * time.Millisecond)
			f, err := os.Create(filepath.Join(cacheDir, policies.PoliciesCacheBaseName, "user"))
			require.NoError(t, err, "Setup: couldn’t copy user cache")
			f.Close()
			f, err = os.Create(filepath.Join(cacheDir, policies.PoliciesCacheBaseName, hostname))
			require.NoError(t, err, "Setup: couldn’t copy user cache")
			f.Close()

			got, err := m.LastUpdateFor(context.Background(), tc.target, tc.isMachine)
			if tc.wantErr {
				require.Error(t, err, "LastUpdateFor should return an error but got none")
				return
			}
			require.NoError(t, err, "LastUpdateFor should return no error but got one")
			end := time.Now()

			assert.True(t, got.After(start), "expected got after start")
			assert.True(t, got.Before(end), "expected got before end")
		})
	}
}

func TestGetStatus(t *testing.T) {
	//t.Parallel()

	bus := testutils.NewDbusConn(t)
	subscriptionDbus := bus.Object(consts.SubcriptionDbusRegisteredName,
		dbus.ObjectPath(consts.SubcriptionDbusObjectPath))

	tests := map[string]struct {
		status string

		want bool
	}{
		"returns enablement status (enabled)":  {status: "enabled", want: true},
		"returns enablement status (disabled)": {status: "somethingelse", want: false},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			// We change the dbus returned values to simulate a subscription
			//t.Parallel()

			require.NoError(t, subscriptionDbus.SetProperty(consts.SubcriptionDbusInterface+".Status", tc.status), "Setup: can not set subscription status to %q", tc.status)
			defer func() {
				require.NoError(t, subscriptionDbus.SetProperty(consts.SubcriptionDbusInterface+".Status", ""), "Teardown: can not restore subscription status")
			}()

			cacheDir := t.TempDir()
			m, err := policies.NewManager(bus, policies.WithCacheDir(cacheDir))
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			// force a refresh
			_ = m.GetSubcriptionState(context.Background())

			got := m.GetStatus()
			assert.Equal(t, tc.want, got, "GetStatus should return %q but got %q", tc.want, got)
		})
	}
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	// Don’t setup samba or sssd for mock helpers
	if !strings.Contains(strings.Join(os.Args, " "), "TestMock") {
		// Ubuntu Advantage
		defer testutils.StartLocalSystemBus()()

		conn, err := dbus.SystemBusPrivate()
		if err != nil {
			log.Fatalf("Setup: can’t get a private system bus: %v", err)
		}
		defer func() {
			if err = conn.Close(); err != nil {
				log.Fatalf("Teardown: can’t close system dbus connection: %v", err)
			}
		}()
		if err = conn.Auth(nil); err != nil {
			log.Fatalf("Setup: can’t auth on private system bus: %v", err)
		}
		if err = conn.Hello(); err != nil {
			log.Fatalf("Setup: can’t send hello message on private system bus: %v", err)
		}

		intro := fmt.Sprintf(`
		<node>
			<interface name="%s">
				<property name='Status' type='s' access="readwrite"/>
			</interface>%s%s</node>`, consts.SubcriptionDbusInterface, introspect.IntrospectDataString, prop.IntrospectDataString)
		ua := struct{}{}
		if err := conn.Export(ua, consts.SubcriptionDbusObjectPath, consts.SubcriptionDbusInterface); err != nil {
			log.Fatalf("Setup: could not export subscription object: %v", err)
		}

		propsSpec := map[string]map[string]*prop.Prop{
			consts.SubcriptionDbusInterface: {
				"Status": {
					Value:    "",
					Writable: true,
					Emit:     prop.EmitTrue,
					Callback: func(c *prop.Change) *dbus.Error { return nil },
				},
			},
		}
		_, err = prop.Export(conn, consts.SubcriptionDbusObjectPath, propsSpec)
		if err != nil {
			log.Fatalf("Setup: could not export property for subscription object: %v", err)
		}

		if err := conn.Export(introspect.Introspectable(intro), consts.SubcriptionDbusObjectPath,
			"org.freedesktop.DBus.Introspectable"); err != nil {
			log.Fatalf("Setup: could not export introspectable subscription object: %v", err)
		}

		reply, err := conn.RequestName(consts.SubcriptionDbusRegisteredName, dbus.NameFlagDoNotQueue)
		if err != nil {
			log.Fatalf("Setup: Failed to acquire sssd name on local system bus: %v", err)
		}
		if reply != dbus.RequestNameReplyPrimaryOwner {
			log.Fatalf("Setup: Failed to acquire sssd name on local system bus: name is already taken")
		}
	}

	m.Run()
}
