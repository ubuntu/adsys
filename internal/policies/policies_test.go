package policies_test

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"

	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

var update bool

func TestDumpPolicies(t *testing.T) {
	t.Parallel()

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
			m, err := policies.New(policies.WithCacheDir(cacheDir))
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			err = os.MkdirAll(filepath.Join(cacheDir, entry.GPORulesCacheBaseName), 0755)
			require.NoError(t, err, "Setup: cant not create gpo rule cache directory")

			if tc.cacheUser != "" {
				err := shutil.CopyFile(filepath.Join("testdata", "cache", tc.cacheUser), filepath.Join(cacheDir, entry.GPORulesCacheBaseName, "user"), false)
				require.NoError(t, err, "Setup: couldn’t copy user cache")
			}
			if tc.cacheMachine == "" {
				f, err := os.Create(filepath.Join(cacheDir, entry.GPORulesCacheBaseName, hostname))
				require.NoError(t, err, "Setup: failed to create empty machine cache file")
				f.Close()
			} else if tc.cacheMachine != "-" {
				err := shutil.CopyFile(filepath.Join("testdata", "cache", tc.cacheMachine), filepath.Join(cacheDir, entry.GPORulesCacheBaseName, hostname), false)
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

			goldPath := filepath.Join("testdata", "golden", name)
			// Update golden file
			if update {
				t.Logf("updating golden file %s", goldPath)
				err = os.WriteFile(goldPath, []byte(got), 0644)
				require.NoError(t, err, "Cannot write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load policy golden file")

			require.Equal(t, string(want), got, "DumpPolicies returned expected output")

		})
	}

}

func TestApplyPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		gposFile              string
		secondCallWithNoRules bool

		wantErr bool
	}{
		"succeed": {gposFile: "all_entry_types.gpos"},
		"second call with no rules deletes everything": {gposFile: "all_entry_types.gpos", secondCallWithNoRules: true},

		"dconf apply policy fails": {gposFile: "dconf_failing.gpos", wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gpos, err := entry.NewGPOs(filepath.Join("testdata", tc.gposFile))
			require.NoError(t, err, "Setup: can not load gpo list")

			fakeRootDir := t.TempDir()
			cacheDir := filepath.Join(fakeRootDir, "var", "cache", "adsys")
			dconfDir := filepath.Join(fakeRootDir, "etc", "dconf")
			m, err := policies.New(policies.WithCacheDir(cacheDir),
				policies.WithDconfDir(dconfDir))
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			err = os.MkdirAll(filepath.Join(cacheDir, entry.GPORulesCacheBaseName), 0755)
			require.NoError(t, err, "Setup: cant not create gpo rule cache directory")

			err = m.ApplyPolicy(context.Background(), "hostname", true, gpos)
			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should return an error but got none")
				return
			}
			require.NoError(t, err, "ApplyPolicy should return no error but got one")

			if tc.secondCallWithNoRules {
				err = m.ApplyPolicy(context.Background(), "hostname", true, nil)
				require.NoError(t, err, "ApplyPolicy should return no error but got one")
			}

			testutils.CompareTreesWithFiltering(t, fakeRootDir, filepath.Join("testdata", "golden", name), update)
		})
	}
}

func TestLastUpdateFor(t *testing.T) {
	t.Parallel()

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
			m, err := policies.New(policies.WithCacheDir(cacheDir))
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			err = os.MkdirAll(filepath.Join(cacheDir, entry.GPORulesCacheBaseName), 0755)
			require.NoError(t, err, "Setup: cant not create gpo rule cache directory")

			start := time.Now()
			// Starts and ends are monotic, while os.Stat is wall clock, we have to wait for measuring difference…
			time.Sleep(10 * time.Millisecond)
			f, err := os.Create(filepath.Join(cacheDir, entry.GPORulesCacheBaseName, "user"))
			require.NoError(t, err, "Setup: couldn’t copy user cache")
			f.Close()
			f, err = os.Create(filepath.Join(cacheDir, entry.GPORulesCacheBaseName, hostname))
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

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
