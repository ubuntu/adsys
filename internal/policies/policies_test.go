package policies_test

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"

	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/entry"
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

			goldPath := filepath.Join("testdata", "golden", name)
			// Update golden file
			if update {
				t.Logf("updating golden file %s", goldPath)
				require.NoError(t, os.RemoveAll(goldPath), "Cannot remove target golden directory")
				// Filter dconf generated DB files that are machine dependent
				require.NoError(t,
					shutil.CopyTree(
						fakeRootDir, goldPath,
						&shutil.CopyTreeOptions{Symlinks: true, Ignore: ignoreDconfDB, CopyFunction: shutil.Copy}),
					"Can’t update golden directory")
			}

			// Check we generated wanted non binary files
			gotContent := treeContent(t, fakeRootDir, []byte("GVariant"))
			goldContent := treeContent(t, goldPath, nil)
			assert.Equal(t, goldContent, gotContent, "got and expected content differs")

			// Dconf: verify that each <DB>.d has a corresponding gvariant db generated by dconf update
			dbs, err := filepath.Glob(filepath.Join(dconfDir, "db", "*.d"))
			require.NoError(t, err, "Checking pattern for dconf db failed")
			for _, db := range dbs {
				_, err = os.Stat(strings.TrimSuffix(db, ".db"))
				assert.NoError(t, err, "Binary version of dconf DB should exists")
			}
		})
	}
}

// treeContent build a recursive file list of dir with their content
func treeContent(t *testing.T, dir string, ignoreHeaders []byte) map[string]string {
	t.Helper()

	r := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("couldn't access path %q: %v", path, err)
		}

		content := ""
		if !info.IsDir() {
			d, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// ignore given header
			if ignoreHeaders != nil && bytes.HasPrefix(d, ignoreHeaders) {
				return nil
			}
			content = string(d)
		}
		r[strings.TrimPrefix(path, dir)] = content
		return nil
	})

	if err != nil {
		t.Fatalf("error while listing directory: %v", err)
	}

	return r
}

func ignoreDconfDB(src string, entries []os.FileInfo) []string {
	var r []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		d, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			continue
		}

		if bytes.HasPrefix(d, []byte("GVariant")) {
			r = append(r, e.Name())
		}
	}
	return r
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
