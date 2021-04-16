package dconf_test

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

var update bool

func TestApplyPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		isComputer       bool
		entries          []entry.Entry
		existingDconfDir string

		wantErr bool
	}{
		// user cases
		"new user": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}}},
		"user updates existing value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-thirdvalue'", Meta: "s"}},
			existingDconfDir: "existing-user"},
		"user updates with different value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "['simple-as']", Meta: "as"}},
			existingDconfDir: "existing-user"},
		"user updates key is now disabled": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Disabled: true, Meta: "s"}},
			existingDconfDir: "existing-user"},
		"update user disabled key with value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			existingDconfDir: "user-with-disabled-value"},

		// machine cases
		"first boot": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			isComputer: true, existingDconfDir: "-"},
		"machine updates existing value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-thirdvalue'", Meta: "s"}},
			isComputer: true},
		"machine updates with different value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "['simple-as']", Meta: "as"}},
			isComputer: true},
		"machine updates key is now disabled": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Disabled: true, Meta: "s"}},
			isComputer: true},
		"update machine disabled key with value": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			isComputer: true, existingDconfDir: "machine-with-disabled-value"},

		"no policy still generates a valid db": {entries: nil},
		"multiple keys same category": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"},
			{Key: "com/ubuntu/category/key-as", Value: "['simple-as']", Meta: "as"},
		}},
		"multiple sections": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"},
			{Key: "com/ubuntu/category2/key-s2", Value: "'onekey-s2'", Meta: "s"},
		}},
		"multiple sections with disabled keys": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Disabled: true, Meta: "s"},
			{Key: "com/ubuntu/category2/key-s2", Disabled: true, Meta: "s"},
		}},
		"mixing sections and keys still groups sections": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"},
			{Key: "com/ubuntu/category2/key-s2", Value: "'onekey-s2'", Meta: "s"},
			{Key: "com/ubuntu/category/key-as", Value: "['simple-as']", Meta: "as"},
		}},

		// Update edge cases
		"no update when no change": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			existingDconfDir: "existing-user"},
		"missing machine compiled db for machine": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			isComputer: true, existingDconfDir: "missing-machine-compiled-db"},
		"missing machine compiled db for user": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			isComputer: false, existingDconfDir: "missing-machine-compiled-db"},
		"missing user compiled db for user": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"}},
			existingDconfDir: "missing-user-compiled-db"},

		// Normalized keys formats
		"normalized canonical form for each supported key": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s'", Meta: "s"},
			{Key: "com/ubuntu/category/key-i", Value: "'42'", Meta: "i"},
			{Key: "com/ubuntu/category/key-b", Value: "true", Meta: "b"},
			{Key: "com/ubuntu/category/key-as", Value: "['simple-as']", Meta: "as"},
			{Key: "com/ubuntu/category/key-ai", Value: "[42]", Meta: "ai"},
			{Key: "com/ubuntu/category/key-returnedunmodified", Value: "[[1,2,3],[4,5,6]]", Meta: "aai"},
		}},

		// help users with quoting, normalizing… (common use cases here: more tests in internal_tests)
		"unquoted string": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "onekey-s", Meta: "s"},
		}},
		"quoted i": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-i", Value: "'1'", Meta: "i"},
		}},
		"quoted b": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-b", Value: "'true'", Meta: "b"},
		}},
		"no surrounding brackets ai": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "1", Meta: "ai"},
		}},
		"no surrounding brackets multiple ai": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "1,2", Meta: "ai"},
		}},
		"no surrounding brackets unquoted as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "simple-as", Meta: "as"},
		}},
		"no surrounding brackets unquoted multiple as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "two-as1, two-as2", Meta: "as"},
		}},
		"no surrounding brackets quoted as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "'simple-as'", Meta: "as"},
		}},
		"no surrounding brackets quoted multiple as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "'two-as1', 'two-as2'", Meta: "as"},
		}},
		"multi-lines as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "first\nsecond\n", Meta: "as"},
		}},
		"multi-lines as mixed with comma": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: "first,second\nthird\n", Meta: "as"},
		}},
		"multi-lines ai": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "1\n2\n", Meta: "ai"},
		}},
		"multi-lines ai mixed with comma": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "1,2\n3\n", Meta: "ai"},
		}},

		// Profiles tests
		"update existing correct profile stays unchanged": {entries: nil,
			existingDconfDir: "existing-user"},
		"update existing correct profile with trailing spaces are removed": {entries: nil,
			existingDconfDir: "existing-user-with-trailing-spaces"},
		"update existing profile without needed db append them": {entries: nil,
			existingDconfDir: "existing-user-no-adsysdb"},
		"update existing profile without needed db, trailine lines are removed": {entries: nil,
			existingDconfDir: "existing-user-no-adsysdb-trailing-newlines"},
		"update existing profile with partial db append them without repetition": {entries: nil,
			existingDconfDir: "existing-user-one-adsysdb-partial"},
		"update existing profile with wrong order appends them in correct order": {entries: nil,
			existingDconfDir: "existing-user-one-adsysdb-reversed-end"},
		"update existing profile eliminates adsys DB repetitions": {entries: nil,
			existingDconfDir: "existing-user-adsysdb-repetitions"},

		// non adsys content
		"do not update other files from db": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-thirdvalue'", Meta: "s"}},
			existingDconfDir: "existing-user-with-extra-files"},
		"do not interfere with other user profile": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-thirdvalue'", Meta: "s"}},
			existingDconfDir: "existing-other-user"},

		"invalid as is too robust to produce defaulting values": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-as", Value: `[value1, ] value2]`, Meta: "as"},
		}},

		// Error cases
		"no machine db will fail": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "'onekey-s-othervalue'", Meta: "s"},
		}, existingDconfDir: "-", wantErr: true},
		"error on invalid ai": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "[1,b]", Meta: "ai"},
		}, wantErr: true},
		"error on invalid value for unnormalized type": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-i", Value: "NaN", Meta: "i"},
		}, wantErr: true},
		"error on invalid type": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-something", Value: "value", Meta: "sometype"},
		}, wantErr: true},
		"error on empty meta": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-something", Value: "value", Meta: ""},
		}, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dconfDir := t.TempDir()

			if tc.existingDconfDir == "" {
				tc.existingDconfDir = "machine-base"
			}
			if tc.existingDconfDir != "-" {
				require.NoError(t, os.Remove(dconfDir), "Setup: can't delete dconf base directory before recreation")
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "dconf", tc.existingDconfDir), dconfDir,
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't create initial dconf directory")
			}

			m := dconf.NewWithDconfDir(dconfDir)
			err := m.ApplyPolicy(context.Background(), "ubuntu", tc.isComputer, tc.entries)
			if tc.wantErr {
				require.NotNil(t, err, "ApplyPolicy should have failed but didn't")
				return
			}
			require.NoError(t, err, "ApplyPolicy failed but shouldn't have")

			testutils.CompareTreesWithFiltering(t, dconfDir, filepath.Join("testdata", "golden", name), update)
		})
	}
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
