package dconf_test

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
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

		// help users with quoting, normalizing… (common use cases here: more tests in internal_tests)
		"unquoted string": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-s", Value: "onekey-s", Meta: "s"},
		}},
		"no surrounding brackets ai": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "1", Meta: "ai"},
		}},
		"no surrounding brackets multiple ai": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "1,2", Meta: "ai"},
		}},
		"no surrounding brackets unquoted as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "simple-as", Meta: "as"},
		}},
		"no surrounding brackets unquoted multiple as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "two-as1, two-as2", Meta: "as"},
		}},
		"no surrounding brackets quoted as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "'simple-as'", Meta: "as"},
		}},
		"no surrounding brackets quoted multiple as": {entries: []entry.Entry{
			{Key: "com/ubuntu/category/key-ai", Value: "'two-as1', 'two-as2'", Meta: "as"},
		}},

		// Profiles tests
		"update existing profile stays as it if correct ending": {entries: nil,
			existingDconfDir: "existing-user"},
		"update existing profile without needed db add them at the end": {entries: nil,
			existingDconfDir: "existing-user-no-adsysdb"},
		"update existing profile without needed db but trainline new lines normalize it": {entries: nil,
			existingDconfDir: "existing-user-no-adsysdb-trailing-newlines"},
		"update existing profile without complete needed db readd them at the end": {entries: nil,
			existingDconfDir: "existing-user-one-adsysdb-end"},
		"update existing profile with partial needed db  readd them at the end": {entries: nil,
			existingDconfDir: "existing-user-one-adsysdb-middle"},

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
			err := m.ApplyPolicy("ubuntu", tc.isComputer, tc.entries)
			if tc.wantErr {
				require.NotNil(t, err, "ApplyPolicy should have failed but didn't")
				return
			}
			require.NoError(t, err, "ApplyPolicy failed but shouldn't have")

			goldPath := filepath.Join("testdata", "golden", name)
			// Update golden file
			if update {
				t.Logf("updating golden file %s", goldPath)
				require.NoError(t, os.RemoveAll(goldPath), "Cannot remove target golden directory")
				// Filter dconf generated DB files that are machine dependent
				require.NoError(t,
					shutil.CopyTree(
						dconfDir, goldPath,
						&shutil.CopyTreeOptions{Symlinks: true, Ignore: ignoreDconfDB, CopyFunction: shutil.Copy}),
					"Can’t update golden directory")
			}

			gotContent := treeContent(t, dconfDir, []byte("GVariant"))
			goldContent := treeContent(t, goldPath, nil)
			assert.Equal(t, goldContent, gotContent, "got and expected content differs")

			// Verify that each <DB>.d has a corresponding gvariant db generated by dconf update
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
			d, err := ioutil.ReadFile(path)
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
		d, err := ioutil.ReadFile(filepath.Join(src, e.Name()))
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
