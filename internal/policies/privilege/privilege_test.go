package privilege_test

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/policies/privilege"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestApplyPolicy(t *testing.T) {
	t.Parallel()

	defaultLocalAdminDisabledRule := []entry.Entry{{Key: "allow-local-admins", Disabled: true}}

	tests := map[string]struct {
		notComputer        bool
		entries            []entry.Entry
		existingSudoersDir string
		existingPolkitDir  string
		makeReadOnly       string
		destIsDir          string

		wantErr bool
	}{
		// local admin cases
		"Disallow local admins":                            {entries: []entry.Entry{{Key: "allow-local-admins", Disabled: true}}},
		"Allow local admins with no other rules is a noop": {entries: []entry.Entry{{Key: "allow-local-admins", Disabled: false}}},

		// client admins from AD
		"Set client user admins":                       {entries: []entry.Entry{{Key: "client-admins", Value: "alice@domain.com"}}},
		"Set client multiple users admins":             {entries: []entry.Entry{{Key: "client-admins", Value: "alice@domain.com,domain\\bob,carole cosmic@otherdomain.com"}}},
		"Set client group admins":                      {entries: []entry.Entry{{Key: "client-admins", Value: "%group@domain.com"}}},
		"Set client mixed with users and group admins": {entries: []entry.Entry{{Key: "client-admins", Value: "alice@domain.com,%group@domain.com"}}},
		"Empty client AD admins":                       {entries: []entry.Entry{{Key: "client-admins", Value: ""}}},
		"No client AD admins":                          {entries: []entry.Entry{{Key: "client-admins", Disabled: true}}},

		// Mixed rules
		"Disallow local admins and set client admins": {entries: []entry.Entry{
			{Key: "allow-local-admins", Disabled: true},
			{Key: "client-admins", Value: "alice@domain.com"}}},
		"Disallow local admins with previous local admin conf and set client admins": {
			existingPolkitDir: "existing-previous-local-admins-multi",
			entries: []entry.Entry{
				{Key: "allow-local-admins", Disabled: true},
				{Key: "client-admins", Value: "alice@domain.com"}}},
		"Allow local admins without previous local admin conf and set client admins": {entries: []entry.Entry{
			{Key: "allow-local-admins", Disabled: false},
			{Key: "client-admins", Value: "alice@domain.com"}}},
		"Allow local admins with previous local admin conf (simple) and set client admins": {
			existingPolkitDir: "existing-previous-local-admins-one",
			entries: []entry.Entry{
				{Key: "allow-local-admins", Disabled: false},
				{Key: "client-admins", Value: "alice@domain.com"}}},
		"Allow local admins with previous local admin conf and set client admins": {
			existingPolkitDir: "existing-previous-local-admins-multi",
			entries: []entry.Entry{
				{Key: "allow-local-admins", Disabled: false},
				{Key: "client-admins", Value: "alice@domain.com"}}},
		"Allow local admins with previous local admin conf (with adsys file) and set client admins": {
			existingPolkitDir: "existing-previous-local-admins-with-adsys-file",
			entries: []entry.Entry{
				{Key: "allow-local-admins", Disabled: false},
				{Key: "client-admins", Value: "alice@domain.com"}}},

		// Overwrite existing files
		"No rules and no existing history means no files": {},
		"Overwrite existing sudoers file":                 {existingSudoersDir: "existing-files", entries: defaultLocalAdminDisabledRule},
		"Overwrite existing polkit file":                  {existingPolkitDir: "existing-files", entries: defaultLocalAdminDisabledRule},
		"No rules still overwrite those files":            {existingSudoersDir: "existing-files", existingPolkitDir: "existing-files"},
		"Don't overwrite other existing files":            {existingSudoersDir: "existing-other-files", existingPolkitDir: "existing-other-files", entries: defaultLocalAdminDisabledRule},

		// Not a computer, don’t do anything (even not create new files)
		"Not a computer": {notComputer: true, existingSudoersDir: "existing-other-files", existingPolkitDir: "existing-other-files"},

		// Error cases
		"Error on writing to sudoers file":                          {makeReadOnly: "sudoers.d/", existingSudoersDir: "existing-files", existingPolkitDir: "existing-files", entries: defaultLocalAdminDisabledRule, wantErr: true},
		"Error on writing to polkit subdirectory creation":          {makeReadOnly: "polkit-1/", existingSudoersDir: "existing-files", existingPolkitDir: "only-base-polkit-dir", entries: defaultLocalAdminDisabledRule, wantErr: true},
		"Error on writing to polkit conf file":                      {makeReadOnly: "polkit-1/localauthority.conf.d", existingSudoersDir: "existing-files", existingPolkitDir: "existing-files", entries: defaultLocalAdminDisabledRule, wantErr: true},
		"Error on creating sudoers and polkit base directory":       {makeReadOnly: ".", entries: defaultLocalAdminDisabledRule, wantErr: true},
		"Error if can’t rename to destination for sudoers file":     {destIsDir: "sudoers.d/99-adsys-privilege-enforcement", entries: defaultLocalAdminDisabledRule, wantErr: true},
		"Error if can’t rename to destination for polkit conf file": {destIsDir: "polkit-1/localauthority.conf.d/99-adsys-privilege-enforcement.conf", entries: defaultLocalAdminDisabledRule, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tempEtc := t.TempDir()
			sudoersDir := filepath.Join(tempEtc, "sudoers.d")
			policyKitDir := filepath.Join(tempEtc, "polkit-1")

			if tc.existingSudoersDir != "" {
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", tc.existingSudoersDir, "sudoers.d"), sudoersDir,
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't create initial sudoer directory")
			}
			if tc.existingPolkitDir != "" {
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", tc.existingPolkitDir, "polkit-1"), policyKitDir,
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't create initial polkit directory")
			}
			// make read only destination to not be able to overwrite or write into it
			if tc.makeReadOnly != "" {
				testutils.MakeReadOnly(t, filepath.Join(tempEtc, tc.makeReadOnly))
			}

			// Fake destination unwritable file
			if tc.destIsDir != "" {
				require.NoError(t, os.MkdirAll(filepath.Join(tempEtc, tc.destIsDir), 0750), "Setup: can't create fake unwritable file")
			}

			m := privilege.NewWithDirs(sudoersDir, policyKitDir)
			err := m.ApplyPolicy(context.Background(), "ubuntu", !tc.notComputer, tc.entries)
			if tc.wantErr {
				require.NotNil(t, err, "ApplyPolicy should have failed but didn't")
				return
			}
			require.NoError(t, err, "ApplyPolicy failed but shouldn't have")

			testutils.CompareTreesWithFiltering(t, tempEtc, testutils.GoldenPath(t), testutils.Update())
		})
	}
}

func TestMain(m *testing.M) {
	testutils.InstallUpdateFlag()
	flag.Parse()

	m.Run()
}
