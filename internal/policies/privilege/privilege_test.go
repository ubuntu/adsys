package privilege_test

import (
	"context"
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
		notComputer bool
		entries     []entry.Entry

		destIsDir                string
		makeReadOnly             string
		existingFS               string
		polkitSystemReservedPath string

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
			existingFS: "existing-previous-local-admins-multi",
			entries: []entry.Entry{
				{Key: "allow-local-admins", Disabled: true},
				{Key: "client-admins", Value: "alice@domain.com"}}},
		"Allow local admins without previous local admin conf and set client admins": {entries: []entry.Entry{
			{Key: "allow-local-admins", Disabled: false},
			{Key: "client-admins", Value: "alice@domain.com"}}},
		"Allow local admins with previous local admin conf (simple) and set client admins": {
			existingFS: "existing-previous-local-admins-one",
			entries: []entry.Entry{
				{Key: "allow-local-admins", Disabled: false},
				{Key: "client-admins", Value: "alice@domain.com"}}},
		"Allow local admins with previous local admin conf and set client admins": {
			existingFS: "existing-previous-local-admins-multi",
			entries: []entry.Entry{
				{Key: "allow-local-admins", Disabled: false},
				{Key: "client-admins", Value: "alice@domain.com"}}},
		"Allow local admins with previous local admin conf (with adsys file) and set client admins": {
			existingFS: "existing-previous-local-admins-with-adsys-file",
			entries: []entry.Entry{
				{Key: "allow-local-admins", Disabled: false},
				{Key: "client-admins", Value: "alice@domain.com"}}},

		// Overwrite existing files
		"No rules and no existing history means no files": {},
		"Overwrite existing sudoers file":                 {existingFS: "existing-files", entries: defaultLocalAdminDisabledRule},
		"Overwrite existing polkit file":                  {existingFS: "existing-files", entries: defaultLocalAdminDisabledRule},
		"No rules still overwrite those files":            {existingFS: "existing-files"},
		"Don't overwrite other existing files":            {existingFS: "existing-other-files", entries: defaultLocalAdminDisabledRule},

		// Migration
		"Create on new polkit version and remove old file":    {existingFS: "existing-old-adsys-conf", entries: []entry.Entry{{Key: "client-admins", Value: "alice@domain.com"}}},
		"Assume old polkit if cant read system reserved path": {existingFS: "old-polkit", entries: []entry.Entry{{Key: "client-admins", Value: "alice@domain.com"}}, polkitSystemReservedPath: "doesnotexist"},

		// Not a computer, don’t do anything (even not create new files)
		"Not a computer": {notComputer: true, existingFS: "existing-other-files"},

		// Error cases
		"Error on writing to sudoers file":                          {makeReadOnly: "etc/sudoers.d/", existingFS: "existing-files", entries: defaultLocalAdminDisabledRule, wantErr: true},
		"Error on writing to polkit subdirectory creation":          {makeReadOnly: "etc/polkit-1/", existingFS: "only-base-polkit-dir", entries: defaultLocalAdminDisabledRule, wantErr: true},
		"Error on writing to polkit conf file":                      {makeReadOnly: "etc/polkit-1/rules.d", existingFS: "existing-files", entries: defaultLocalAdminDisabledRule, wantErr: true},
		"Error on creating sudoers and polkit base directory":       {makeReadOnly: "etc", entries: defaultLocalAdminDisabledRule, wantErr: true},
		"Error if can’t rename to destination for sudoers file":     {destIsDir: "etc/sudoers.d/99-adsys-privilege-enforcement", entries: defaultLocalAdminDisabledRule, wantErr: true},
		"Error if can’t rename to destination for polkit conf file": {destIsDir: "etc/polkit-1/rules.d/00-adsys-privilege-enforcement.rules", entries: defaultLocalAdminDisabledRule, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tmp, err := os.MkdirTemp("", "privilege-test")
			require.NoError(t, err, "Setup: Failed to create tempdir for tests")
			t.Cleanup(func() { _ = os.RemoveAll(tmp) })
			tmpRootDir := filepath.Join(tmp, "root")

			if tc.existingFS != "" {
				err = shutil.CopyTree(filepath.Join("testdata", tc.existingFS), tmpRootDir, &shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy})
				require.NoError(t, err, "Setup: can't create initial filesystem")
			}

			sudoersDir := filepath.Join(tmpRootDir, "etc", "sudoers.d")
			policyKitDir := filepath.Join(tmpRootDir, "etc", "polkit-1")
			if tc.polkitSystemReservedPath == "" {
				tc.polkitSystemReservedPath = filepath.Join(tmpRootDir, "usr", "share", "polkit-1")
			}

			// make read only destination to not be able to overwrite or write into it
			if tc.makeReadOnly != "" {
				_ = os.MkdirAll(filepath.Join(tmpRootDir, tc.makeReadOnly), 0750)
				testutils.MakeReadOnly(t, filepath.Join(tmpRootDir, tc.makeReadOnly))
			}

			// Fake destination unwritable file
			if tc.destIsDir != "" {
				require.NoError(t, os.MkdirAll(filepath.Join(tmpRootDir, tc.destIsDir), 0750), "Setup: can't create fake unwritable file")
			}

			m := privilege.NewWithDirs(sudoersDir, policyKitDir, privilege.WithPolicyKitSystemDir(tc.polkitSystemReservedPath))
			err = m.ApplyPolicy(context.Background(), "ubuntu", !tc.notComputer, tc.entries)
			if tc.wantErr {
				require.NotNil(t, err, "ApplyPolicy should have failed but didn't")
				return
			}
			require.NoError(t, err, "ApplyPolicy failed but shouldn't have")

			testutils.CompareTreesWithFiltering(t, filepath.Join(tmpRootDir, "etc"), testutils.GoldenPath(t), testutils.UpdateEnabled())
		})
	}
}
