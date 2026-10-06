package dconf

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		keyType string
		value   string

		want string
	}{
		// string cases
		"simple quoted string":   {keyType: "s", value: "'hello world'", want: "'hello world'"},
		"simple unquoted string": {keyType: "s", value: "hello world", want: "'hello world'"},
		"empty quoted string":    {keyType: "s", value: "''", want: "''"},
		"empty unquoted string":  {keyType: "s", value: "", want: "''"},

		"one quote":         {keyType: "s", value: "'", want: `'\''`},
		"one escaped quote": {keyType: "s", value: `\'`, want: `'\''`},

		"quoted string with quotes":                       {keyType: "s", value: "'this isn't a quote'", want: `'this isn\'t a quote'`},
		"unquoted string with quotes":                     {keyType: "s", value: "this isn't a quote", want: `'this isn\'t a quote'`},
		"string with escaped quotes":                      {keyType: "s", value: `this isn\'t a quote`, want: `'this isn\'t a quote'`},
		"string with multiple backslashes escaped quotes": {keyType: "s", value: `this isn\\\'t a quote`, want: `'this isn\\\'t a quote'`},
		"string with two backslashes don’t escape quotes": {keyType: "s", value: `this isn\\'t a quote`, want: `'this isn\\\'t a quote'`},

		// boolean cases
		"simple boolean true":             {keyType: "b", value: "true", want: "true"},
		"weird case true":                 {keyType: "b", value: "tRuE", want: "true"},
		"with spaces":                     {keyType: "b", value: "  true  ", want: "true"},
		"yes transformed to boolean":      {keyType: "b", value: "yes", want: "true"},
		"y transformed to boolean":        {keyType: "b", value: "y", want: "true"},
		"on transformed to boolean":       {keyType: "b", value: "on", want: "true"},
		"simple boolean false":            {keyType: "b", value: "false", want: "false"},
		"weird case false":                {keyType: "b", value: "fAlSe", want: "false"},
		"no transformed to boolean":       {keyType: "b", value: "no", want: "false"},
		"n transformed to boolean":        {keyType: "b", value: "n", want: "false"},
		"off transformed to boolean":      {keyType: "b", value: "off", want: "false"},
		"non supported is reported as is": {keyType: "b", value: "nonboolean", want: "nonboolean"},

		// as cases
		"simple unquoted as":                               {keyType: "as", value: "[aa, bb, cc]", want: "['aa', 'bb', 'cc']"},
		"simple quoted as":                                 {keyType: "as", value: "['aa', 'bb', 'cc']", want: "['aa', 'bb', 'cc']"},
		"simple as with no spaces":                         {keyType: "as", value: "[aa,bb,cc]", want: "['aa', 'bb', 'cc']"},
		"as with spaces inside":                            {keyType: "as", value: "[aa   ,bb,   cc]", want: "['aa', 'bb', 'cc']"},
		"as without leading [":                             {keyType: "as", value: "aa,bb,cc]", want: "['aa', 'bb', 'cc']"},
		"as without ending ]":                              {keyType: "as", value: "[aa,bb,cc", want: "['aa', 'bb', 'cc']"},
		"as with leading and ending spaces and no []":      {keyType: "as", value: "    aa,bb,cc   ", want: "['aa', 'bb', 'cc']"},
		"as with leading and ending spaces and  []":        {keyType: "as", value: "    [aa,bb,cc]   ", want: "['aa', 'bb', 'cc']"},
		"as simple quoted as with spaces":                  {keyType: "as", value: "      ['aa', 'bb', 'cc']    ", want: "['aa', 'bb', 'cc']"},
		"as empty elements separated with commas are kept": {keyType: "as", value: "[aa,bb,,cc]", want: "['aa', 'bb', '', 'cc']"},

		"as partially quoted can lead to unexpect result":                  {keyType: "as", value: "[aa,'bb',cc]", want: `['aa', '\'bb\'', 'cc']`},
		"as partially quoted with comma can lead to unexpected result":     {keyType: "as", value: "[aa,'b,b',cc]", want: `['aa', '\'b', 'b\'', 'cc']`},
		"as partially quoted unbalanced start can lead to unexpect result": {keyType: "as", value: "['aa,'bb',cc]", want: `['\'aa', '\'bb\'', 'cc']`},
		"as partially quoted unbalanced end can lead to unexpect result":   {keyType: "as", value: "[aa,'bb',cc']", want: `['aa', '\'bb\'', 'cc\'']`},
		"as wrongly quoted will consider comma as part of the string":      {keyType: "as", value: "['aa,'bb',cc']", want: `['aa,\'bb\',cc']`},
		"as with weird composition inception will be quoted":               {keyType: "as", value: "[value1, ] value2]", want: `['value1', '] value2']`},
		"as with empty quoted can lead to unexpect result":                 {keyType: "as", value: "[aa,'bb',cc]", want: `['aa', '\'bb\'', 'cc']`},

		"Multi-lines as unquoted":                                                   {keyType: "as", value: "aa\nbb\ncc", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as quoted":                                                     {keyType: "as", value: "'aa'\n'bb'\n'cc'", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with spaces inside":                                         {keyType: "as", value: "aa   \nbb\n   cc", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with leading and trailing brackets":                         {keyType: "as", value: "[aa\nbb\ncc]", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as and single line mix, unquoted":                              {keyType: "as", value: "aa,bb\ncc", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as and single line mix, quoted":                                {keyType: "as", value: "'aa','bb'\n'cc'", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with quoted ',' is supported":                               {keyType: "as", value: "'aa,bb'\n'cc'", want: "['aa,bb', 'cc']"},
		"Multi-lines as with all unquoted ',' will split":                           {keyType: "as", value: "aa,bb\ncc", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with empty lines strips empty elements":                     {keyType: "as", value: "aa\n\ncc", want: "['aa', 'cc']"},
		"Multi-lines as with consecutive empty lines strip empty elements":          {keyType: "as", value: "aa\n\n\n\ncc", want: "['aa', 'cc']"},
		"Multi-lines as with explicit empty element":                                {keyType: "as", value: "'aa'\n''\n'cc'", want: "['aa', '', 'cc']"},
		"Multi-lines as with leading or trailing empty lines are ignored":           {keyType: "as", value: "\n\n\n\naa\nbb\ncc\n\n\n\n\n", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with leading or trailing empty lines before [] are ignored": {keyType: "as", value: "[\n\n\n\naa\nbb\ncc\n\n\n\n\n]", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with leading or trailing empty lines after [] are ignored":  {keyType: "as", value: "\n\n\n\n[aa\nbb\ncc]\n\n\n\n\n", want: "['aa', 'bb', 'cc']"},

		// ai cases
		"simple ai":                                        {keyType: "ai", value: "[1, 2, 3]", want: "[1, 2, 3]"},
		"simple ai with no spaces":                         {keyType: "ai", value: "[1,2,3]", want: "[1, 2, 3]"},
		"ai with spaces inside":                            {keyType: "ai", value: "[1   ,2,   3]", want: "[1, 2, 3]"},
		"ai without leading [":                             {keyType: "ai", value: "1,2,3]", want: "[1, 2, 3]"},
		"ai without ending ]":                              {keyType: "ai", value: "[1,2,3", want: "[1, 2, 3]"},
		"ai with leading and ending spaces and no []":      {keyType: "ai", value: "    1,2,3   ", want: "[1, 2, 3]"},
		"ai with leading and ending spaces and  []":        {keyType: "ai", value: "    [1,2,3]   ", want: "[1, 2, 3]"},
		"ai empty elements separated with commas are kept": {keyType: "ai", value: "1,,3", want: "[1, , 3]"},

		"Multi-lines ai":                                                            {keyType: "ai", value: "1\n2\n3", want: "[1, 2, 3]"},
		"Multi-lines ai with spaces inside":                                         {keyType: "ai", value: "1\n   2\n   3", want: "[1, 2, 3]"},
		"Multi-lines ai with leading and trailing brackets":                         {keyType: "ai", value: "[1\n2\n3]", want: "[1, 2, 3]"},
		"Multi-lines ai with all unquoted ',' will split":                           {keyType: "ai", value: "1,2\n3", want: "[1, 2, 3]"},
		"Multi-lines ai with empty lines strips empty element":                      {keyType: "ai", value: "1\n\n3", want: "[1, 3]"},
		"Multi-lines ai with consecutive empty lines strips empty element":          {keyType: "ai", value: "1\n\n\n\n3", want: "[1, 3]"},
		"Multi-lines ai with leading or trailing empty lines are ignored":           {keyType: "ai", value: "\n\n\n\n1\n2\n3\n\n\n\n\n", want: "[1, 2, 3]"},
		"Multi-lines ai with leading or trailing empty lines before [] are ignored": {keyType: "ai", value: "[\n\n\n\n1\n2\n3\n\n\n\n\n]", want: "[1, 2, 3]"},
		"Multi-lines ai with leading or trailing empty lines after [] are ignored":  {keyType: "ai", value: "\n\n\n\n[1\n2\n3]\n\n\n\n\n", want: "[1, 2, 3]"},

		// Unmanaged cases
		"unmanaged types are returned as is": {keyType: "xxx", value: "hello [ %x bar 🤪", want: "hello [ %x bar 🤪"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := normalizeValue(tc.keyType, tc.value)
			assert.Equal(t, tc.want, got, "normalizeValue returned expected value")
		})
	}
}

func TestDconfDatabaseIsUpToDate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		newerSourcePath string
		equalSourcePath string
		removeDatabase  bool
		wantUpToDate    bool
	}{
		{name: "Fresh database", wantUpToDate: true},
		{name: "Missing database", removeDatabase: true},
		{name: "Keyfile directory newer", newerSourcePath: ".d"},
		{name: "Keyfile newer", newerSourcePath: ".d/adsys"},
		{name: "Locks directory newer", newerSourcePath: ".d/locks"},
		{name: "Lock file newer", newerSourcePath: ".d/locks/adsys"},
		{name: "Keyfile directory has compiled timestamp", equalSourcePath: ".d"},
		{name: "Keyfile has compiled timestamp", equalSourcePath: ".d/adsys"},
		{name: "Locks directory has compiled timestamp", equalSourcePath: ".d/locks"},
		{name: "Lock file has compiled timestamp", equalSourcePath: ".d/locks/adsys"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dbPath := filepath.Join(t.TempDir(), "db", "machine")
			createDconfDatabaseFiles(t, dbPath)

			baseTime := time.Unix(1_700_000_000, 0)
			setDconfDatabaseTimes(t, dbPath, baseTime.Add(time.Second), baseTime, baseTime, baseTime, baseTime)
			if tc.removeDatabase {
				require.NoError(t, os.Remove(dbPath))
			}
			if tc.newerSourcePath != "" {
				setDconfTestMtime(t, dbPath+tc.newerSourcePath, baseTime.Add(2*time.Second))
			}
			if tc.equalSourcePath != "" {
				setDconfTestMtime(t, dbPath+tc.equalSourcePath, baseTime.Add(time.Second))
			}

			assert.Equal(t, tc.wantUpToDate, dconfDatabaseIsUpToDate(dbPath))
		})
	}
}

func TestApplyPolicyDconfUpdateFailure(t *testing.T) {
	var logs bytes.Buffer
	logger := logrus.StandardLogger()
	originalOutput := logger.Out
	logger.SetOutput(&logs)
	t.Cleanup(func() { logger.SetOutput(originalOutput) })

	tests := []struct {
		name                     string
		isComputer               bool
		setup                    func(t *testing.T, dconfDir string)
		updater                  func(dbDir string) ([]byte, error)
		wantErrorContains        []string
		wantExitError            bool
		wantExecError            bool
		wantWarningContain       []string
		wantFreshDatabases       []string
		wantNotUpToDateDatabases []string
	}{
		{
			name:              "Missing machine database after failed update",
			isComputer:        true,
			updater:           failedDconfUpdate,
			wantErrorContains: []string{"dconf update failed", "simulated dconf update failure", "exit status 1", "machine"},
			wantExitError:     true,
		},
		{
			name:       "Stale machine database after failed update",
			isComputer: true,
			setup: func(t *testing.T, dconfDir string) {
				t.Helper()

				dbPath := filepath.Join(dconfDir, "db", "machine")
				createDconfDatabaseFiles(t, dbPath)
				require.NoError(t, os.Chtimes(dbPath, time.Unix(1, 0), time.Unix(1, 0)))
			},
			updater:           failedDconfUpdate,
			wantErrorContains: []string{"dconf update failed", "simulated dconf update failure", "exit status 1", "machine"},
			wantExitError:     true,
		},
		{
			name: "Missing user database after failed update",
			setup: func(t *testing.T, dconfDir string) {
				t.Helper()

				dbPath := filepath.Join(dconfDir, "db", "machine")
				createDconfDatabaseFiles(t, dbPath)
				baseTime := time.Unix(1_700_000_000, 0)
				setDconfDatabaseTimes(t, dbPath, baseTime.Add(time.Second), baseTime, baseTime, baseTime, baseTime)
			},
			updater:           failedDconfUpdate,
			wantErrorContains: []string{"dconf update failed", "simulated dconf update failure", "exit status 1", "ubuntu"},
			wantExitError:     true,
		},
		{
			name:       "New machine database with equal source timestamp is accepted",
			isComputer: true,
			updater:    recompiledMachineDconfUpdateWithEqualTimestamp,
			wantWarningContain: []string{
				"dconf update failed, but ADSys-managed databases were compiled or are up to date",
				"simulated dconf update failure",
			},
			wantNotUpToDateDatabases: []string{"machine"},
		},
		{
			name:       "Recompiled machine database with equal source timestamp is accepted",
			isComputer: true,
			setup: func(t *testing.T, dconfDir string) {
				t.Helper()

				dbPath := filepath.Join(dconfDir, "db", "machine")
				require.NoError(t, os.MkdirAll(filepath.Dir(dbPath), 0750))
				require.NoError(t, os.WriteFile(dbPath, []byte("old compiled database"), 0600))
				require.NoError(t, os.Chtimes(dbPath, time.Unix(1, 0), time.Unix(1, 0)))
			},
			updater: recompiledMachineDconfUpdateWithEqualTimestamp,
			wantWarningContain: []string{
				"dconf update failed, but ADSys-managed databases were compiled or are up to date",
				"simulated dconf update failure",
			},
			wantNotUpToDateDatabases: []string{"machine"},
		},
		{
			name:       "Replaced machine database with unchanged timestamp is accepted",
			isComputer: true,
			setup: func(t *testing.T, dconfDir string) {
				t.Helper()

				dbPath := filepath.Join(dconfDir, "db", "machine")
				require.NoError(t, os.MkdirAll(filepath.Dir(dbPath), 0750))
				require.NoError(t, os.WriteFile(dbPath, []byte("old compiled database"), 0600))
				require.NoError(t, os.Chtimes(dbPath, time.Unix(1, 0), time.Unix(1, 0)))
			},
			updater: recompiledMachineDconfUpdateWithUnchangedTimestamp,
			wantWarningContain: []string{
				"dconf update failed, but ADSys-managed databases were compiled or are up to date",
				"simulated dconf update failure",
			},
			wantNotUpToDateDatabases: []string{"machine"},
		},
		{
			name: "Unrelated invalid database does not block compiled ADSys databases",
			setup: func(t *testing.T, dconfDir string) {
				t.Helper()

				machineLocks := filepath.Join(dconfDir, "db", "machine.d", "locks")
				require.NoError(t, os.MkdirAll(machineLocks, 0750))
				require.NoError(t, os.WriteFile(filepath.Join(machineLocks, "adsys"), nil, 0600))

				unrelatedDB := filepath.Join(dconfDir, "db", "local.d")
				require.NoError(t, os.MkdirAll(unrelatedDB, 0750))
				require.NoError(t, os.WriteFile(filepath.Join(unrelatedDB, "broken"), []byte("not a valid keyfile\n"), 0600))
			},
			wantWarningContain: []string{
				"dconf update failed, but ADSys-managed databases were compiled or are up to date",
				"local.d: broken",
			},
			wantFreshDatabases: []string{"machine", "ubuntu"},
		},
		{
			name:          "Missing dconf executable returns an error",
			isComputer:    true,
			updater:       unavailableDconfUpdate,
			wantExecError: true,
			wantErrorContains: []string{
				"dconf update failed",
				"executable file not found",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs.Reset()
			dconfDir := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, dconfDir)
			}

			manager := newWithDconfDirAndProfileDataDirs(dconfDir, []string{})
			manager.dconfUpdater = tc.updater
			err := manager.ApplyPolicy(context.Background(), "ubuntu", tc.isComputer, nil)

			if len(tc.wantErrorContains) > 0 {
				require.Error(t, err)
				for _, want := range tc.wantErrorContains {
					assert.Contains(t, err.Error(), want)
				}
				if tc.wantExitError {
					var exitErr *exec.ExitError
					require.ErrorAs(t, err, &exitErr)
				}
				if tc.wantExecError {
					var execErr *exec.Error
					require.ErrorAs(t, err, &execErr)
					require.Equal(t, "dconf", execErr.Name)
				}
				return
			}

			require.NoError(t, err)
			for _, want := range tc.wantWarningContain {
				assert.Contains(t, logs.String(), want)
			}
			for _, dbName := range tc.wantFreshDatabases {
				assert.True(t, dconfDatabaseIsUpToDate(filepath.Join(dconfDir, "db", dbName)),
					"%s database should have been compiled and current", dbName)
			}
			for _, dbName := range tc.wantNotUpToDateDatabases {
				assert.False(t, dconfDatabaseIsUpToDate(filepath.Join(dconfDir, "db", dbName)),
					"%s database should have an equal source timestamp", dbName)
			}
		})
	}
}

func failedDconfUpdate(string) ([]byte, error) {
	return exec.Command("/bin/sh", "-c", "printf 'simulated dconf update failure'; exit 1").CombinedOutput()
}

func recompiledMachineDconfUpdateWithEqualTimestamp(dbDir string) ([]byte, error) {
	dbPath := filepath.Join(dbDir, "machine")
	keyfilePath := filepath.Join(dbDir, "machine.d", "adsys")
	keyfileInfo, err := os.Stat(keyfilePath)
	if err != nil {
		return nil, err
	}

	temporaryDBPath := dbPath + ".new"
	if err := os.WriteFile(temporaryDBPath, []byte("compiled during update"), 0600); err != nil {
		return nil, err
	}
	if err := os.Chtimes(temporaryDBPath, keyfileInfo.ModTime(), keyfileInfo.ModTime()); err != nil {
		return nil, err
	}
	if err := os.Rename(temporaryDBPath, dbPath); err != nil {
		return nil, err
	}

	return failedDconfUpdate(dbDir)
}

func recompiledMachineDconfUpdateWithUnchangedTimestamp(dbDir string) ([]byte, error) {
	dbPath := filepath.Join(dbDir, "machine")
	dbInfo, err := os.Stat(dbPath)
	if err != nil {
		return nil, err
	}

	keyfilePath := filepath.Join(dbDir, "machine.d", "adsys")
	if err := os.Chtimes(keyfilePath, dbInfo.ModTime(), dbInfo.ModTime()); err != nil {
		return nil, err
	}

	temporaryDBPath := dbPath + ".new"
	if err := os.WriteFile(temporaryDBPath, []byte("compiled during update"), 0600); err != nil {
		return nil, err
	}
	if err := os.Chtimes(temporaryDBPath, dbInfo.ModTime(), dbInfo.ModTime()); err != nil {
		return nil, err
	}
	if err := os.Rename(temporaryDBPath, dbPath); err != nil {
		return nil, err
	}

	return failedDconfUpdate(dbDir)
}

func unavailableDconfUpdate(string) ([]byte, error) {
	return nil, &exec.Error{Name: "dconf", Err: exec.ErrNotFound}
}

func createDconfDatabaseFiles(t *testing.T, dbPath string) {
	t.Helper()

	keyfilesDir := dbPath + ".d"
	require.NoError(t, os.MkdirAll(filepath.Join(keyfilesDir, "locks"), 0750))
	require.NoError(t, os.MkdirAll(filepath.Dir(dbPath), 0750))
	require.NoError(t, os.WriteFile(dbPath, []byte("compiled"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(keyfilesDir, "adsys"), []byte("[org/example]\nkey='value'\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(keyfilesDir, "locks", "adsys"), []byte("/org/example/key\n"), 0600))
}

func setDconfDatabaseTimes(t *testing.T, dbPath string, databaseTime, keyfilesDirTime, keyfileTime, locksDirTime, lockFileTime time.Time) {
	t.Helper()

	setDconfTestMtime(t, dbPath, databaseTime)
	setDconfTestMtime(t, dbPath+".d", keyfilesDirTime)
	setDconfTestMtime(t, filepath.Join(dbPath+".d", "adsys"), keyfileTime)
	setDconfTestMtime(t, filepath.Join(dbPath+".d", "locks"), locksDirTime)
	setDconfTestMtime(t, filepath.Join(dbPath+".d", "locks", "adsys"), lockFileTime)
}

func setDconfTestMtime(t *testing.T, path string, modified time.Time) {
	t.Helper()
	require.NoError(t, os.Chtimes(path, modified, modified))
}
