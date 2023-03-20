package watchd_test

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	watchdconfig "github.com/ubuntu/adsys/internal/config/watchd"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestConfigFileFromArgs(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		args string

		want    string
		wantErr bool
	}{
		"Short config argument":             {args: `adwatchd.exe -c C:\path\to\adwatchd.yaml`, want: `C:\path\to\adwatchd.yaml`},
		"Short config argument with quotes": {args: `adwatchd.exe -c "C:\path\to\adwatchd.yaml"`, want: `C:\path\to\adwatchd.yaml`},

		"Error on empty args":                    {wantErr: true},
		"Error on no config argument":            {args: "adwatchd.exe", wantErr: true},
		"Error on config argument with no value": {args: "adwatchd.exe -c ", wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := watchdconfig.ConfigFileFromArgs(tc.args)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestDirsFromConfigFile(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		dirsInConfig string
		noConfig     bool

		wantDirs []string
	}{
		"No config file":              {noConfig: true},
		"Empty config file":           {dirsInConfig: ""},
		"No dirs in config file":      {dirsInConfig: "dirs:\n"},
		"Config dirs is not an array": {dirsInConfig: "dirs: testdir"},
		"Config dirs is an array": {
			dirsInConfig: "dirs:\n  - /path/to/dir1\n  - /path/to/dir2",
			wantDirs:     []string{"/path/to/dir1", "/path/to/dir2"},
		},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			configPath := filepath.Join(t.TempDir(), strings.ReplaceAll(name, " ", "_"))
			if !tc.noConfig {
				err := os.WriteFile(configPath, []byte(tc.dirsInConfig), 0600)
				require.NoError(t, err, "Setup: failed to write config file")
			}

			got := watchdconfig.DirsFromConfigFile(context.Background(), configPath)
			require.ElementsMatch(t, tc.wantDirs, got)
		})
	}
}

func TestWriteConfig(t *testing.T) {
	tests := map[string]struct {
		dirs             []string
		useDefaultConfig bool

		nestedConfigPath bool
		absentDirs       bool

		wantErr bool
	}{
		"With relative config path": {dirs: []string{"dir1", "dir2"}},
		"With nested config path":   {dirs: []string{"dir1", "dir2"}, nestedConfigPath: true},

		"Error on empty dirs":  {wantErr: true},
		"Error on absent dirs": {dirs: []string{"dir1", "dir2"}, absentDirs: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			goldPath, err := filepath.Abs(testutils.GoldenPath(t))
			require.NoError(t, err, "failed to get absolute path")

			tmpdir := t.TempDir()
			testutils.Chdir(t, tmpdir)

			if !tc.absentDirs {
				for _, dir := range tc.dirs {
					require.NoError(t, os.MkdirAll(dir, 0750), "failed to create dirs")
				}
			}

			configPath := "adwatchd.yaml"
			if tc.nestedConfigPath {
				configPath = filepath.Join("path", "to", "adwatchd.yaml")
			}

			err = watchdconfig.WriteConfig(configPath, tc.dirs)
			if tc.wantErr {
				require.Error(t, err, "expected writing config to fail")
				return
			}
			require.NoError(t, err, "didn't expect writing config to fail")

			if testutils.Update() {
				err := os.MkdirAll(filepath.Dir(goldPath), 0750)
				require.NoError(t, err, "Setup: Failed to create path to store the golden files")
				testutils.Copy(t, configPath, goldPath)
			}

			got := watchdconfig.DirsFromConfigFile(context.Background(), goldPath)
			require.ElementsMatch(t, tc.dirs, got)
		})
	}
}

func TestMain(m *testing.M) {
	testutils.InstallUpdateFlag()
	flag.Parse()

	m.Run()
}
