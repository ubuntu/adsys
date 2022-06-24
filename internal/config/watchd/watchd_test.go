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

var update bool

func TestConfigFileFromArgs(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		args string

		want    string
		wantErr bool
	}{
		"short config argument":             {args: `adwatchd.exe -c C:\path\to\adwatchd.yaml`, want: `C:\path\to\adwatchd.yaml`},
		"short config argument with quotes": {args: `adwatchd.exe -c "C:\path\to\adwatchd.yaml"`, want: `C:\path\to\adwatchd.yaml`},

		"empty args":                    {wantErr: true},
		"no config argument":            {args: "adwatchd.exe", wantErr: true},
		"config argument with no value": {args: "adwatchd.exe -c ", wantErr: true},
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
		"no config file":              {noConfig: true},
		"empty config file":           {dirsInConfig: ""},
		"no dirs in config file":      {dirsInConfig: "dirs:\n"},
		"config dirs is not an array": {dirsInConfig: "dirs: testdir"},
		"config dirs is an array": {
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
		"with relative config path": {dirs: []string{"dir1", "dir2"}},
		"with nested config path":   {dirs: []string{"dir1", "dir2"}, nestedConfigPath: true},

		"with empty dirs":  {wantErr: true},
		"with absent dirs": {dirs: []string{"dir1", "dir2"}, absentDirs: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			goldPath, err := filepath.Abs(filepath.Join("testdata", "golden", strings.ReplaceAll(name, " ", "_")))
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

			error := watchdconfig.WriteConfig(configPath, tc.dirs)
			if tc.wantErr {
				require.Error(t, error, "expected writing config to fail")
				return
			}
			require.NoError(t, error, "didn't expect writing config to fail")

			if update {
				testutils.Copy(t, configPath, goldPath)
			}

			got := watchdconfig.DirsFromConfigFile(context.Background(), goldPath)
			require.ElementsMatch(t, tc.dirs, got)
		})
	}
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
