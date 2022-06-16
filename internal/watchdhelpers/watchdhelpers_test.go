package watchdhelpers_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/watchdhelpers"
	"gopkg.in/yaml.v2"
)

var update bool

func TestGetConfigFileFromArgs(t *testing.T) {
	tests := map[string]struct {
		args string

		want    string
		wantErr bool
	}{
		"empty args":                        {wantErr: true},
		"no config argument":                {args: "adwatchd.exe", wantErr: true},
		"short config argument":             {args: `adwatchd.exe -c C:\path\to\adwatchd.yml`, want: `C:\path\to\adwatchd.yml`},
		"short config argument with quotes": {args: `adwatchd.exe -c "C:\path\to\adwatchd.yml"`, want: `C:\path\to\adwatchd.yml`},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			got, err := watchdhelpers.GetConfigFileFromArgs(tc.args)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, got)
		})
	}
}

func TestGetDirsFromConfigFile(t *testing.T) {
	tests := map[string]struct {
		emptyConfig bool
		noConfig    bool
		noDirs      bool
		badDirs     bool

		wantDirs []string
	}{
		"no config file":              {noConfig: true},
		"empty config file":           {emptyConfig: true},
		"no dirs in config file":      {noDirs: true},
		"config dirs is not an array": {badDirs: true},
		"config dirs is an array":     {wantDirs: []string{"/path/to/dir1", "/path/to/dir2"}},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			var data []byte
			var err error

			goldPath := filepath.Join("testdata", "golden", strings.Replace(name, " ", "_", -1))
			if update {
				appConfig := watchdhelpers.AppConfig{Dirs: tc.wantDirs}

				// Handle error cases
				if tc.noConfig {
					// no config file
				} else if tc.emptyConfig {
					_, err = os.Create(goldPath)
					require.NoError(t, err, "failed to create empty config file")
				} else if tc.noDirs {
					appConfig.Dirs = nil
					data, err = yaml.Marshal(&appConfig)
					require.NoError(t, err, "failed to marshal config")
					err = os.WriteFile(goldPath, data, 0600)
					require.NoError(t, err, "failed to write config")
				} else if tc.badDirs {
					err = os.WriteFile(goldPath, []byte(`- dirs: "testdir"`), 0600)
					require.NoError(t, err, "failed to write config")
				} else {
					// Normal case
					data, err = yaml.Marshal(&appConfig)
					require.NoError(t, err, "failed to marshal config")
					err = os.WriteFile(goldPath, data, 0600)
					require.NoError(t, err, "failed to write config")
				}
			}
			got := watchdhelpers.GetDirsFromConfigFile(goldPath)
			require.ElementsMatch(t, tc.wantDirs, got)
		})
	}
}

func TestFilterAbsentDirs(t *testing.T) {
	tests := map[string]struct {
		inputDirs    []string
		existingDirs []string

		wantDirs []string
	}{
		"no existing dirs":   {inputDirs: []string{"dir1", "dir2"}},
		"some existing dirs": {inputDirs: []string{"dir1", "dir2"}, existingDirs: []string{"dir1"}, wantDirs: []string{"dir1"}},
		"all existing dirs":  {inputDirs: []string{"dir1", "dir2"}, existingDirs: []string{"dir1", "dir2"}, wantDirs: []string{"dir1", "dir2"}},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			chdirToTempdir(t)
			for _, dir := range tc.existingDirs {
				require.NoError(t, os.MkdirAll(dir, 0750), "failed to create existing dirs")
			}
			got := watchdhelpers.FilterAbsentDirs(tc.inputDirs)
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
		"with empty dirs":  {wantErr: true},
		"with absent dirs": {dirs: []string{"dir1", "dir2"}, absentDirs: true, wantErr: true},

		"with relative config path": {dirs: []string{"dir1", "dir2"}},
		"with nested config path":   {dirs: []string{"dir1", "dir2"}, nestedConfigPath: true},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			goldPath, err := filepath.Abs(filepath.Join("testdata", "golden", strings.Replace(name, " ", "_", -1)))
			require.NoError(t, err, "failed to get absolute path")

			chdirToTempdir(t)

			var data []byte

			if !tc.absentDirs {
				for _, dir := range tc.dirs {
					require.NoError(t, os.MkdirAll(dir, 0750), "failed to create dirs")
				}
			}

			if update {
				appConfig := watchdhelpers.AppConfig{Dirs: tc.dirs}

				// If we want an error, we don't need to write the config file
				if !tc.wantErr {
					data, err = yaml.Marshal(&appConfig)
					require.NoError(t, err, "failed to marshal config")

					err = os.WriteFile(goldPath, data, 0600)
					require.NoError(t, err, "failed to write config")
				}
			}

			configPath := "adwatchd.yml"
			if tc.nestedConfigPath {
				configPath = filepath.Join("path", "to", "adwatchd.yml")
			}

			error := watchdhelpers.WriteConfig(configPath, tc.dirs)
			if tc.wantErr {
				require.Error(t, error, "expected error")
			} else {
				require.NoError(t, error, "unexpected error")

				got := watchdhelpers.GetDirsFromConfigFile(goldPath)
				require.ElementsMatch(t, tc.dirs, got)
			}
		})
	}
}

func chdirToTempdir(t *testing.T) string {
	t.Helper()

	orig, err := os.Getwd()
	require.NoError(t, err, "Setup: can't get current directory")

	dir := t.TempDir()
	err = os.Chdir(dir)
	require.NoError(t, err, "Setup: can't change current directory")
	t.Cleanup(func() {
		err := os.Chdir(orig)
		require.NoError(t, err, "Teardown: can't restore current directory")
	})
	return dir
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}
