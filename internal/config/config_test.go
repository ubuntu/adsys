package config_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestSetVerboseMode(t *testing.T) {
	msgs := map[string]string{
		"debug":   "Debug msg",
		"info":    "Info msg",
		"warning": "Warning msg",
		"error":   "Error msg",
	}

	tests := map[string]struct {
		level int

		wantOut    []string
		wantCaller bool
	}{
		"Default level is warning":    {level: 0, wantOut: []string{"warning", "error"}},
		"1 is for info":               {level: 1, wantOut: []string{"info", "warning", "error"}},
		"2 is for debug":              {level: 2, wantOut: []string{"debug", "info", "warning", "error"}},
		"3 is debug printing callers": {level: 3, wantOut: []string{"debug", "info", "warning", "error"}, wantCaller: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			// capture log output (set to stderr, but captured when loading logrus)
			r, w, err := os.Pipe()
			require.NoError(t, err, "Setup: pipe shouldn’t fail")
			orig := logrus.StandardLogger().Out
			logrus.StandardLogger().SetOutput(w)
			defer logrus.StandardLogger().SetOutput(orig)

			config.SetVerboseMode(tc.level)

			logrus.Debug(msgs["debug"])
			logrus.Info(msgs["info"])
			logrus.Warning(msgs["warning"])
			logrus.Error(msgs["error"])

			w.Close()
			var out bytes.Buffer
			_, err = io.Copy(&out, r)
			require.NoError(t, err, "Couldn’t copy stderr to buffer")

			dontWantMsgs := make(map[string]string)
			for k, v := range msgs {
				dontWantMsgs[k] = v
			}
			// Messages we want in
			for _, levelWanted := range tc.wantOut {
				assert.Contains(t, out.String(), msgs[levelWanted], "Should be in logs")
				if tc.wantCaller {
					assert.Contains(t, out.String(), "/config_test.TestSetVerboseMode.func1", "Caller is printed in logs")
				} else {
					assert.NotContains(t, out.String(), "/config_test.TestSetVerboseMode.func1", "Caller is not printed in logs")
				}
				delete(dontWantMsgs, levelWanted)
			}
			// Messages we don’t want
			for _, msg := range dontWantMsgs {
				assert.NotContains(t, out.String(), msg, "Should not be in logs")
			}
		})
	}
}

func TestInit(t *testing.T) {
	tests := map[string]struct {
		withValueFlagSet   bool
		noVerboseFlag      bool
		noConfigFlag       bool
		withConfigFlagSet  string
		withConfigEnv      bool
		withConfigInExeDir bool
		configFileContent  string
		notInConfigDir     bool
		changeConfigWith   string

		subcommand             bool
		configFlagOnSubcommand bool

		errFromCallbackOn int

		want               string
		wantCallbackCalled int
		wantErr            bool
	}{
		"Load configuration, no file, no flag, no env": {wantCallbackCalled: 1},

		// Configuration file
		"Load configuration with file": {
			configFileContent: "value: filecontentvalue",
			want:              "filecontentvalue", wantCallbackCalled: 1,
		},
		"Load configuration from executable dir": {
			configFileContent:  "value: filecontentvalue",
			withConfigInExeDir: true,
			notInConfigDir:     true,
			want:               "filecontentvalue", wantCallbackCalled: 1,
		},
		"No config flag set before Init is call is ignored": {
			noConfigFlag:       true,
			wantCallbackCalled: 1,
		},
		"Empty configuration file is supported": {
			configFileContent:  "-",
			wantCallbackCalled: 1,
		},

		// Other configuration options
		"Configuration flag, not in config dir": {
			withConfigFlagSet: "custom.yaml", notInConfigDir: true,
			want: "customconfigvalue", wantCallbackCalled: 1,
		},
		"Configuration flag on parent, not in config dir, init on subcommand": {
			withConfigFlagSet: "custom.yaml", notInConfigDir: true, subcommand: true,
			want: "customconfigvalue", wantCallbackCalled: 1,
		},
		"Configuration flag on subcommand, not in config dir, init on subcommand": {
			withConfigFlagSet: "custom.yaml", notInConfigDir: true, subcommand: true, configFlagOnSubcommand: true,
			want: "customconfigvalue", wantCallbackCalled: 1,
		},
		"Flag is supported": {
			withValueFlagSet: true,
			want:             "flagvalue", wantCallbackCalled: 1},
		"Environment is supported": {
			withConfigEnv: true,
			want:          "envvalue", wantCallbackCalled: 1,
		},

		// Configuration changes support
		"Configuration changed": {
			configFileContent: "value: filecontentvalue", changeConfigWith: "value: filecontentvaluerefreshed",
			want: "filecontentvaluerefreshed", wantCallbackCalled: 2,
		},
		"Configuration file created after Init() is not taken into account": {
			changeConfigWith:   "value: filecontentvaluerefreshed",
			wantCallbackCalled: 1,
		},
		"Callback in error on refresh only prints warning": {
			configFileContent: "value: filecontentvalue", changeConfigWith: "value: filecontentvaluerefreshed",
			errFromCallbackOn: 2,
			want:              "filecontentvalue", wantCallbackCalled: 2,
		},

		// Precedence tests
		"Flag has precedence over env": {
			withValueFlagSet: true, withConfigEnv: true,
			want: "flagvalue", wantCallbackCalled: 1,
		},
		"Env has precedence over configuration": {
			withConfigEnv: true, configFileContent: "value: filecontentvalue",
			want: "envvalue", wantCallbackCalled: 1,
		},
		"Configuration flag has precedence over local file": {
			withConfigFlagSet: "custom.yaml", notInConfigDir: true,
			want: "customconfigvalue", wantCallbackCalled: 1,
		},

		// Error cases
		"Error on no verbose flag set before Init is call": {noVerboseFlag: true, wantErr: true},
		"Error on invalid configuration file":              {configFileContent: "invalidcontent", want: "filecontentvalue", wantErr: true},
		"Error on callback returning error on first call":  {errFromCallbackOn: 1, wantErr: true},
		"Error on config flag points to unexisting path":   {withConfigFlagSet: "DELETED.yaml", wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			configDir := t.TempDir()
			prefix := "adsys_config_test"

			if tc.withConfigInExeDir {
				exePath, err := os.Executable()
				require.NoError(t, err, "Setup: can't get executable path")
				configDir = filepath.Dir(exePath)

				t.Cleanup(func() {
					os.Remove(filepath.Join(configDir, prefix+".yaml"))
					syscall.Sync()
				})
			}

			if !tc.notInConfigDir {
				chDir(t, configDir)
			}

			// Setup config to read
			vip := viper.New()
			rootCmd := cobra.Command{}
			rootCmd.PersistentFlags().String("value", "", "value flag")
			err := vip.BindPFlag("value", rootCmd.PersistentFlags().Lookup("value"))
			require.NoError(t, err, "Setup: can't bind value flag to viper")

			if tc.withValueFlagSet {
				err := rootCmd.PersistentFlags().Set("value", "flagvalue")
				require.NoError(t, err, "Setup: can’t set value flag")
			}

			if !tc.noVerboseFlag {
				rootCmd.PersistentFlags().CountP("verbose", "v", "verbose flag")
			}

			if !tc.noConfigFlag && !tc.configFlagOnSubcommand {
				rootCmd.PersistentFlags().String("config", "", "config flag")
			}

			cmdFlags := rootCmd.PersistentFlags()
			cmd := rootCmd
			if tc.subcommand {
				subcmd := cobra.Command{}
				if tc.configFlagOnSubcommand {
					cmdFlags = subcmd.Flags()
					cmdFlags.String("config", "", "config flag")
				}
				rootCmd.AddCommand(&subcmd)
				cmd = subcmd
			}

			if tc.withConfigFlagSet != "" {
				p := filepath.Join(configDir, tc.withConfigFlagSet)
				if tc.withConfigFlagSet != "DELETED.yaml" {
					err = os.WriteFile(p, []byte("value: customconfigvalue"), 0600)
					require.NoError(t, err, "Setup: failed to write custom config file")
				}
				err := cmdFlags.Set("config", p)
				require.NoError(t, err, "Setup: can’t set config flag")
			}

			if tc.withConfigEnv {
				testutils.Setenv(t, strings.ToUpper(prefix)+"_VALUE", "envvalue")
			}

			if tc.configFileContent != "" {
				if tc.configFileContent == "-" {
					tc.configFileContent = ""
				}
				err = os.WriteFile(filepath.Join(configDir, prefix+".yaml"), []byte(tc.configFileContent), 0600)
				require.NoError(t, err, "Setup: failed to write initial config file")
			}

			result := struct {
				Value string
			}{}

			// Let’s force a sync to make sure the initial files are written on disk
			syscall.Sync()

			var phaseMu sync.Mutex
			callbackPhase := 1
			var callbackCalled int
			firstCallbackDone, secondCallbackDone := make(chan struct{}), make(chan struct{})
			err = config.Init(prefix, cmd, vip, func(refreshed bool) error {
				// inotify triggers on several times "randomly" so, we split the callback in phases to ensure
				// we don’t have delayed calls from the system

				phaseMu.Lock()
				phase := callbackPhase
				phaseMu.Unlock()

				if phase == 1 && callbackCalled != phase {
					defer func() { close(firstCallbackDone) }()
					require.False(t, refreshed, "First call to callback is an init")
				} else if phase == 2 && callbackCalled != phase {
					// Only close it on the secondary call, as the callback can be called more than this due to inotify
					defer func() { close(secondCallbackDone) }()
					require.True(t, refreshed, "Any following calls to callback are refresh")
				} else {
					return nil
				}

				callbackCalled = phase
				if callbackCalled == tc.errFromCallbackOn {
					return errors.New("Error from callback")
				}
				return vip.Unmarshal(&result)
			})
			if tc.wantErr {
				require.Error(t, err, "Init should have errored out")
				return
			}
			require.NoError(t, err, "Init should not have errored out")

			// First callback
			<-firstCallbackDone

			// Refresh config file
			if tc.changeConfigWith != "" {
				// Wait a little bit for consecutive inotify calls to be consumed before entering second phase.
				time.Sleep(2 * time.Second)
				phaseMu.Lock()
				callbackPhase = 2
				phaseMu.Unlock()

				err = os.WriteFile(filepath.Join(configDir, prefix+".yaml"), []byte(tc.changeConfigWith), 0600)
				require.NoError(t, err, "Setup: failed to write initial config file")
				// Let’s force a sync to make sure the file is written on disk
				syscall.Sync()
				select {
				case <-secondCallbackDone:
					if tc.wantCallbackCalled != 2 {
						t.Fatal("We shouldn’t have a secondary callback call when the configuration file was not created before Init()")
					}
				case <-time.After(2 * time.Second):
					if tc.wantCallbackCalled == 2 {
						t.Fatal("Secondary callback call for refresh has not happened while we had an initial configuration file on creation")
					}
				}
			}
			phaseMu.Lock()
			callbackPhase = 3
			phaseMu.Unlock()

			require.Equal(t, callbackCalled, tc.wantCallbackCalled, "Callback was called expected amount of times")
			require.EqualValues(t, tc.want, result.Value, "Expected config has been decoded")
		})
	}
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	type configType struct {
		Verbose int
		Socket  string
	}
	origConf := configType{
		Verbose: 42,
		Socket:  "/some/socket/path",
	}

	tests := map[string]struct {
		noConfig bool

		want    configType
		wantErr bool
	}{
		"Load configuration deserialize its": {want: origConf},
		"Empty configuration is supported":   {noConfig: true},

		// Error cases
		/*"Error on undecodable data to": {},*/
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Setup config to read
			vip := viper.New()
			if !tc.noConfig {
				vip.Set("Socket", origConf.Socket)
				vip.Set("Verbose", origConf.Verbose)
			}

			var got configType
			err := config.LoadConfig(&got, vip)
			if tc.wantErr {
				require.Error(t, err, "LoadConfig should have errored out")
				return
			}
			require.NoError(t, err, "LoadConfig should not have errored out")

			require.EqualValues(t, tc.want, got, "LoadConfig returns the expected configuration")
		})
	}
}

func chDir(t *testing.T, p string) {
	t.Helper()

	orig, err := os.Getwd()
	require.NoError(t, err, "Setup: can’t get current directory")

	err = os.Chdir(p)
	require.NoError(t, err, "Setup: can’t change current directory")
	t.Cleanup(func() {
		err := os.Chdir(orig)
		require.NoError(t, err, "Teardown: can’t restore current directory")
	})
}
