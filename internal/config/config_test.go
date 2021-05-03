package config_test

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/config"
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
