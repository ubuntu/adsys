package adsys_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestAdsysdRunScripts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		orderFile        string
		args             []string
		notready         bool
		scriptObjectName string

		wantSessionFlagFileRemoved bool
		wantErr                    bool
	}{
		"one script":                      {orderFile: "simple"},
		"multiple scripts":                {orderFile: "multiple"},
		"multiple scripts with subfolder": {orderFile: "multiple-subfolder"},

		"logoff cleans up running flag":           {orderFile: "logoff", wantSessionFlagFileRemoved: true},
		"shutdown machine cleans up running flag": {orderFile: "shutdown", scriptObjectName: "machine", wantSessionFlagFileRemoved: true},
		"order file is missing but allowed":       {orderFile: "missing", args: []string{"--allow-order-missing"}},
		"one missing script is allowed":           {orderFile: "script-missing"},
		"failing script is allowed":               {orderFile: "script-failing"},

		"error on order file not existing": {orderFile: "missing", wantErr: true},
		"error on directory not ready":     {orderFile: "simple", notready: true, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := daemon.New()

			if tc.scriptObjectName == "" {
				tc.scriptObjectName = "users"
			}

			p := t.TempDir()
			scriptRunBaseDir := filepath.Join(p, tc.scriptObjectName)

			// Setup script directory
			testutils.Copy(t, "testdata/RunScripts/scripts", scriptRunBaseDir)

			if tc.notready {
				require.NoError(t, os.RemoveAll(filepath.Join(scriptRunBaseDir, ".ready")), "Setup: can't remove .ready flag file")
			}

			args := []string{"-vv", "runscripts", filepath.Join(scriptRunBaseDir, tc.orderFile)}
			if tc.args != nil {
				args = append(args, tc.args...)
			}
			changeAppArgs(t, d, "", args...)

			err := d.Run()

			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				// Client version is still printed
				return
			}
			require.NoError(t, err, "client should exit with no error")

			_, err = os.Stat(filepath.Join(scriptRunBaseDir, ".running"))
			if tc.wantSessionFlagFileRemoved {
				require.True(t, errors.Is(err, fs.ErrNotExist), "In session flag should have been removed from user/machine scripts dir but didn't")
			} else {
				require.Nil(t, err, "RunScripts should have added in session flag file but didn’t")
			}

			// Get and compare oracle file to check order
			src := filepath.Join(p, "golden")
			testutils.CompareTreesWithFiltering(t, src, filepath.Join("testdata", "RunScripts", "golden", name), update)
		})
	}
}
