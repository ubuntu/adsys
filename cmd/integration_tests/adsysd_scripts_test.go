package adsys_test

import (
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

		wantDirRemoved bool
		wantErr        bool
	}{
		"one script":                      {orderFile: "simple"},
		"multiple scripts":                {orderFile: "multiple"},
		"multiple scripts with subfolder": {orderFile: "multiple-subfolder"},

		"logoff cleans up scripts and order":           {orderFile: "logoff", wantDirRemoved: true},
		"shutdown machine cleans up scripts and order": {orderFile: "shutdown", scriptObjectName: "machine", wantDirRemoved: true},
		"order file is missing but allowed":            {orderFile: "missing", args: []string{"--allow-order-missing"}},
		"one missing script is allowed":                {orderFile: "script-missing"},
		"failing script is allowed":                    {orderFile: "script-failing"},

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

			_, err = os.Stat(scriptRunBaseDir)
			if tc.wantDirRemoved {
				require.True(t, os.IsNotExist(err), "RunScripts should have removed user/machine scripts dir but didn't")
			} else {
				require.NoError(t, err, "RunScripts should have kept scripts directory intact")
			}

			// Get and compare oracle file to check order
			src := filepath.Join(p, "golden")
			testutils.CompareTreesWithFiltering(t, src, filepath.Join("testdata", "RunScripts", "golden", name), update)
		})
	}
}
