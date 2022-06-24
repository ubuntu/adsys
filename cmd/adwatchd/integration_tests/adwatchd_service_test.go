package adwatchd_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adwatchd/commands"
	"github.com/ubuntu/adsys/internal/testutils"
	"golang.org/x/exp/slices"
	"gopkg.in/ini.v1"
)

func TestServiceStateChange(t *testing.T) {
	tests := map[string]struct {
		sequence   []string
		invalidDir bool

		skipUnlessWindows bool

		wantErrAt   []int
		wantStopped bool
	}{
		// From stopped state
		"stop multiple times": {sequence: []string{"stop"}},
		"start":               {sequence: []string{"start"}},
		"restart":             {sequence: []string{"restart"}},
		"uninstall":           {sequence: []string{"uninstall"}},
		"install":             {sequence: []string{"install"}, wantErrAt: []int{0}},

		// From started state
		// This should error on Windows but doesn't with systemd because of the auto-restart policy
		"start with a bad dir": {sequence: []string{"start"}, invalidDir: true, wantStopped: true, skipUnlessWindows: true},
		"start multiple times": {sequence: []string{"start", "start"}},
		"start and stop":       {sequence: []string{"start", "stop"}},
		"start and restart":    {sequence: []string{"start", "restart"}},
		"start and uninstall":  {sequence: []string{"start", "uninstall"}},

		// From uninstalled state
		"uninstall multiple times": {sequence: []string{"uninstall", "uninstall"}},
		"uninstall and install":    {sequence: []string{"uninstall", "install"}},
		"uninstall and start":      {sequence: []string{"uninstall", "start"}, wantErrAt: []int{1}},
		"uninstall and stop":       {sequence: []string{"uninstall", "stop"}, wantErrAt: []int{1}},
		"uninstall and restart":    {sequence: []string{"uninstall", "stop"}, wantErrAt: []int{1}},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			// Skip Windows-only tests if requested
			if runtime.GOOS != "windows" && tc.skipUnlessWindows {
				t.Skip()
			}

			var err error

			watchDir := t.TempDir()
			configPath := generateConfig(t, -1, watchDir)

			// Give each test a different service name for better tracking
			svcName := strings.ReplaceAll(name, " ", "_")
			app := commands.New(commands.WithServiceName(fmt.Sprintf("adwatchd-test-%s", svcName)))

			installService(t, configPath, app)
			time.Sleep(time.Second)

			// Begin with a stopped state
			changeAppArgs(t, app, "", "service", "stop")
			err = app.Run()
			require.NoError(t, err, "Setup: Stopping the service failed but shouldn't")

			if tc.invalidDir {
				os.RemoveAll(watchDir)
			}
			for index, state := range tc.sequence {
				if runtime.GOOS == "windows" {
					time.Sleep(time.Second)
				}

				var configPathArg string
				if state == "install" {
					configPathArg = configPath
				}
				changeAppArgs(t, app, configPathArg, "service", state)

				err := app.Run()
				if slices.Contains(tc.wantErrAt, index) {
					require.Error(t, err, fmt.Sprintf("%s should have failed but hasn't", state))
					return
				}
				require.NoError(t, err, fmt.Sprintf("%s failed but shouldn't", state))

				if tc.wantStopped {
					out := getStatus(t, app)
					require.Contains(t, out, "stopped", "Service should be stopped")
				}
			}
		})
	}
}
func TestInstall(t *testing.T) {
	watchedDir := t.TempDir()

	app := commands.New()
	installService(t, generateConfig(t, -1, watchedDir), app)

	out := getStatus(t, app)
	require.Contains(t, out, "running", "Newly installed service should be running")
}

func TestCreateAndUpdateGPT(t *testing.T) {
	// Parallelization is not supported on Windows due to Service
	// Control Manager reasons.
	if runtime.GOOS != "windows" {
		t.Parallel()
	}

	watchedDir := t.TempDir()
	configPath := generateConfig(t, -1, watchedDir)

	app := commands.New(commands.WithServiceName(fmt.Sprintf("adwatchd-test-%s", t.Name())))

	installService(t, configPath, app)

	// Wait for service to be running
	time.Sleep(time.Second)

	for i, state := range []string{"create", "update"} {
		expectedValue := i + 1

		if state == "update" {
			// Start the service if already installed
			changeAppArgs(t, app, "", "service", "start")
			err := app.Run()
			require.NoError(t, err, "Setup: Starting the service failed but shouldn't")

			// Wait for service to be running
			time.Sleep(time.Millisecond * 100)
		}

		// Write to some file
		err := os.WriteFile(filepath.Join(watchedDir, "new_file"), []byte("new content"), 0600)
		require.NoError(t, err, "Setup: Can't write to file")

		// Give time for the writes to be picked up
		testutils.WaitForWrites(t)

		// Stop the service to trigger GPT creation / update
		changeAppArgs(t, app, "", "service", "stop")
		err = app.Run()
		require.NoError(t, err, "Setup: Stopping the service failed but shouldn't")

		// Give time for the GPT creation / update to be processed
		testutils.WaitForWrites(t)

		cfg, err := ini.Load(filepath.Join(watchedDir, "GPT.INI"))
		require.NoError(t, err, "Can't load GPT.ini")

		v, err := cfg.Section("General").Key("Version").Int()
		require.NoError(t, err, "Can't get GPT.ini version as an integer")

		assert.Equal(t, expectedValue, v, "GPT.ini version is not equal to the expected one")
	}
}

func TestServiceStatusContainsCorrectDirs(t *testing.T) {
	// Implementation is Windows-specific and there's really no point in
	// implementing a Linux variant as well.
	if runtime.GOOS != "windows" {
		t.Skip("This test is Windows-only")
	}

	firstDir, secondDir := t.TempDir(), t.TempDir()
	configPath := generateConfig(t, -1, firstDir, secondDir)

	app := commands.New(commands.WithServiceName(fmt.Sprintf("adwatchd-test-%s", t.Name())))

	installService(t, configPath, app)

	// Wait for service to be running
	time.Sleep(time.Second)

	want := fmt.Sprintf(`Service status: running

Config file: %s
Watched directories: 
  - %s
  - %s
`, configPath, firstDir, secondDir)

	// Get actual status
	require.Equal(t, want, getStatus(t, app), "Service status doesn't match")
}

func TestServiceConfigFlagUsage(t *testing.T) {
	tests := map[string]struct {
		wantConfig bool
	}{
		// Subcommands not allowing a config flag
		"start":     {},
		"restart":   {},
		"uninstall": {},
		"status":    {},

		// Subcommands allowing a config flag
		"install": {wantConfig: true},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			r, w, err := os.Pipe()
			require.NoError(t, err, "Setup: pipe shouldn't fail")

			app := commands.New()

			changeAppArgs(t, app, "", "service", name, "-c", "badconf")

			err = app.Run()
			if tc.wantConfig {
				assert.ErrorContains(t, err, "invalid configuration file")
			} else {
				assert.ErrorContains(t, err, "unknown shorthand flag: 'c' in -c")
			}

			// Check the usage message
			changeAppArgs(t, app, "", "service", name, "--help")

			orig := os.Stdout
			os.Stdout = w

			err = app.Run()
			require.NoError(t, err, "Setup: running the app shouldn't fail")

			os.Stdout = orig
			w.Close()

			var out bytes.Buffer
			_, err = io.Copy(&out, r)
			require.NoError(t, err, "Couldn't copy stdout to buffer")

			if tc.wantConfig {
				assert.Contains(t, out.String(), "--config", "--config should be in the usage message")
			} else {
				assert.NotContains(t, out.String(), "--config", "--config should not be in the usage message")
			}
		})
	}
}
