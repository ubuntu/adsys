package adwatchd_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adwatchd/commands"
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
			// Parallelization is not supported on Windows due to Service
			// Control Manager reasons.
			if runtime.GOOS != "windows" {
				t.Parallel()
			}

			// Skip Windows-only tests if requested
			if runtime.GOOS != "windows" && tc.skipUnlessWindows {
				t.Skip()
			}

			var err error

			watchDir := t.TempDir()
			configPath := generateConfig(t, -1, watchDir)

			// Give each test a different service name so we can parallelize
			svcName := strings.ReplaceAll(name, " ", "_")
			app := commands.New(commands.WithServiceName(fmt.Sprintf("adwatchd-test-%s", svcName)))

			t.Cleanup(func() {
				uninstallService(t, configPath, app)
			})

			installService(t, configPath, app)

			// Begin with a stopped state
			changeAppArgs(t, app, configPath, "service", "stop")
			err = app.Run()
			require.NoError(t, err, "Setup: Stopping the service failed but shouldn't")

			if tc.invalidDir {
				os.RemoveAll(watchDir)
			}
			for index, state := range tc.sequence {
				changeAppArgs(t, app, configPath, "service", state)
				err := app.Run()
				if slices.Contains(tc.wantErrAt, index) {
					require.Error(t, err, fmt.Sprintf("%s should have failed but hasn't", state))
				} else {
					require.NoError(t, err, fmt.Sprintf("%s failed but shouldn't", state))
				}
				if tc.wantStopped {
					out := getStatus(t, app)
					require.Contains(t, out, "stopped", "Service should be stopped")
				}
			}

		})
	}
}
func TestInstall(t *testing.T) {
	// Parallelization is not supported on Windows due to Service
	// Control Manager reasons.
	if runtime.GOOS != "windows" {
		t.Parallel()
	}

	watchedDir := t.TempDir()

	app := commands.New()
	installService(t, generateConfig(t, -1, watchedDir), app)

	t.Cleanup(func() {
		uninstallService(t, generateConfig(t, -1, watchedDir), app)
	})

	out := getStatus(t, app)
	require.Contains(t, out, "running", "Newly installed service should be running")
}

func TestUpdateGPT(t *testing.T) {
	// Parallelization is not supported on Windows due to Service
	// Control Manager reasons.
	if runtime.GOOS != "windows" {
		t.Parallel()
	}

	watchedDir := t.TempDir()
	configPath := generateConfig(t, -1, watchedDir)

	app := commands.New(commands.WithServiceName("adwatchd-test-update-gpt"))
	t.Cleanup(func() {
		uninstallService(t, configPath, app)
	})

	installService(t, configPath, app)

	// Wait for service to be running
	time.Sleep(time.Second)

	// Write to some file
	err := os.WriteFile(filepath.Join(watchedDir, "new_file"), []byte("new content"), 0644)
	require.NoError(t, err, "Can't write to file")

	// Give time for the writes to be picked up
	time.Sleep(time.Millisecond * 100)

	// Stop the service to trigger the GPT update
	changeAppArgs(t, app, configPath, "service", "stop")
	err = app.Run()
	require.NoError(t, err, "Setup: Stopping the service failed but shouldn't")

	cfg, err := ini.Load(filepath.Join(watchedDir, "gpt.ini"))
	require.NoError(t, err, "Can't load GPT.ini")

	v, err := cfg.Section("General").Key("Version").Int()
	require.NoError(t, err, "Can't get GPT.ini version as an integer")

	assert.Equal(t, 1, v, "GPT.ini version is not equal to the expected one")
}

func TestServiceStatusContainsCorrectDirs(t *testing.T) {
	// Implementation is Windows-specific and there's really no point in
	// implementing a Linux variant as well.
	if runtime.GOOS != "windows" {
		t.Skip("This test is Windows-only")
	}

	firstDir, secondDir := t.TempDir(), t.TempDir()
	configPath := generateConfig(t, -1, firstDir, secondDir)

	app := commands.New(commands.WithServiceName("adwatchd-test-service-status-contains-correct-dirs"))
	t.Cleanup(func() {
		uninstallService(t, configPath, app)
	})

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
