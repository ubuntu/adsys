package adwatchd_test

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adwatchd/commands"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestRunFailsWhenServiceIsRunning(t *testing.T) {
	var err error
	watchDir := t.TempDir()
	configPath := generateConfig(t, -1, watchDir)

	app := commands.New(commands.WithServiceName(fmt.Sprintf("adwatchd-test-%s", t.Name())))

	installService(t, configPath, app)

	changeAppArgs(t, app, configPath, "run")
	err = app.Run()
	require.ErrorContains(t, err, "another instance of the adwatchd service is already running", "Running second instance should fail")
}

func TestRunWithForceWhenServiceIsRunning(t *testing.T) {
	watchDir := t.TempDir()
	configPath := generateConfig(t, -1, watchDir)

	app := commands.New(commands.WithServiceName(fmt.Sprintf("adwatchd-test-%s", t.Name())))

	installService(t, configPath, app)

	changeAppArgs(t, app, configPath, "run", "--force")
	done := make(chan struct{})
	var err, appErr error
	go func() {
		defer close(done)
		appErr = app.Run()
	}()
	app.WaitReady()

	err = app.Quit(syscall.SIGTERM)
	require.NoError(t, err, "Quitting should succeed")
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		// FIXME: fix quitting on windows
		if runtime.GOOS != "windows" {
			t.Fatal("run hasn't exited quickly enough")
		}
	}
	require.NoError(t, appErr, "App should exit without error")
}

func TestRunWithNoDirs(t *testing.T) {
	t.Parallel()

	app := commands.New()
	changeAppArgs(t, app, "", "run", "--force")
	err := app.Run()
	require.ErrorContains(t, err, "needs at least one directory", "Run with no dirs should fail")
}

func TestRunReactsToConfigUpdates(t *testing.T) {
	var err, appErr error
	watchDir := t.TempDir()
	newWatchDir := t.TempDir()

	configPath := generateConfig(t, -1, watchDir)
	newConfigPath := generateConfig(t, -1, newWatchDir)
	nonExistentConfigPath := generateConfig(t, 3, "non-existent-dir")

	app := commands.New()

	changeAppArgs(t, app, configPath, "run", "--force")
	done := make(chan struct{})
	go func() {
		defer close(done)
		appErr = app.Run()
	}()
	app.WaitReady()

	// Replace the config file to trigger reload
	testutils.Copy(t, newConfigPath, configPath)

	// Give time for the watcher to reload
	time.Sleep(time.Millisecond * 100)

	require.EqualValues(t, []string{newWatchDir}, app.Dirs(), "Watcher should have updated dirs")

	// Replace the config file to trigger reload
	testutils.Copy(t, nonExistentConfigPath, configPath)

	// Give time for the watcher to reload
	time.Sleep(time.Millisecond * 100)

	// Verbosity should change, but dirs should not
	require.EqualValues(t, []string{newWatchDir}, app.Dirs(), "Watcher should not be updated with non-existent directory")
	require.Equal(t, 3, app.Verbosity(), "Watcher should have updated verbosity")

	err = app.Quit(syscall.SIGTERM)
	require.NoError(t, err, "Quitting should succeed")
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		// FIXME: fix quitting on windows
		if runtime.GOOS != "windows" {
			t.Fatal("run hasn't exited quickly enough")
		}
	}
	require.NoError(t, appErr, "App should exit without error")
}
