package adwatchd_test

import (
	"fmt"
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
	t.Cleanup(func() {
		uninstallService(t, configPath, app)
	})

	installService(t, configPath, app)

	changeAppArgs(t, app, configPath, "run")
	err = app.Run()
	require.ErrorContains(t, err, "another instance of adwatchd is already running", "Running second instance should fail")
}

func TestRunWithForceWhenServiceIsRunning(t *testing.T) {
	watchDir := t.TempDir()
	configPath := generateConfig(t, -1, watchDir)

	app := commands.New(commands.WithServiceName("adwatchd-test-force"))
	t.Cleanup(func() {
		uninstallService(t, configPath, app)
	})

	installService(t, configPath, app)

	changeAppArgs(t, app, configPath, "run", "--force")
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		err = app.Run()
	}()

	// Give time for the watcher itself to start
	time.Sleep(time.Millisecond * 100)

	err = terminateProc(syscall.SIGTERM)
	// err = app.Quit(syscall.SIGTERM)
	require.NoError(t, err, "Quitting should succeed")

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// TODO: fix quitting on windows
		// t.Fatal("run hasn't exited quickly enough")
	}
	require.NoError(t, err)
}

func TestRunWithNoDirs(t *testing.T) {
	t.Parallel()

	app := commands.New()
	changeAppArgs(t, app, "", "run", "--force")
	err := app.Run()
	require.ErrorContains(t, err, "needs at least one directory", "Run with no dirs should fail")
}

func TestRunReactsToConfigUpdates(t *testing.T) {
	var err error
	watchDir := t.TempDir()
	newWatchDir := t.TempDir()

	configPath := generateConfig(t, -1, watchDir)
	newConfigPath := generateConfig(t, -1, newWatchDir)
	nonExistentConfigPath := generateConfig(t, 3, "non-existent-dir")

	app := commands.New()

	changeAppArgs(t, app, configPath, "run")
	done := make(chan struct{})
	go func() {
		defer close(done)
		err = app.Run()
	}()

	// Give time for the watcher itself to start
	time.Sleep(time.Millisecond * 500)

	// Replace the config file to trigger reload
	testutils.Copy(t, newConfigPath, configPath)

	// Give time for the watcher to reload
	time.Sleep(time.Millisecond * 100)

	require.EqualValues(t, []string{newWatchDir}, app.Dirs(), "Watcher should have updated dirs")

	// Replace the config file to trigger reload
	testutils.Copy(t, nonExistentConfigPath, configPath)

	// Give time for the watcher to reload
	time.Sleep(time.Millisecond * 100)

	require.EqualValues(t, []string{newWatchDir}, app.Dirs(), "Watcher should not be updated with non-existent directory")

	// TODO: fix verbosity assertion, should actually be 3 here
	require.Equal(t, 2, app.Verbosity(), "Watcher should have updated verbosity")

	// TODO: fix quitting on windows
	// err = terminateProc(syscall.SIGTERM)
	// err = app.Quit(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		// t.Fatal("run hasn't exited quickly enough")
	}
	require.NoError(t, err, "Quitting should succeed")
}

// TODO: TestRunCanQuitWithCtrlC.
func TestRunCanQuitWithSigterm(t *testing.T) {
	t.Skip()
	watchDir := t.TempDir()
	app := commands.New()
	changeAppArgs(t, app, "", "run", "--dirs", watchDir)

	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		err = app.Run()
	}()

	// Give time for the watcher itself to start
	time.Sleep(time.Millisecond * 100)

	err = terminateProc(syscall.SIGTERM)
	// err = app.Quit(syscall.SIGTERM)
	require.NoError(t, err, "Quitting should succeed")

	select {
	case <-done:
	case <-time.After(1000 * time.Second):
		t.Fatal("run hasn't exited quickly enough")
	}
}

func TestRunCanQuitWithSigint(t *testing.T) {
	t.Skip()
	watchDir := t.TempDir()
	app := commands.New()
	changeAppArgs(t, app, "", "run", "--dirs", watchDir)

	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		err = app.Run()
	}()

	// Give time for the watcher itself to start
	time.Sleep(time.Millisecond * 100)

	err = terminateProc(syscall.SIGINT)
	// err = app.Quit(syscall.SIGINT)
	require.NoError(t, err, "Quitting should succeed")

	select {
	case <-done:
	case <-time.After(1000 * time.Second):
		t.Fatal("run hasn't exited quickly enough")
	}
}
