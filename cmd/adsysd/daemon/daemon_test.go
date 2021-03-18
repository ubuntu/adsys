package daemon_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
)

func TestAppHelp(t *testing.T) {
	a := daemon.New()

	defer changeArgs("adsysd", "--help")()
	err := a.Run()
	require.NoError(t, err, "Run should return no error")
}

func TestAppCompletion(t *testing.T) {
	a := daemon.New()

	defer changeArgs("adsysd", "completion")()
	err := a.Run()
	require.NoError(t, err, "Completion should not use socket and always be reachable")
}

func TestAppVersion(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn’t fail")

	a := daemon.New()

	defer changeArgs("adsysd", "version")()

	orig := os.Stdout
	os.Stdout = w

	a.Run()

	os.Stdout = orig
	w.Close()

	var out bytes.Buffer
	_, err = io.Copy(&out, r)
	require.NoError(t, err, "Couldn’t copy stdout to buffer")
	require.Equal(t, "adsysd\tdev\n", out.String(), "Version is printed")
}

func TestAppNoUsageError(t *testing.T) {
	a := daemon.New()

	defer changeArgs("adsysd", "completion")()
	a.Run()
	isUsageError := a.UsageError()
	require.False(t, isUsageError, "No usage error is reported as such")
}

func TestAppUsageError(t *testing.T) {
	a := daemon.New()

	defer changeArgs("adsys", "doesnotexist")()
	a.Run()
	isUsageError := a.UsageError()
	require.True(t, isUsageError, "Usage error is reported as such")
}

func TestAppCanQuitWhenExecute(t *testing.T) {
	a, wait := startDaemon(t)
	defer wait()

	a.Quit()
}

func TestAppCanQuitAfterExecute(t *testing.T) {
	os.Setenv("ADSYS_SERVICETIMEOUT", "1")
	defer func() {
		os.Unsetenv("ADSYS_SERVICETIMEOUT")
	}()
	a, wait := startDaemon(t)
	wait()
	a.Quit()
}

func TestAppCanQuitWithoutExecute(t *testing.T) {
	t.Skip("We need to initialize the daemon first, so this is not possible and will hang forever (ready not closed)")
	a := daemon.New()
	a.Quit()
}

func TestAppCanSigHupWhenExecute(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn’t fail")

	a, wait := startDaemon(t)

	defer wait()
	defer a.Quit()

	orig := os.Stdout
	os.Stdout = w

	a.Hup()

	os.Stdout = orig
	w.Close()

	var out bytes.Buffer
	_, err = io.Copy(&out, r)
	require.NoError(t, err, "Couldn’t copy stdout to buffer")
	require.NotEmpty(t, out.String(), "Stacktrace is printed")
}

func TestAppCanSigHupAfterExecute(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn’t fail")

	os.Setenv("ADSYS_SERVICETIMEOUT", "1")
	defer func() {
		os.Unsetenv("ADSYS_SERVICETIMEOUT")
	}()
	a, wait := startDaemon(t)
	wait()
	a.Quit()

	orig := os.Stdout
	os.Stdout = w

	a.Hup()

	os.Stdout = orig
	w.Close()

	var out bytes.Buffer
	_, err = io.Copy(&out, r)
	require.NoError(t, err, "Couldn’t copy stdout to buffer")
	require.NotEmpty(t, out.String(), "Stacktrace is printed")
}

func TestAppCanSigHupWithoutExecute(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn’t fail")

	a := daemon.New()

	orig := os.Stdout
	os.Stdout = w

	a.Hup()

	os.Stdout = orig
	w.Close()

	var out bytes.Buffer
	_, err = io.Copy(&out, r)
	require.NoError(t, err, "Couldn’t copy stdout to buffer")
	require.NotEmpty(t, out.String(), "Stacktrace is printed")
}

func TestAppTimeout(t *testing.T) {
	os.Setenv("ADSYS_SERVICETIMEOUT", "1")
	defer func() {
		os.Unsetenv("ADSYS_SERVICETIMEOUT")
	}()
	a, wait := startDaemon(t)

	done := make(chan struct{})
	go func() {
		wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		a.Quit()
		t.Error("Daemon hasn’t timeout after 2s as expected")
		// Let the daemon cleanup to proceed
		<-done
	}
}

func TestAppGetRootCmd(t *testing.T) {
	t.Parallel()

	a := daemon.New()
	require.NotNil(t, a.RootCmd(), "Returns root command")
}

// startDaemon prepares and start the daemon in the background. The done function should be called
// to wait for the daemon to stop
func startDaemon(t *testing.T) (app *daemon.App, done func()) {
	t.Helper()

	cleanup := prepareEnv(t)

	a := daemon.New()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := a.Run()
		require.NoError(t, err, "Run should exits without any error")
	}()

	return a, func() {
		wg.Wait()
		cleanup()
	}
}

// prepareEnv prepares adsys generic configuration with temporary socket and caches
// It returns a function to restore it
func prepareEnv(t *testing.T) func() {
	t.Helper()

	dir := t.TempDir()
	err := os.Setenv("ADSYS_SOCKET", filepath.Join(dir, "socket"))
	require.NoError(t, err, "Setup: can’t set env variable")
	err = os.Setenv("ADSYS_CACHE_DIR", filepath.Join(dir, "cache"))
	require.NoError(t, err, "Setup: can’t set env variable")
	err = os.Setenv("ADSYS_RUN_DIR", filepath.Join(dir, "run"))
	require.NoError(t, err, "Setup: can’t set env variable")
	err = os.Setenv("ADSYS_AD_SERVER", "ldap://adserver")
	require.NoError(t, err, "Setup: can’t set env variable")
	err = os.Setenv("ADSYS_AD_DOMAIN", "adserver.domain")
	require.NoError(t, err, "Setup: can’t set env variable")

	return func() {
		err := os.Unsetenv("ADSYS_SOCKET")
		require.NoError(t, err, "Teardown: can’t restore env variable")
		err = os.Unsetenv("ADSYS_CACHE_DIR")
		require.NoError(t, err, "Teardown: can’t restore env variable")
		err = os.Unsetenv("ADSYS_RUN_DIR")
		require.NoError(t, err, "Teardown: can’t restore env variable")
		err = os.Unsetenv("ADSYS_AD_SERVER")
		require.NoError(t, err, "Teardown: can’t restore env variable")
		err = os.Unsetenv("ADSYS_AD_DOMAIN")
		require.NoError(t, err, "Teardown: can’t restore env variable")
	}
}

// changeArgs allows changing command line arguments and return a function to return it
func changeArgs(args ...string) func() {
	orig := os.Args
	os.Args = args
	return func() { os.Args = orig }
}
