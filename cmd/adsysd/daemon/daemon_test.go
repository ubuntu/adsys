package daemon_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
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
	require.True(t, strings.HasPrefix(out.String(), "adsysd\t"), "Start printing daemon name")
	version := strings.TrimSpace(strings.TrimPrefix(out.String(), "adsysd\t"))
	require.NotEmpty(t, version, "Version is printed")
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
	a, wait := startDaemon(t, true)
	defer wait()

	a.Quit()
}

func TestAppCanQuitAfterExecute(t *testing.T) {
	os.Setenv("ADSYS_SERVICETIMEOUT", "1")
	defer func() {
		os.Unsetenv("ADSYS_SERVICETIMEOUT")
	}()
	a, wait := startDaemon(t, true)
	wait()
	a.Quit()
}

func TestAppCanQuitWithoutExecute(t *testing.T) {
	t.Skip("We need to initialize the daemon first, so this is not possible and will hang forever (ready not closed)")
	a := daemon.New()
	a.Quit()
}

func TestAppRunFailsOnDaemonCreationAndQuit(t *testing.T) {
	// Trigger the error with a socket that cannot be created over an existing
	// directory
	prepareEnv(t)
	socket := os.Getenv("ADSYS_SOCKET")
	os.MkdirAll(socket, 0755)

	a := daemon.New()
	err := a.Run()
	require.Error(t, err, "Run should exit with an error")
	a.Quit()
}

func TestAppRunFailsOnServiceCreationAndQuit(t *testing.T) {
	// Trigger the error with a cache directory that cannot be created over an
	// existing file
	prepareEnv(t)
	cachedir := os.Getenv("ADSYS_CACHE_DIR")
	err := os.WriteFile(cachedir, []byte(""), 0644)
	require.NoError(t, err, "Can't create cachedir file to make service fails")

	a := daemon.New()
	err = a.Run()
	require.Error(t, err, "Run should exit with an error")
	a.Quit()
}

func TestAppCanSigHupWhenExecute(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn’t fail")

	a, wait := startDaemon(t, true)

	defer wait()
	defer a.Quit()

	orig := os.Stdout
	os.Stdout = w

	err = a.IsReady(time.Second)
	require.NoError(t, err, "Daemon should start within second")

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
	a, wait := startDaemon(t, true)
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
	a, wait := startDaemon(t, true)

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

func TestConfigLoad(t *testing.T) {
	dir := t.TempDir()
	configFile := writeConfig(t, dir, "adsys.socket", 1, 10)
	defer changeArgs("adsysd", "-c", configFile)()

	a, wait := startDaemon(t, false)
	defer wait()
	defer a.Quit()

	a.IsReady(5 * time.Second) // Wait until the socket is really createad
	_, err := os.Stat(filepath.Join(dir, "adsys.socket"))
	require.NoError(t, err, "Socket should exist")
	require.Equal(t, 1, a.Verbosity(), "Verbosity is set from config")
}

func TestConfigChange(t *testing.T) {
	dir := t.TempDir()
	configFile := writeConfig(t, dir, "adsys.socket", 1, 10)
	defer changeArgs("adsysd", "-c", configFile)()

	a, wait := startDaemon(t, false)
	defer wait()
	defer a.Quit()

	a.IsReady(5 * time.Second) // Wait until the socket is really created
	_, err := os.Stat(filepath.Join(dir, "adsys.socket"))
	require.NoError(t, err, "Socket should exist")
	require.Equal(t, 1, a.Verbosity(), "Verbosity is set from config")

	out := captureLogs(t)

	// Write new config
	writeConfig(t, dir, "adsys.socket", 2, 5)

	time.Sleep(time.Second) // let the config change

	logs := out()
	require.Contains(t, logs, "changed. Reloading", "Config file has changed")
}

// writeConfig is a helper to generate a config file for adsysd.
// It returns the path to the config file.
func writeConfig(t *testing.T, dir, socketName string, verbose, serviceTimeout int) string {
	t.Helper()

	configFile := filepath.Join(dir, "config.yaml")

	data := []byte(fmt.Sprintf(`# Service and client configuration
verbose: %d
socket: %s

# Service only configuration
cache_dir: %s
run_dir: %s
servicetimeout: %d
ad_server: warthogs.biz
ad_domain: ldap://adc.warthogs.biz
`,
		verbose,
		filepath.Join(dir, socketName),
		filepath.Join(dir, "cache"),
		filepath.Join(dir, "run"),
		serviceTimeout))

	err := os.WriteFile(configFile, data, 0700)
	require.NoError(t, err, "Setup: failed to write test config file")

	return configFile
}

// startDaemon prepares and start the daemon in the background. The done function should be called
// to wait for the daemon to stop
func startDaemon(t *testing.T, setupEnv bool) (app *daemon.App, done func()) {
	t.Helper()

	if setupEnv {
		prepareEnv(t)
	}

	a := daemon.New()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := a.Run()
		require.NoError(t, err, "Run should exits without any error")
	}()
	a.WaitReady()
	time.Sleep(50 * time.Millisecond)

	return a, func() {
		wg.Wait()
	}
}

// prepareEnv prepares adsys generic configuration with temporary socket and caches.
// The original environment is restored when the test ends.
func prepareEnv(t *testing.T) {
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

	t.Cleanup(func() {
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
	})
}

// changeArgs allows changing command line arguments and return a function to restore it.
func changeArgs(args ...string) (restore func()) {
	orig := os.Args
	os.Args = args
	return func() { os.Args = orig }
}

// captureLogs captures current logs.
// It returns a function to read the buffered log output.
// The original log output is restored when the test ends.
func captureLogs(t *testing.T) (out func() string) {
	t.Helper()

	localLogger := logrus.StandardLogger()
	orig := localLogger.Out
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal("Setup error: creating pipe:", err)
	}
	localLogger.SetOutput(w)
	t.Cleanup(func() {
		localLogger.SetOutput(orig)
	})

	return func() string {
		w.Close()
		var buf bytes.Buffer
		_, errCopy := io.Copy(&buf, r)
		if errCopy != nil {
			t.Fatal("Setup error: couldn’t get buffer content:", err)
		}
		return buf.String()
	}
}
func TestMain(m *testing.M) {
	defer startLocalSystemBus()()
	m.Run()
}
