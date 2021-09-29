package client_test

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adsysd/client"
)

// We can’t run any tests in parallel, even those not changing env variables as cobra install flags globally

func TestInitApp(t *testing.T) {
	t.Parallel()

	a := client.New()
	err := a.Run()
	require.Error(t, err, "Run should return usage")
}

func TestAppHelp(t *testing.T) {
	a := client.New()

	defer changeArgs("adsysctl", "--help")()
	err := a.Run()
	require.NoError(t, err, "Run should return no error")
}

func TestAppCompletion(t *testing.T) {
	a := client.New()

	defer changeArgs("adsysctl", "completion", "bash")()
	err := a.Run()
	require.NoError(t, err, "Completion should not use socket and always be reachable")
}

func TestAppNoUsageError(t *testing.T) {
	a := client.New()

	defer changeArgs("adsysctl", "completion", "bash")()
	err := a.Run()
	require.NoError(t, err, "Completion should not return an error")
	isUsageError := a.UsageError()
	require.False(t, isUsageError, "No usage error is reported as such")
}

func TestAppUsageError(t *testing.T) {
	a := client.New()

	defer changeArgs("adsysctl", "doesnotexist")()
	err := a.Run()
	require.Error(t, err, "Run should return usage")
	isUsageError := a.UsageError()
	require.True(t, isUsageError, "Usage error is reported as such")
}

func TestAppCanQuitWhenExecute(t *testing.T) {
	a := client.New()
	a.AddWaitCommand()
	defer changeArgs("adsysctl", "wait")()

	wg := sync.WaitGroup{}
	wg.Add(1)
	var runErr error
	go func() {
		defer wg.Done()
		runErr = a.Run()
	}()
	a.Quit()

	wg.Wait()
	require.NoError(t, runErr, "Wait should have quit before reaching end of function")
}

func TestAppCanQuitAfterExecute(t *testing.T) {
	a := client.New()

	defer changeArgs("adsysctl", "completion", "bash")()
	err := a.Run()
	require.NoError(t, err, "Run should return no error")
	a.Quit()
}

func TestAppCanQuitWithoutExecute(t *testing.T) {
	a := client.New()
	a.Quit()
}

func TestAppCanSigHupWhenExecute(t *testing.T) {
	a := client.New()

	a.AddWaitCommand()
	defer changeArgs("adsysctl", "wait")()

	wg := sync.WaitGroup{}
	wg.Add(1)
	var runErr error
	go func() {
		defer wg.Done()
		runErr = a.Run()
	}()
	a.Hup()

	wg.Wait()
	require.NoError(t, runErr, "Wait should have quit before reaching end of function")
}

func TestAppCanSigHupAfterExecute(t *testing.T) {
	a := client.New()

	defer changeArgs("adsysctl", "completion", "bash")()
	err := a.Run()
	require.NoError(t, err, "Run should return no error")
	require.True(t, a.Hup(), "Hup returns true for client")
}

func TestAppGetRootCmd(t *testing.T) {
	t.Parallel()

	a := client.New()
	require.NotNil(t, a.RootCmd(), "Returns root command")
}

// TODO: config change

// changeArgs allows changing command line arguments and return a function to return it.
func changeArgs(args ...string) func() {
	orig := os.Args
	os.Args = args
	return func() { os.Args = orig }
}
