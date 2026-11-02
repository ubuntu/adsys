package main

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type myApp struct {
	done chan struct{}

	runError         bool
	usageErrorReturn bool
}

func (a *myApp) Run() error {
	<-a.done
	if a.runError {
		return errors.New("Error requested")
	}
	return nil
}

func (a myApp) UsageError() bool {
	return a.usageErrorReturn
}

func (a *myApp) Quit(_ syscall.Signal) error {
	close(a.done)
	return nil
}

func TestRun(t *testing.T) {
	tests := map[string]struct {
		runError         bool
		usageErrorReturn bool
		sendSig          syscall.Signal

		wantReturnCode int
	}{
		"Run and exit successfully":              {},
		"Run and return error":                   {runError: true, wantReturnCode: 1},
		"Run and return usage error":             {usageErrorReturn: true, runError: true, wantReturnCode: 2},
		"Run and usage error only does not fail": {usageErrorReturn: true},

		// Signals handling
		"Send SIGINT exits":  {sendSig: syscall.SIGINT},
		"Send SIGTERM exits": {sendSig: syscall.SIGTERM},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Signal handler tests cannot run in parallel
			if tc.sendSig != 0 && runtime.GOOS == "windows" {
				// Skip signal handling tests on Windows, we already test
				// quitting the app as part of the integration tests.
				t.Skip("Signal handling tests are not supported on Windows")
			}

			a := myApp{
				done:             make(chan struct{}),
				runError:         tc.runError,
				usageErrorReturn: tc.usageErrorReturn,
			}

			var rc int
			wait := make(chan struct{})
			go func() {
				rc = run(&a)
				close(wait)
			}()

			time.Sleep(100 * time.Millisecond)

			var exited bool
			switch tc.sendSig {
			case syscall.SIGINT:
				fallthrough
			case syscall.SIGTERM:
				process, err := os.FindProcess(syscall.Getpid())
				require.NoError(t, err, "Teardown: find process should return no error")
				err = process.Signal(tc.sendSig)
				require.NoError(t, err, "Teardown: kill should return no error")
				select {
				case <-time.After(50 * time.Millisecond):
					exited = false
				case <-wait:
					exited = true
				}
				require.Equal(t, true, exited, "Expect to exit on SIGINT and SIGTERM")
			}

			if !exited {
				_ = a.Quit(syscall.SIGINT)
				<-wait
			}

			require.Equal(t, tc.wantReturnCode, rc, "Return expected code")
		})
	}
}

func TestMainApp(t *testing.T) {
	if os.Getenv("ADSYS_CALL_MAIN") != "" {
		main()
		return
	}

	// #nosec G204: this is only for tests, under controlled args
	cmd := exec.Command(os.Args[0], "version", "-test.run=TestMainApp")
	cmd.Env = append(os.Environ(), "ADSYS_CALL_MAIN=1")
	out, err := cmd.CombinedOutput()

	version := strings.TrimSpace(strings.TrimPrefix(string(out), "adwatchd\t"))
	require.NotEmpty(t, version, "Main function should print the version")
	require.NoError(t, err, "Main should not return an error")
}
