package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adsysd/client"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
)

type myApp struct {
	done chan struct{}

	runError         bool
	usageErrorReturn bool
	hupReturn        bool
	codeErrorReturn  int
}

func (a *myApp) Run() error {
	<-a.done
	if a.runError {
		return errors.New("Error requested")
	}
	if a.codeErrorReturn != 0 {
		return codeError{code: a.codeErrorReturn}
	}
	return nil
}

// codeError is a test error carrying an explicit exit code.
type codeError struct {
	code int
}

func (e codeError) Error() string { return "" }

// ExitCode returns the associated process exit code.
func (e codeError) ExitCode() int { return e.code }

func (a myApp) UsageError() bool {
	return a.usageErrorReturn
}

func (a myApp) Hup() bool {
	return a.hupReturn
}

func (a *myApp) Quit() {
	close(a.done)
}

func TestRun(t *testing.T) {
	tests := map[string]struct {
		runError         bool
		usageErrorReturn bool
		hupReturn        bool
		codeErrorReturn  int
		sendSig          syscall.Signal

		wantReturnCode int
	}{
		"Run and exit successfully":              {},
		"Run and return error":                   {runError: true, wantReturnCode: 1},
		"Run and return usage error":             {usageErrorReturn: true, runError: true, wantReturnCode: 2},
		"Run and usage error only does not fail": {usageErrorReturn: true, runError: false, wantReturnCode: 0},
		"Run and return specific exit code":      {codeErrorReturn: 3, wantReturnCode: 3},

		// Signals handling
		"Send SIGINT exits":           {sendSig: syscall.SIGINT},
		"Send SIGTERM exits":          {sendSig: syscall.SIGTERM},
		"Send SIGHUP without exiting": {sendSig: syscall.SIGHUP},
		"Send SIGHUP with exit":       {sendSig: syscall.SIGHUP, hupReturn: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Signal handlers tests: can’t be parallel

			a := myApp{
				done:             make(chan struct{}),
				runError:         tc.runError,
				usageErrorReturn: tc.usageErrorReturn,
				hupReturn:        tc.hupReturn,
				codeErrorReturn:  tc.codeErrorReturn,
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
				err := syscall.Kill(syscall.Getpid(), tc.sendSig)
				require.NoError(t, err, "Teardown: kill should return no error")
				select {
				case <-time.After(50 * time.Millisecond):
					exited = false
				case <-wait:
					exited = true
				}
				require.Equal(t, true, exited, "Expect to exit on SIGINT and SIGTERM")
			case syscall.SIGHUP:
				err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
				require.NoError(t, err, "Teardown: kill should return no error")
				select {
				case <-time.After(50 * time.Millisecond):
					exited = false
				case <-wait:
					exited = true
				}
				// if SIGHUP returns false: do nothing and still wait.
				// Otherwise, it means that we wanted to stop
				require.Equal(t, tc.hupReturn, exited, "Expect to exit only on SIGHUP returning True")
			}

			if !exited {
				a.Quit()
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

	// #nosec G204,G702: this is only for tests, under controlled args
	cmd := exec.Command(os.Args[0], "version", "-test.run=TestMainApp")
	cmd.Env = append(os.Environ(), "ADSYS_CALL_MAIN=1")
	out, err := cmd.CombinedOutput()

	version := strings.TrimSpace(strings.TrimPrefix(string(out), "adsysd\t"))
	require.NotEmpty(t, version, "Main function should print the version")
	require.NoError(t, err, "Main should not return an error")
}

func TestMainAppLocalizedHelp(t *testing.T) {
	if os.Getenv("ADSYS_CALL_MAIN") != "" {
		os.Args = []string{os.Getenv("ADSYS_MAIN_ARGV0"), "--help"}
		main()
		return
	}

	tests := map[string]struct {
		argv0 string

		wantHelp string
	}{
		"Client help is localized": {argv0: client.CmdName, wantHelp: "Outil en ligne de commande de la suite d'intégration avec Active Directory."},
		"Daemon help is localized": {argv0: daemon.CmdName, wantHelp: "Démon de la suite d'intégration avec Active Directory."},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// #nosec G204,G702: this is only for tests, under controlled args
			cmd := exec.Command(os.Args[0], "-test.run=TestMainAppLocalizedHelp")
			cmd.Env = append(os.Environ(), "ADSYS_CALL_MAIN=1", "ADSYS_MAIN_ARGV0="+tc.argv0, "LANGUAGE=fr")
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "Main should not return an error: %s", out)
			require.Contains(t, string(out), tc.wantHelp, "Help should be printed in the language selected by the environment")
		})
	}
}
