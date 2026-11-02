package main

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

type myApp struct {
	runError         bool
	usageErrorReturn bool
}

func (a *myApp) Run() error {
	if a.runError {
		return errors.New("Error requested")
	}
	return nil
}

func (a myApp) UsageError() bool {
	return a.usageErrorReturn
}

func TestRun(t *testing.T) {
	tests := map[string]struct {
		runError         bool
		usageErrorReturn bool

		wantReturnCode int
	}{
		"Run and exit successfully":              {},
		"Run and return error":                   {runError: true, wantReturnCode: 1},
		"Run and return usage error":             {usageErrorReturn: true, runError: true, wantReturnCode: 2},
		"Run and usage error only does not fail": {usageErrorReturn: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			a := myApp{
				runError:         tc.runError,
				usageErrorReturn: tc.usageErrorReturn,
			}

			var rc int
			wait := make(chan struct{})
			go func() {
				rc = run(&a)
				close(wait)
			}()

			<-wait

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
	cmd := exec.Command(os.Args[0], "help", "-test.run=TestMainApp")
	cmd.Env = append(os.Environ(), "ADSYS_CALL_MAIN=1")
	out, err := cmd.CombinedOutput()

	require.Contains(t, string(out),
		"Generate ADMX and intermediary working files from a list of policy definition files.",
		"Main function should print the help message",
	)
	require.NoError(t, err, "Main should not return an error")
}

func TestAppUsage(t *testing.T) {
	tests := map[string]struct {
		args []string

		wantUsageError bool
	}{
		"Expand with correct arguments": {args: []string{"expand", "source", "dest"}},
		"Admx with correct arguments":   {args: []string{"admx", "categories.yaml", "source", "dest"}},
		"Doc with correct arguments":    {args: []string{"doc", "categories.yaml", "source", "dest"}},

		"Error when command is called with wrong arguments": {args: []string{"not_a_command"}, wantUsageError: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if os.Getenv("ADSYS_CALL_MAIN") != "" {
				main()
				return
			}

			args := append([]string{os.Args[0]}, tc.args...)
			args = append(args, "-test.run=TestMainApp")

			// #nosec G204: this is only for tests, under controlled args
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Env = append(os.Environ(), "ADSYS_CALL_MAIN=1")

			err := cmd.Run()
			require.Error(t, err, "Main should return an error")
			require.Equal(t, tc.wantUsageError, cmd.ProcessState.ExitCode() == 2, "Main should return expected code")
		})
	}
}
