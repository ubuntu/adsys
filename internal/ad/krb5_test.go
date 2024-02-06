package ad_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestTicketPath(t *testing.T) {
	// Build mock libkrb5
	var mockLibPath string
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		mockLibPath = testutils.BuildKrb5Mock(t, ".")
	}

	// We setup and rerun in a subprocess because we need to preload the mock libkrb5
	if setupSubprocessForTest(t, mockLibPath) {
		return
	}

	tests := map[string]struct {
		krb5Behavior string
		ccacheIsDir  bool

		wantErr bool
	}{
		"Lookup is successful":                 {krb5Behavior: "return_ccache:FILE:%s"},
		"Allow ccache without FILE identifier": {krb5Behavior: "return_ccache:%s"},

		"Error when ccache not present on disk": {krb5Behavior: "return_ccache:FILE:%s/non-existent", wantErr: true},
		"Error when ccache is a directory":      {krb5Behavior: "return_ccache:%s", ccacheIsDir: true, wantErr: true},
		"Error when initializing context":       {krb5Behavior: "error_initializing_context", wantErr: true},
		"Error on empty ticket path":            {krb5Behavior: "return_empty_ccache", wantErr: true},
		"Error on NULL ticket path":             {krb5Behavior: "return_null_ccache", wantErr: true},
		"Error on non-FILE ccache":              {krb5Behavior: "return_memory_ccache", wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			wantOut := filepath.Join(t.TempDir(), "krb5cc_12345")
			if strings.Contains(tc.krb5Behavior, "return_ccache") {
				tc.krb5Behavior = fmt.Sprintf(tc.krb5Behavior, wantOut)
			}

			// Set up mock libwbclient behavior
			t.Setenv("ADSYS_KRB5_BEHAVIOR", tc.krb5Behavior)

			var err error
			if tc.ccacheIsDir {
				err = os.Mkdir(wantOut, 0700)
			} else {
				err = os.WriteFile(wantOut, []byte("dummy ticket data"), 0600)
			}
			require.NoError(t, err, "Setup: Failed to create path to ticket cache")

			ticketPath, err := ad.TicketPath()
			if tc.wantErr {
				require.Error(t, err, "TicketPath should have errored out")
				return
			}
			require.NoError(t, err, "Call to TicketPath failed")

			require.Equal(t, wantOut, ticketPath, "Returned ticket path is not the expected one")
		})
	}
}

// setupSubprocessForTest prepares a subprocess preloading a shared library for running the tests.
// Returns false if we are already in the subprocess and should continue.
// Returns true if we prepare the subprocess and reexec ourself.
func setupSubprocessForTest(t *testing.T, mockLibPath string) bool {
	t.Helper()

	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		return false
	}

	var subArgs []string
	// We are going to only reexec ourself: only take options (without -run)
	// and redirect coverage file
	var hasExplicitTestAsRunArg bool
	for i, arg := range os.Args {
		if i != 0 && !strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.HasPrefix(arg, "-test.run=") {
			if !strings.HasPrefix(arg, fmt.Sprintf("-test.run=%s", t.Name())) {
				continue
			}
			hasExplicitTestAsRunArg = true
		}
		if strings.HasPrefix(arg, "-test.coverprofile=") {
			continue
		}
		subArgs = append(subArgs, arg)
	}
	// Cover subprocess in a different file that we will merge when the test ends
	if testCoverFile := testutils.TrackTestCoverage(t); testCoverFile != "" {
		subArgs = append(subArgs, "-test.coverprofile="+testCoverFile)
	}

	if !hasExplicitTestAsRunArg {
		subArgs = append(subArgs, fmt.Sprintf("-test.run=%s", t.Name()))
	}

	t.Log("Running subprocess with", subArgs)
	// #nosec G204: this is only for tests, under controlled args
	cmd := exec.Command(subArgs[0], subArgs[1:]...)

	// Setup correct child environment, including LD_PRELOAD for wbclient mock
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		// override system libwbclient
		fmt.Sprintf("LD_PRELOAD=%s", mockLibPath),
	)

	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		t.Fail() // The real failure will be written by the child test process
	}

	return true
}
