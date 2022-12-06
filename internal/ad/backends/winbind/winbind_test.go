package winbind_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad/backends/winbind"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestWinbind(t *testing.T) {
	// Build mock libwbclient
	var mockLibPath string
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		mockLibPath = buildMockLib(t)
	}

	// We setup and rerun in a subprocess because we need to preload the mock libwbclient
	if setupSubprocessForTest(t, mockLibPath) {
		return
	}

	tests := map[string]struct {
		wbclientBehavior string
		staticADDomain   string
		staticADServer   string

		wantErr bool
	}{
		"Lookup is successful": {},

		// Override cases
		"Lookup with overridden ad_domain":                  {staticADDomain: "overridden.com"},
		"Lookup with overridden ad_server":                  {staticADServer: "controller.overridden.com"},
		"Lookup with overridden ad_server with LDAP prefix": {staticADServer: "ldap://controller.overridden.com"},

		// Error cases
		"Error looking up domain":      {wbclientBehavior: "domain_not_found", wantErr: true},
		"Error looking up DC name":     {wbclientBehavior: "error_getting_dc_name"},
		"Error getting online status":  {wbclientBehavior: "error_getting_online_status"},
		"Error when domain is offline": {wbclientBehavior: "domain_is_offline"},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			// Set up mock libwbclient behavior
			t.Setenv("ADSYS_WBCLIENT_BEHAVIOR", tc.wbclientBehavior)

			config := winbind.Config{}
			if tc.staticADDomain != "" {
				config.ADDomain = tc.staticADDomain
			}
			if tc.staticADServer != "" {
				config.ADServer = tc.staticADServer
			}

			backend, err := winbind.New(context.Background(), config)
			if tc.wantErr {
				require.Error(t, err, "New should have errored out")
				return
			}

			got := testutils.FormatBackendCalls(t, backend)
			want := testutils.LoadWithUpdateFromGolden(t, got)
			require.Equal(t, want, got, "Got expected loaded values in winbind config object")
		})
	}
}

// setupSubprocessForTest prepares a subprocess with a mock passwd file for running the tests.
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

	fmt.Println("Running subprocess with", subArgs)
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

func buildMockLib(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("pkg-config", "--cflags-only-I", "wbclient")
	cflags, err := cmd.Output()
	require.NoError(t, err, "libwbclient-dev is not installed on disk, either skip these tests or install the required package")

	// Build mock libwbclient
	tmpdir := t.TempDir()
	libPath := filepath.Join(tmpdir, "libwbclient.so.0")
	args := strings.Fields(string(cflags))
	args = append(args, "-fPIC", "-shared", "mock/libwbclient_mock.c", "-o", libPath)
	// #nosec G204: this is only for tests, under controlled args
	out, err := exec.Command("gcc", args...).CombinedOutput()
	require.NoError(t, err, "failed to build mock libwbclient: ", string(out))

	return libPath
}

func TestMain(m *testing.M) {
	testutils.InstallUpdateFlag()
	debug := flag.Bool("verbose", false, "Print debug log level information within the test")
	flag.Parse()
	if *debug {
		logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	}

	m.Run()
	testutils.MergeCoverages()
}
