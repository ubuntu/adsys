package winbind_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
		mockLibPath = testutils.BuildWinbindMock(t, ".")
	}

	// We setup and rerun in a subprocess because we need to preload the mock libwbclient
	if testutils.PreloadLibInSubprocess(t, mockLibPath) {
		return
	}

	tests := map[string]struct {
		wbclientBehavior string
		staticADDomain   string
		staticADServer   string
		hostname         string

		wantKinitErr bool
		wantErr      bool
	}{
		"Lookup is successful":                         {},
		"Lookup with different hostname is successful": {hostname: "mycustomhostname"},

		// Override cases
		"Lookup with overridden ad_domain":                  {staticADDomain: "overridden.com"},
		"Lookup with overridden ad_server":                  {staticADServer: "controller.overridden.com"},
		"Lookup with overridden ad_server with LDAP prefix": {staticADServer: "ldap://controller.overridden.com"},

		// Error cases
		"Error when looking up domain":     {wbclientBehavior: "domain_not_found", wantErr: true},
		"Error when looking up DC name":    {wbclientBehavior: "error_getting_dc_name"},
		"Error when getting online status": {wbclientBehavior: "error_getting_online_status"},
		"Error when domain is offline":     {wbclientBehavior: "domain_is_offline"},
		"Error when requesting krb5cc":     {wantKinitErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Set up mock libwbclient behavior
			t.Setenv("ADSYS_WBCLIENT_BEHAVIOR", tc.wbclientBehavior)

			hostname := tc.hostname
			if hostname == "" {
				hostname = "ubuntu"
			}

			config := winbind.Config{}
			if tc.staticADDomain != "" {
				config.ADDomain = tc.staticADDomain
			}
			if tc.staticADServer != "" {
				config.ADServer = tc.staticADServer
			}

			kinitCmdOutputFile := filepath.Join(t.TempDir(), "kinit-output")
			kinitCmd := []string{"env", "GO_WANT_HELPER_PROCESS=1", os.Args[0], "-test.run=TestExecuteKinitCommand", "--", kinitCmdOutputFile}
			if tc.wantKinitErr {
				kinitCmd = append(kinitCmd, "-Exit1-")
			}

			backend, err := winbind.New(context.Background(), config, hostname, winbind.WithKinitCmd(kinitCmd))
			if tc.wantErr {
				require.Error(t, err, "New should have errored out")
				return
			}

			got := testutils.FormatBackendCalls(t, backend)

			// Check kinit command
			if !tc.wantKinitErr {
				gotKinitArgs, err := os.ReadFile(kinitCmdOutputFile)
				require.NoError(t, err, "Setup: failed to read kinit command output")
				got += "\nKinit args: " + string(gotKinitArgs)
			}
			want := testutils.LoadWithUpdateFromGolden(t, got)
			require.Equal(t, want, got, "Got expected loaded values in winbind config object")
		})
	}
}

func TestExecuteKinitCommand(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	var goldPath string
	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			goldPath = args[1]
			args = args[2:]
			break
		}
		args = args[1:]
	}

	if args[0] == "-Exit1-" {
		fmt.Fprintf(os.Stderr, "EXIT 1 requested in mock")
		os.Exit(1)
	}

	err := os.WriteFile(goldPath, []byte(fmt.Sprintf("%q", args)+"\n"), 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Setup: failed to write kinit command output: %v", err)
		os.Exit(1)
	}
}

func TestMain(m *testing.M) {
	debug := flag.Bool("verbose", false, "Print debug log level information within the test")
	flag.Parse()
	if *debug {
		logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	}

	m.Run()
	testutils.MergeCoverages()
}
