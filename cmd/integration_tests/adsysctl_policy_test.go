package adsys_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestPolicyAdmx(t *testing.T) {
	tests := map[string]struct {
		arg              string
		distroOption     string
		systemAnswer     string
		daemonNotStarted bool

		wantErr bool
	}{
		"LTS only content":               {arg: "lts-only", systemAnswer: "yes"},
		"All supported releases content": {arg: "all", systemAnswer: "yes"},

		"Accept distro option": {arg: "lts-only", distroOption: "Ubuntu", systemAnswer: "yes"},

		"Need one valid argument": {systemAnswer: "yes", wantErr: true},

		"Admx generation is always allowed": {arg: "lts-only", systemAnswer: "no"},
		"Fail on non stored distro":         {arg: "lts-only", distroOption: "Tartanpion", systemAnswer: "yes", wantErr: true},
		"Fail on invalid arg":               {arg: "something", systemAnswer: "yes", wantErr: true},
		"Daemon not responding":             {arg: "lts-only", daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			systemAnswer(t, tc.systemAnswer)

			conf := createConf(t, "")
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}
			args := []string{"policy", "admx"}
			if tc.arg != "" {
				args = append(args, tc.arg)
			}
			distro := consts.DistroID
			if tc.distroOption != "" {
				args = append(args, "--distro", tc.distroOption)
				distro = tc.distroOption
			}
			dest := t.TempDir()
			chdir(t, dest)
			_, err := runClient(t, conf, args...)
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}
			require.NoError(t, err, "client should exit with no error")

			// Ensure files exists
			_, err = os.Stat(filepath.Join(dest, fmt.Sprintf("%s.admx", distro)))
			require.NoError(t, err, "admx file exists for this distro")
			_, err = os.Stat(filepath.Join(dest, fmt.Sprintf("%s.adml", distro)))
			require.NoError(t, err, "adml file exists for this distro")
		})
	}
}

func TestPolicyApplied(t *testing.T) {
	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get current user")
	user, err := user.Current()
	require.NoError(t, err, "Setup: failed to get current user")
	currentUser := user.Username

	tests := map[string]struct {
		args              []string
		systemAnswer      string
		daemonNotStarted  bool
		userGPORules      string
		noMachineGPORules bool

		wantErr bool
	}{
		"Current user applied gpos": {systemAnswer: "yes"},
		// we use user "root" here as another user because the test user must exist on the machine for the authorizer.
		"Other user applied gpos":   {args: []string{"root"}, userGPORules: "root", systemAnswer: "yes"},
		"Machine only applied gpos": {args: []string{hostname}, systemAnswer: "yes"},

		"Detailed policy without override":               {args: []string{"--details"}, systemAnswer: "yes"},
		"Detailed policy with overrides (all)":           {args: []string{"--all"}, systemAnswer: "yes"},
		"Current user gpos no color":                     {args: []string{"--no-color"}, systemAnswer: "yes"},
		"Detailed policy with overrides (all), no color": {args: []string{"--no-color", "--all"}, systemAnswer: "yes"},

		// Error cases
		"Machine cache not available": {noMachineGPORules: true, systemAnswer: "yes", wantErr: true},
		"User cache not available":    {userGPORules: "-", systemAnswer: "yes", wantErr: true},
		"Applied denied":              {systemAnswer: "no", wantErr: true},
		"Daemon not responding":       {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			systemAnswer(t, tc.systemAnswer)

			// Reset color that we disable on client when we request --no-color
			color.NoColor = false

			dir := t.TempDir()
			dstDir := filepath.Join(dir, "cache", "gpo_rules")
			err := os.MkdirAll(dstDir, 0700)
			require.NoError(t, err, "setup failed: couldn't create gpo_rules directory: %v", err)
			if !tc.noMachineGPORules {
				err := shutil.CopyFile("testdata/PolicyApplied/gpo_rules/machine.yaml", filepath.Join(dstDir, hostname), false)
				require.NoError(t, err, "Setup: failed to copy machine gporules cache")
			}
			if tc.userGPORules != "-" {
				if tc.userGPORules == "" {
					tc.userGPORules = currentUser
				}
				err := shutil.CopyFile("testdata/PolicyApplied/gpo_rules/user.yaml", filepath.Join(dstDir, tc.userGPORules), false)
				require.NoError(t, err, "Setup: failed to copy user gporules cache")
			}
			conf := createConf(t, dir)
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			args := []string{"policy", "applied"}
			if tc.args != nil {
				args = append(args, tc.args...)
			}
			got, err := runClient(t, conf, args...)
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				// Client version is still printed
				return
			}
			require.NoError(t, err, "client should exit with no error")

			// Compare golden files
			goldPath := filepath.Join("testdata/PolicyApplied/golden", name)
			// Update golden file
			if update {
				t.Logf("updating golden file %s", goldPath)
				err = os.WriteFile(goldPath, []byte(got), 0644)
				require.NoError(t, err, "Cannot write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load policy golden file")

			require.Equal(t, string(want), got, "DumpPolicies returned expected output")
		})
	}
}

func TestPolicyUpdate(t *testing.T) {
	currentUser := "adsystestuser@example.com"

	// Reexec ourself, with a mock passwd file
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		err := exec.Command("pkg-config", "--exists", "nss_wrapper").Run()
		require.NoError(t, err, "libnss_wrapper is not installed on disk, either skip integration tests or install it")

		testutils.PythonCoverageToGoFormat(t, "../../internal/policies/ad/adsys-gpolist", true)

		var subArgs []string
		// We are going to only reexec ourself: only take options (without -run)
		// and redirect coverage file
		var hasPolicyUpdateAsRun bool
		for i, arg := range os.Args {
			if i != 0 && !strings.HasPrefix(arg, "-") {
				continue
			}
			if strings.HasPrefix(arg, "-test.run=") {
				if !strings.HasPrefix(arg, "-test.run=TestPolicyUpdate") {
					continue
				}
				hasPolicyUpdateAsRun = true
			}
			// Cover subprocess in a different file that we will merge when the test ends
			if strings.HasPrefix(arg, "-test.coverprofile=") {
				coverage := strings.TrimPrefix(arg, "-test.coverprofile=")
				coverage = fmt.Sprintf("%s.testpolicyupdate", coverage)
				arg = fmt.Sprintf("-test.coverprofile=%s", coverage)
				testutils.AddCoverageFile(coverage)
			}
			subArgs = append(subArgs, arg)
		}
		if !hasPolicyUpdateAsRun {
			subArgs = append(subArgs, "-test.run=TestPolicyUpdate")
		}

		cmd := exec.Command(subArgs[0], subArgs[1:]...)

		admock, err := filepath.Abs("../../internal/testutils/admock")
		require.NoError(t, err, "Setup: Failed to get current absolute path for ad mock")

		passwd := modifyAndAddUsers(t, currentUser, "UserIntegrationTest@example.com")

		// Setup correct child environment, including LD_PRELOAD for nss mock
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_PROCESS=1",

			// dbus addresses to be reset in child
			fmt.Sprintf("DBUS_SYSTEM_BUS_ADDRESS_YES=%s", systemSockets["yes"]),
			fmt.Sprintf("DBUS_SYSTEM_BUS_ADDRESS_NO=%s", systemSockets["no"]),

			// mock for ad python samba code
			fmt.Sprintf("PYTHONPATH=%s", admock),

			// override user and host database
			"LD_PRELOAD=libnss_wrapper.so",
			fmt.Sprintf("NSS_WRAPPER_PASSWD=%s", passwd),
			"NSS_WRAPPER_GROUP=/etc/group",
		)

		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		err = cmd.Run()
		if err != nil {
			t.Fail() // The real failure will be written by the child test process
		}

		return
	}

	// Real test (in a subprocess, with coverage report when enabled in main one)

	// Restore for subprocess the yes and no socket to connect to polkitd
	systemSockets = make(map[string]string)
	systemSockets["yes"] = os.Getenv("DBUS_SYSTEM_BUS_ADDRESS_YES")
	systemSockets["no"] = os.Getenv("DBUS_SYSTEM_BUS_ADDRESS_NO")

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get current host")

	type krb5ccNamesWithState struct {
		src          string
		adsysSymlink string
		invalid      bool
		machine      bool
	}

	tests := map[string]struct {
		args             []string
		initState        string
		systemAnswer     string
		krb5ccname       string
		krb5ccNamesState []krb5ccNamesWithState
		isOffLine        bool
		clearDirs        []string // Removes already generated system files eg dconf db, apparmor profiles, ...

		wantErr bool
	}{
		// First time download
		"Current user, first time": {
			initState: "localhost-uptodate",
		},
		"Other user, first time": {
			args:       []string{"UserIntegrationTest@example.com", "UserIntegrationTest@example.com.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{src: "UserIntegrationTest@example.com.krb5"},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			}},
		"Machine, first time": {
			args:       []string{"-m"},
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "ccache_EXAMPLE.COM",
					machine: true,
				},
			}},

		// Download and update cached data
		"Current user, update old data": {
			initState: "old-data",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          currentUser + ".krb5",
					adsysSymlink: currentUser,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
		},
		"Other user, update old data": {
			args:       []string{"UserIntegrationTest@example.com", "UserIntegrationTest@example.com.krb5"},
			initState:  "old-data",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "UserIntegrationTest@example.com.krb5",
					adsysSymlink: "UserIntegrationTest@example.com",
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			}},
		"Machine, update old data": {args: []string{"-m"},
			initState:  "old-data",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			}},
		"Already up to date": {args: []string{"-m"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			}},
		"Refresh all connected": {args: []string{"--all"},
			initState:  "old-data",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          currentUser + ".krb5",
					adsysSymlink: currentUser,
				},
				{
					src:          "UserIntegrationTest@example.com.krb5",
					adsysSymlink: "UserIntegrationTest@example.com",
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			}},
		"Refresh some connected": {args: []string{"--all"},
			initState:  "old-data",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          currentUser + ".krb5",
					adsysSymlink: currentUser,
				},
				// UserIntegration is not connected (no symlink, old ticket exists though)
				{
					src: "UserIntegrationTest@example.com.krb5",
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			}},
		"Refresh with no user connected updates machines": {args: []string{"--all"},
			initState:  "old-data",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
		},

		// no AD connection
		"Host is offline, get from cache (no update)": {
			isOffLine: true,
			initState: "old-data",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          currentUser + ".krb5",
					adsysSymlink: currentUser,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
		},
		"Host is offline, regenerate from old data": {
			isOffLine: true,
			initState: "old-data",
			// clean generate dconf dbs to regenerate
			clearDirs: []string{
				"dconf/db/adsystestuser@offline.d",
				"dconf/profile/adsystestuser@offline",
			},
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          currentUser + ".krb5",
					adsysSymlink: currentUser,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
		},
		"Host is offline, gpos cache is cleared, with gpo_rules cache": {
			isOffLine: true,
			initState: "old-data",
			// clean gpos cache, but keep machine ones and user gpo_rules
			clearDirs: []string{
				"dconf/db/adsystestuser@offline.d",
				"dconf/profile/adsystestuser@offline",
				"cache/gpo_cache/{5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242}",
				"cache/gpo_cache/{073AA7FC-5C1A-4A12-9AFC-42EC9C5CAF04}",
				"cache/gpo_cache/{75545F76-DEC2-4ADA-B7B8-D5209FD48727}",
			},
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          currentUser + ".krb5",
					adsysSymlink: currentUser,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
		},

		// Tickets handling
		"KRB5CCNAME is ignored with existing ticket for user": {
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          currentUser + ".krb5",
					adsysSymlink: currentUser,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
		},
		"KRB5CCNAME is ignored when requesting ticket on other user": {
			args:       []string{"UserIntegrationTest@example.com", "UserIntegrationTest@example.com.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "NonexistentTicket.krb5",
			krb5ccNamesState: []krb5ccNamesWithState{
				{src: "UserIntegrationTest@example.com.krb5"},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
		},
		"Invalid KRB5CCNAME format is supported": {
			initState:  "localhost-uptodate",
			krb5ccname: "invalidformat" + currentUser + ".krb5",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src: currentUser + ".krb5",
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
		},

		// Error cases
		"User needs machine to be updated": {wantErr: true},
		"Polkit denied updating self":      {systemAnswer: "no", initState: "localhost-uptodate", wantErr: true},
		"Polkit denied updating other":     {systemAnswer: "no", args: []string{"UserIntegrationTest@example.com", "FIXME"}, initState: "localhost-uptodate", wantErr: true},
		"Polkit denied updating machine":   {systemAnswer: "no", args: []string{"-m"}, wantErr: true},
		"Error on dconf apply failing": {
			initState: "localhost-uptodate",
			// this generates an error when checking that a machine dconf is present
			clearDirs: []string{
				"dconf",
			},
			wantErr: true,
		},
		"Error on host is offline, without gpo_rules": {
			isOffLine: true,
			initState: "old-data",
			// clean gpos rules, but gpo_cache
			clearDirs: []string{
				"dconf/db/adsystestuser@example.com.d",
				"dconf/profile/adsystestuser@example.com",
				"cache/gpo_rules/adsystestuser@example.com",
			},
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          currentUser + ".krb5",
					adsysSymlink: currentUser,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		// danglink symlink
		"Error on no KRB5CCNAME and no adsys symlink created": {
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			wantErr:    true,
		},
		"Error on non-existent ticket provided": {
			args:       []string{"UserIntegrationTest@example.com", "NonexistentTicket.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{src: "UserIntegrationTest@example.com.krb5"},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		"Error on invalid ticket in KRB5CCNAME": {
			initState: "localhost-uptodate",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     currentUser + ".krb5",
					invalid: true,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		"Error on invalid ticket provided": {
			args:       []string{"UserIntegrationTest@example.com", "UserIntegrationTest@example.com.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "UserIntegrationTest@example.com.krb5",
					invalid: true,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		"Error on dangling symlink for current user ticket": {
			initState: "localhost-uptodate",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					adsysSymlink: currentUser,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		"Error with no ticket, even with cache": {
			initState: "old-data",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		// Incompatible options
		"Error on all and specific user requested": {
			args:       []string{"--all", "UserIntegrationTest@example.com", "UserIntegrationTest@example.com.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "UserIntegrationTest@example.com.krb5",
					invalid: true,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		"Error on all and computer requested": {
			args:       []string{"--all", "-m"},
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		"Error computer and specific user requested": {
			args:       []string{"-m", "UserIntegrationTest@example.com", "UserIntegrationTest@example.com.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "UserIntegrationTest@example.com.krb5",
					invalid: true,
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		"Error on computer requested directly (argument is user)": {
			args:       []string{"-m", hostname, "ccache_EXAMPLE.COM"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		// FIXME: if one user fails (ticket expired for a long time, do we really want to fail there?
		// we say we are failing, but the other were updated)
		// maybe only a warning if better
		"Error on refresh with one user failing": {args: []string{"--all"},
			initState:  "old-data",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          currentUser + ".krb5",
					adsysSymlink: currentUser,
				},
				{
					// dangling adsys symlink for this user
					//src:          "UserIntegrationTest@example.com.krb5",
					adsysSymlink: "UserIntegrationTest@example.com",
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.systemAnswer == "" {
				tc.systemAnswer = "yes"
			}
			systemAnswer(t, tc.systemAnswer)

			adsysDir := t.TempDir()

			// Prepare initial state, renaming HOST file to current host
			if tc.initState != "" {
				// Copytree dest directory should not exists
				err = os.Remove(adsysDir)
				require.NoError(t, err, "Setup: could not remove adsysDir")
				copyRenameHost := func(src, dst string, followSymlinks bool) (string, error) {
					if filepath.Base(src) == "HOST" {
						dst = filepath.Join(filepath.Dir(dst), hostname)
					}
					return shutil.Copy(src, dst, followSymlinks)
				}
				err := shutil.CopyTree(filepath.Join("testdata", "PolicyUpdate", "states", tc.initState), adsysDir, &shutil.CopyTreeOptions{CopyFunction: copyRenameHost})
				require.NoError(t, err, "Setup: could not copy initial state")
			}
			// Some tests will need some initial state assets
			for _, k := range tc.clearDirs {
				err := os.RemoveAll(filepath.Join(adsysDir, k))
				require.NoError(t, err, "Remove generate assets db")
			}

			// Ticket creation for mock.
			krb5dir := t.TempDir()
			krb5ccDir := filepath.Join(adsysDir, "run", "krb5cc")
			err := os.MkdirAll(krb5ccDir, 0755)
			require.NoError(t, err, "Setup: could not create ticket directory")
			if tc.krb5ccNamesState == nil {
				tc.krb5ccNamesState = []krb5ccNamesWithState{
					{src: currentUser + ".krb5"},
					{
						src:          "ccache_EXAMPLE.COM",
						adsysSymlink: hostname,
						machine:      true,
					},
				}
			}
			for _, krb5 := range tc.krb5ccNamesState {
				krb5currentDir := krb5dir
				if krb5.machine {
					krb5currentDir = filepath.Join(adsysDir, "sss_cache")
					err := os.MkdirAll(krb5currentDir, 0755)
					require.NoError(t, err, "Setup: could not create machine sss cache")
				}
				if krb5.src != "" {
					krb5.src = filepath.Join(krb5currentDir, krb5.src)
					content := "Some data for the mock"
					if krb5.invalid {
						content = "Some invalid ticket content for the mock"
					}
					err := os.WriteFile(krb5.src, []byte(content), 0600)
					require.NoError(t, err, "Setup: Could not write ticket content")
				} else {
					// dangling symlink
					krb5.src = "/some/unexisting/ticket"
				}

				if krb5.adsysSymlink == "" {
					continue
				}

				err = os.Symlink(krb5.src, filepath.Join(krb5ccDir, krb5.adsysSymlink))
				require.NoError(t, err, "Setup: could not set krb5 file adsys symlink")
			}

			if tc.krb5ccname == "" {
				tc.krb5ccname = currentUser + ".krb5"
			}
			if tc.krb5ccname != "-" {
				if strings.HasPrefix(tc.krb5ccname, "invalidformat") {
					tc.krb5ccname = filepath.Join(krb5dir, strings.TrimPrefix(tc.krb5ccname, "invalidformat"))
				} else {
					tc.krb5ccname = fmt.Sprintf("FILE:%s/%s", krb5dir, tc.krb5ccname)
				}
				testutils.Setenv(t, "KRB5CCNAME", tc.krb5ccname)
			}

			conf := createConf(t, adsysDir)
			if tc.isOffLine {
				content, err := os.ReadFile(conf)
				require.NoError(t, err, "Setup: can’t read configuration file")
				content = bytes.Replace(content, []byte("ad_domain: example.com"), []byte("ad_domain: offline"), 1)
				err = os.WriteFile(conf, content, 0644)
				require.NoError(t, err, "Setup: can’t rewrite configuration file")
			}
			defer runDaemon(t, conf)()

			args := []string{"policy", "update"}
			for _, arg := range tc.args {
				// Prefix krb5 ticket with our krb5dir
				if strings.HasSuffix(arg, ".krb5") {
					arg = filepath.Join(krb5dir, arg)
				}
				args = append(args, arg)
			}
			_, err = runClient(t, conf, args...)
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				// Client version is still printed
				return
			}
			require.NoError(t, err, "client should exit with no error")

			testutils.CompareTreesWithFiltering(t, filepath.Join(adsysDir, "dconf"), filepath.Join("testdata", "PolicyUpdate", "golden", name, "dconf"), update)
		})
	}
}

func TestPolicyDebugGPOListScript(t *testing.T) {
	gpolistSrc, err := ioutil.ReadFile("../../internal/policies/ad/adsys-gpolist")
	require.NoError(t, err, "Setup: failed to load source of adsys-gpolist")

	tests := map[string]struct {
		systemAnswer     string
		daemonNotStarted bool

		wantErr bool
	}{
		"Get adsys-gpolist script":     {systemAnswer: "yes"},
		"Version is always authorized": {systemAnswer: "no"},
		"Daemon not responding":        {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			systemAnswer(t, tc.systemAnswer)

			conf := createConf(t, "")
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			chdir(t, os.TempDir())

			_, err := runClient(t, conf, "policy", "debug", "gpolist-script")
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}

			f, err := os.Stat("adsys-gpolist")
			require.NoError(t, err, "gpo list script should exists")

			require.NotEqual(t, 0, f.Mode()&0111, "Script should be executable")

			got, err := os.ReadFile("adsys-gpolist")
			require.NoError(t, err, "gpo list script is not readable")

			require.Equal(t, string(gpolistSrc), string(got), "Script content should match source")
		})
	}
}

func modifyAndAddUsers(t *testing.T, new string, users ...string) (passwd string) {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "passwd")

	f, err := os.Open("/etc/passwd")
	require.NoError(t, err, "Setup: can't open source passwd file")
	defer func() { require.NoError(t, f.Close(), "Setup: can’t close") }()

	d, err := os.Create(dest)
	require.NoError(t, err, "Setup: can’t create passwd temp file")
	defer func() { require.NoError(t, d.Close(), "Setup: can’t close") }()

	u, err := user.Current()
	require.NoError(t, err, "Setup: can’t get current user name")
	groups, err := u.GroupIds()
	require.NoError(t, err, "Setup: can’t get group for current user")
	group := groups[0]

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		if strings.HasPrefix(l, fmt.Sprintf("%s:", u.Username)) {
			l = fmt.Sprintf("%s%s", new, strings.TrimPrefix(l, u.Username))
		}
		d.Write([]byte(l + "\n"))
	}
	require.NoError(t, scanner.Err(), "Setup: can't write temporary passwd file")

	for i, u := range users {
		d.Write([]byte(fmt.Sprintf("%s:x:%d:%s::/nonexistent:/usr/bin/false", u, i+23450, group)))
	}

	return dest
}

// chdir change current directory to dir.
// The previous current directory is restored when the test ends.
func chdir(t *testing.T, dir string) {
	t.Helper()

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Setup: Can’t get current directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Setup: Can’t change current directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Fatalf("Teardown: Can’t restore current directory: %v", err)
		}
	})
}
