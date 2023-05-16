package adsys_test

import (
	"bufio"
	"bytes"
	"fmt"
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
		"LTS only content":               {arg: "lts-only", systemAnswer: "polkit_yes"},
		"All supported releases content": {arg: "all", systemAnswer: "polkit_yes"},

		"Accept distro option": {arg: "lts-only", distroOption: "Ubuntu", systemAnswer: "polkit_yes"},

		"Admx generation is always allowed": {arg: "lts-only", systemAnswer: "polkit_no"},

		// Error cases
		"Error on none valid argument":   {systemAnswer: "polkit_yes", wantErr: true},
		"Error on invalid arg":           {arg: "something", systemAnswer: "polkit_yes", wantErr: true},
		"Error on non stored distro":     {arg: "lts-only", distroOption: "Tartanpion", systemAnswer: "polkit_yes", wantErr: true},
		"Error on daemon not responding": {arg: "lts-only", daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			dbusAnswer(t, tc.systemAnswer)

			conf := createConf(t)
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
			testutils.Chdir(t, dest)
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
	currentUser := "adsystestuser@example.com"

	// We setup and rerun in a subprocess because the test users must exist on the machine for the authorizer.
	if setupSubprocessForTest(t, currentUser, "userintegrationtest@example.com") {
		return
	}

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get current hostname")

	tests := map[string]struct {
		args              []string
		systemAnswer      string
		daemonNotStarted  bool
		userGPORules      string
		noMachineGPORules bool

		wantErr bool
	}{
		"Current user applied gpos":               {},
		"Other user applied gpos":                 {args: []string{"userintegrationtest@example.com"}, userGPORules: "userintegrationtest@example.com"},
		"Other user applied gpos with mixed case": {args: []string{"UserIntegrationTest@example.com"}, userGPORules: "userintegrationtest@example.com"},
		"Machine only applied gpos using -m flag": {args: []string{"--machine"}},

		"Detailed policy without override":               {args: []string{"--details"}},
		"Detailed policy with overrides (all)":           {args: []string{"--all"}},
		"Current user gpos no color":                     {args: []string{"--no-color"}},
		"Detailed policy with overrides (all), no color": {args: []string{"--no-color", "--all"}},

		// User options
		`Current user with domain\username`:           {args: []string{`example.com\adsystestuser`}},
		`Current user with default domain completion`: {args: []string{`adsystestuser`}},

		// Error cases
		"Error when getting machine only applied gpos without flag": {args: []string{hostname}, wantErr: true},
		"Error on machine cache not available":                      {noMachineGPORules: true, wantErr: true},
		"Error on user cache not available":                         {userGPORules: "-", wantErr: true},
		"Error on unexisting user":                                  {args: []string{"doesnotexists@example.com"}, wantErr: true},
		"Error on user name without domain and no default domain":   {args: []string{"doesnotexists"}, wantErr: true},
		"Error on applied denied":                                   {systemAnswer: "polkit_no", wantErr: true},
		"Error on daemon not responding":                            {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.systemAnswer == "" {
				tc.systemAnswer = "polkit_yes"
			}
			dbusAnswer(t, tc.systemAnswer)

			// Reset color that we disable on client when we request --no-color
			color.NoColor = false

			dir := t.TempDir()
			dstDir := filepath.Join(dir, "cache", "policies")
			err := os.MkdirAll(dstDir, 0700)
			require.NoError(t, err, "setup failed: couldn't create policies directory: %v", err)
			if !tc.noMachineGPORules {
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join(testutils.TestFamilyPath(t), "policies", "machine"),
						filepath.Join(dstDir, hostname),
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: failed to copy machine policies cache")
			}
			if tc.userGPORules != "-" {
				if tc.userGPORules == "" {
					tc.userGPORules = currentUser
				}
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join(testutils.TestFamilyPath(t), "policies", "user"),
						filepath.Join(dstDir, tc.userGPORules),
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: failed to copy user policies cache")
			}
			conf := createConf(t, confWithAdsysDir(dir))

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
			want := testutils.LoadWithUpdateFromGolden(t, got)
			require.Equal(t, want, got, "DumpPolicies returned expected output")
		})
	}
}

func TestPolicyUpdate(t *testing.T) {
	currentUser := "adsystestuser@example.com"

	u, err := user.Current()
	require.NoError(t, err, "Setup: can't get current user")
	currentUID := u.Uid

	// We setup and rerun in a subprocess because the test users must exist on the machine for the authorizer.
	if setupSubprocessForTest(t, currentUser, "userintegrationtest@example.com") {
		return
	}

	t.Setenv("ADSYS_TESTS_MOCK_SMBDOMAIN", "example.com")
	t.Setenv("ADSYS_SKIP_ROOT_CALLS", "TRUE")

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get current host")

	type krb5ccNamesWithState struct {
		src          string
		adsysSymlink string
		invalid      bool
		machine      bool
	}

	tests := map[string]struct {
		args                []string
		backend             string
		initState           string
		sssdConf            string
		systemAnswer        string
		krb5ccname          string
		krb5ccNamesState    []krb5ccNamesWithState
		clearDirs           []string // Removes already generated system files eg dconf db, apparmor profiles, ...
		addPaths            []string
		readOnlyDirs        []string
		winbindMockBehavior string
		purge               bool

		wantErr bool
	}{
		// First time download
		"Current user, first time": {
			initState: "localhost-uptodate",
		},
		"Current user, first time with winbind backend": {
			backend:   "winbind",
			initState: "localhost-uptodate",
		},
		"Other user, first time": {
			args:       []string{"userintegrationtest@example.com", "userintegrationtest@example.com.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{src: "userintegrationtest@example.com.krb5"},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			}},
		"Machine, first time": {
			args:       []string{"-m"},
			addPaths:   []string{"apparmorfs/profiles"},
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "ccache_EXAMPLE.COM",
					machine: true,
				},
			}},
		"Machine, first time with winbind backend": {
			backend:    "winbind",
			args:       []string{"-m"},
			addPaths:   []string{"apparmorfs/profiles"},
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "/tmp/krb5cc_0",
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
			args:       []string{"userintegrationtest@example.com", "userintegrationtest@example.com.krb5"},
			initState:  "old-data",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "userintegrationtest@example.com.krb5",
					adsysSymlink: "userintegrationtest@example.com",
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			}},
		"Other user with mixed case, update old data": {
			args:       []string{"UserIntegrationTest@example.com", "userintegrationtest@example.com.krb5"},
			initState:  "old-data",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "userintegrationtest@example.com.krb5",
					adsysSymlink: "userintegrationtest@example.com",
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
					src:          "userintegrationtest@example.com.krb5",
					adsysSymlink: "userintegrationtest@example.com",
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
					src: "userintegrationtest@example.com.krb5",
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

		// Static AD server
		"Current user, static AD server": {
			sssdConf:  "sssd.conf-example.com_static-server",
			initState: "localhost-uptodate",
		},

		// no AD connection
		"Host is offline, get user from cache (no update)": {
			sssdConf:  "sssd.conf-offline",
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
		"Host is offline, regenerate user from old data": {
			sssdConf:  "sssd.conf-offline",
			initState: "old-data",
			// clean generate dconf dbs and privilege files to regenerate
			clearDirs: []string{
				"dconf/db/adsystestuser@example.com.d",
				"dconf/profile/adsystestuser@example.com",
				"run/users/1000",
				"apparmor.d/adsys/users",
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
		"Host is offline, sysvol cache is cleared, use user cache": {
			sssdConf:  "sssd.conf-offline",
			initState: "old-data",
			// clean sysvol cache, but keep machine ones and user policies
			clearDirs: []string{
				"dconf/db/adsystestuser@example.com.d",
				"dconf/profile/adsystestuser@example.com",
				"run/users/1000",
				"apparmor.d/adsys/users",
				"cache/sysvol/Policies/{5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242}",
				"cache/sysvol/Policies/{073AA7FC-5C1A-4A12-9AFC-42EC9C5CAF04}",
				"cache/sysvol/Policies/{75545F76-DEC2-4ADA-B7B8-D5209FD48727}",
				"cache/sysvol/assets",
				"cache/sysvol/assets.db",
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
		"Host is offline, get machine from cache (no update)": {
			args:      []string{"-m"},
			sssdConf:  "sssd.conf-offline",
			initState: "old-data",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "ccache_OFFLINE",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
		},
		"Host is offline, regenerate machine from old data": {
			args:      []string{"-m"},
			sssdConf:  "sssd.conf-offline",
			initState: "old-data",
			// clean generate dconf dbs and privilege files to regenerate
			clearDirs: []string{
				"dconf/db/machine.d",
				"dconf/profile/gdm",
				"sudoers.d",
				"polkit-1",
				"run/machine",
				"apparmor.d/adsys/machine",
				"systemd/system",
			},
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "ccache_OFFLINE",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
		},
		"Host is offline, mach gpos cache is cleared, with policies cache": {
			args:      []string{"-m"},
			sssdConf:  "sssd.conf-offline",
			initState: "old-data",
			// clean gpos for machine cache, but keep machine ones and user policies
			clearDirs: []string{
				"dconf/db/machine.d",
				"dconf/profile/gdm",
				"sudoers.d",
				"polkit-1",
				"run/machine",
				"apparmor.d/adsys/machine",
				"systemd/system",
				"cache/sysvol/Policies/{C4F393CA-AD9A-4595-AEBC-3FA6EE484285}",
				"cache/sysvol/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}",
			},
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          "ccache_OFFLINE",
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
			args:       []string{"userintegrationtest@example.com", "userintegrationtest@example.com.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "NonexistentTicket.krb5",
			krb5ccNamesState: []krb5ccNamesWithState{
				{src: "userintegrationtest@example.com.krb5"},
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

		// User options
		`Current user with domain\username`: {
			initState: "localhost-uptodate",
			args:      []string{`example.com\adsystestuser`, "adsystestuser@example.com.krb5"},
		},
		`Current user with default domain completion`: {
			initState: "localhost-uptodate",
			args:      []string{`adsystestuser`, "adsystestuser@example.com.krb5"},
		},

		// subscriptions
		"No subscription means dconf only": {
			systemAnswer: "subscription_disabled",
			args:         []string{"-m"},
			krb5ccname:   "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "ccache_EXAMPLE.COM",
					machine: true,
				},
			}},

		// Specific manager functionality
		"Does not error when D-Bus proxy object is not available": {
			args:       []string{"-m"},
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "ccache_EXAMPLE.COM",
					machine: true,
				},
			},
			initState:    "localhost-uptodate",
			systemAnswer: "no_proxy_object",
		},

		// Purge cases
		"Purge current user policies": {
			purge:     true,
			initState: "localhost-uptodate",
		},
		"Purge other user policies": {
			purge:     true,
			args:      []string{"userintegrationtest@example.com"},
			initState: "localhost-uptodate",
		},
		"Purge machine policies": {
			purge:     true,
			args:      []string{"-m"},
			initState: "localhost-uptodate",
		},
		"Purge policies for all cached objects": {args: []string{"--all"},
			purge:     true,
			initState: "old-data", // old-data state has cached policies for both user and machine
		},

		// Error cases
		"Error on applying user policies before updating the machine": {wantErr: true},
		"Error on Polkit denying updating self":                       {systemAnswer: "polkit_no", initState: "localhost-uptodate", wantErr: true},
		"Error on Polkit denying updating other":                      {systemAnswer: "polkit_no", args: []string{"userintegrationtest@example.com", "FIXME"}, initState: "localhost-uptodate", wantErr: true},
		"Error on Polkit denying updating machine":                    {systemAnswer: "polkit_no", args: []string{"-m"}, wantErr: true},
		"Error on dynamic AD returning nothing": {
			initState: "localhost-uptodate",
			sssdConf:  "sssd.conf-online_no_active_server",
			wantErr:   true,
		},
		"Error on dconf apply failing": {
			initState: "localhost-uptodate",
			// this generates an error when checking that a machine dconf is present
			clearDirs: []string{
				"dconf",
			},
			wantErr: true,
		},
		"Error on privilege apply failing": {
			args:       []string{"-m"},
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "ccache_EXAMPLE.COM",
					machine: true,
				},
			},
			initState: "localhost-uptodate",
			// this generates an error when parent directories are not writable
			readOnlyDirs: []string{
				"sudoers.d",
				"polkit-1",
			},
			wantErr: true,
		},
		"Error on user mount apply failing": {
			initState: "old-data",
			clearDirs: []string{
				fmt.Sprintf("run/users/%s/mounts", currentUID),
			},
			// This generates an error when the used path already exists as a directory instead of a file.
			addPaths: []string{
				fmt.Sprintf("run/users/%s/mounts/", currentUID),
			},
			wantErr: true,
		},
		"Error on system mount apply failing": {
			args:       []string{"-m"},
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "ccache_EXAMPLE.COM",
					machine: true,
				},
			},
			initState: "old-data",
			// This generates an error when trying to write the units into a read only directory.
			readOnlyDirs: []string{"systemd/system"},
			wantErr:      true,
		},
		"Error on apparmor apply failing": {
			args:       []string{"-m"},
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "ccache_EXAMPLE.COM",
					machine: true,
				},
			},
			initState: "localhost-uptodate",
			// this generates an error when dumping assets to machine.new
			readOnlyDirs: []string{"apparmor.d/adsys"},
			wantErr:      true,
		},
		"Error on system proxy apply failing": {
			args:       []string{"-m"},
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "ccache_EXAMPLE.COM",
					machine: true,
				},
			},
			initState:    "localhost-uptodate",
			systemAnswer: "apply_proxy_fail",
			wantErr:      true,
		},
		"Error on host is offline, without policies": {
			sssdConf:  "sssd.conf-offline",
			initState: "old-data",
			// clean gpos rules, but sysvol/ directory
			clearDirs: []string{
				"dconf/db/adsystestuser@example.com.d",
				"dconf/profile/adsystestuser@example.com",
				"sudoers.d",
				"polkit-1",
				"run",
				"cache/policies/adsystestuser@example.com",
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
		"Error on host is offline, without policies and backend is winbind": {
			backend:             "winbind",
			winbindMockBehavior: "domain_is_offline",
			initState:           "old-data",
			// clean gpos rules, but sysvol/ directory
			clearDirs: []string{
				"dconf/db/adsystestuser@example.com.d",
				"dconf/profile/adsystestuser@example.com",
				"sudoers.d",
				"polkit-1",
				"run",
				"cache/policies/adsystestuser@example.com",
			},
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:          currentUser + ".krb5",
					adsysSymlink: currentUser,
				},
				{
					src:          "/tmp/krb5cc_0",
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
			args:       []string{"userintegrationtest@example.com", "NonexistentTicket.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{src: "userintegrationtest@example.com.krb5"},
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
			args:       []string{"userintegrationtest@example.com", "userintegrationtest@example.com.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "userintegrationtest@example.com.krb5",
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
			args:       []string{"--all", "userintegrationtest@example.com", "userintegrationtest@example.com.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "userintegrationtest@example.com.krb5",
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
			args:       []string{"-m", "userintegrationtest@example.com", "userintegrationtest@example.com.krb5"},
			initState:  "localhost-uptodate",
			krb5ccname: "-",
			krb5ccNamesState: []krb5ccNamesWithState{
				{
					src:     "userintegrationtest@example.com.krb5",
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
					//src:          "userintegrationtest@example.com.krb5",
					adsysSymlink: "userintegrationtest@example.com",
				},
				{
					src:          "ccache_EXAMPLE.COM",
					adsysSymlink: hostname,
					machine:      true,
				},
			},
			wantErr: true,
		},
		"Error on unexisting user": {
			initState: "localhost-uptodate",
			args:      []string{"doesnotexists@example.com", "adsystestuser@example.com.krb5"},
			wantErr:   true,
		},
		"Error on user name without domain and no default domain": {
			initState: "localhost-uptodate",
			args:      []string{"doesnotexists", "adsystestuser@example.com.krb5"},
			wantErr:   true,
		},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.systemAnswer == "" {
				tc.systemAnswer = "polkit_yes"
			}
			dbusAnswer(t, tc.systemAnswer)
			testutils.PythonCoverageToGoFormat(t, filepath.Join(rootProjectDir, "internal/ad/adsys-gpolist"), true)

			adsysDir := t.TempDir()

			// Prepare initial state, renaming HOST file to current host
			if tc.initState != "" {
				// Copytree dest directory should not exists
				err = os.Remove(adsysDir)
				require.NoError(t, err, "Setup: could not remove adsysDir")
				err := shutil.CopyTree(filepath.Join(testutils.TestFamilyPath(t), "states", tc.initState), adsysDir, &shutil.CopyTreeOptions{CopyFunction: shutil.Copy})
				require.NoError(t, err, "Setup: could not copy initial state")

				// rename HOST and CURRENT_UID directory in destination:
				// CopyTree does not use its CopyFunction for directories.
				src := filepath.Join(adsysDir, "cache", "policies", "HOST")
				dst := strings.ReplaceAll(src, "HOST", hostname)
				require.NoError(t, os.Rename(src, dst), "Setup: can't renamed HOST directory to current hostname")

				src = filepath.Join(adsysDir, "run", "users", "CURRENT_UID")
				dst = strings.ReplaceAll(src, "CURRENT_UID", currentUID)
				if _, err := os.Stat(src); err == nil {
					require.NoError(t, os.Rename(src, dst),
						"Setup: can't rename current user directory to generic CURRENT_UID")
				}
			}

			if tc.backend == "" {
				tc.backend = "sssd"
			}

			t.Setenv("ADSYS_WBCLIENT_BEHAVIOR", tc.winbindMockBehavior)

			// Some tests will need some initial state assets
			for _, k := range tc.clearDirs {
				err := os.RemoveAll(filepath.Join(adsysDir, k))
				require.NoError(t, err, "Setup: could not remove generate assets db")
			}

			// Some tests will need some additional paths to be created
			for _, k := range tc.addPaths {
				testutils.CreatePath(t, adsysDir+"/"+k)
			}

			// Some tests will need read only dirs to create failures
			for _, k := range tc.readOnlyDirs {
				require.NoError(t, os.MkdirAll(filepath.Join(adsysDir, k), 0750), "Setup: could not create read only dir")
				testutils.MakeReadOnly(t, filepath.Join(adsysDir, k))
			}

			// Ticket creation for mock.
			krb5dir := t.TempDir()
			krb5ccDir := filepath.Join(adsysDir, "run", "krb5cc")
			err := os.MkdirAll(krb5ccDir, 0750)
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
					err := os.MkdirAll(krb5currentDir, 0750)
					require.NoError(t, err, "Setup: could not create machine sss cache")
				}
				var danglingSymlink bool
				if krb5.src != "" {
					if !filepath.IsAbs(krb5.src) {
						krb5.src = filepath.Join(krb5currentDir, krb5.src)
					}
					content := "Some data for the mock"
					if krb5.invalid {
						content = "Some invalid ticket content for the mock"
					}
					err := os.WriteFile(krb5.src, []byte(content), 0600)
					require.NoError(t, err, "Setup: Could not write ticket content")
				} else {
					// dangling symlink
					danglingSymlink = true
					krb5.src = "/some/unexisting/ticket"
				}

				if krb5.adsysSymlink == "" {
					continue
				}

				// Symlink ticket to krb5ccDir
				err = os.MkdirAll(filepath.Join(krb5ccDir, "tracking"), 0700)
				require.NoError(t, err, "Setup: could not create krb5 ticket directory")
				err = os.Symlink(krb5.src, filepath.Join(krb5ccDir, "tracking", krb5.adsysSymlink))
				require.NoError(t, err, "Setup: could not set krb5 file adsys symlink")

				if danglingSymlink {
					continue
				}

				// If our symlink is valid, make a copy of the ticket
				testutils.Copy(t, krb5.src, filepath.Join(krb5ccDir, krb5.adsysSymlink))
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
				t.Setenv("KRB5CCNAME", tc.krb5ccname)
			}

			conf := createConf(t, confWithAdsysDir(adsysDir), confWithBackend(tc.backend))
			if tc.sssdConf != "" {
				content, err := os.ReadFile(conf)
				require.NoError(t, err, "Setup: can’t read configuration file")
				content = bytes.Replace(content, []byte("testdata/sssd-configs/sssd.conf-example.com"),
					[]byte(fmt.Sprintf("testdata/sssd-configs/%s", tc.sssdConf)), 1)
				err = os.WriteFile(conf, content, 0600)
				require.NoError(t, err, "Setup: can’t rewrite configuration file")
			}
			defer runDaemon(t, conf)()

			action := "update"
			if tc.purge {
				action = "purge"
			}
			args := []string{"policy", action}
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

			goldenPath := testutils.GoldenPath(t)
			update := testutils.Update()
			testutils.CompareTreesWithFiltering(t, filepath.Join(adsysDir, "dconf"), filepath.Join(goldenPath, "dconf"), update)
			testutils.CompareTreesWithFiltering(t, filepath.Join(adsysDir, "sudoers.d"), filepath.Join(goldenPath, "sudoers.d"), update)
			testutils.CompareTreesWithFiltering(t, filepath.Join(adsysDir, "polkit-1"), filepath.Join(goldenPath, "polkit-1"), update)
			testutils.CompareTreesWithFiltering(t, filepath.Join(adsysDir, "apparmor.d", "adsys"), filepath.Join(goldenPath, "apparmor.d", "adsys"), update)
			testutils.CompareTreesWithFiltering(t, filepath.Join(adsysDir, "systemd", "system"), filepath.Join(goldenPath, "systemd", "system"), update)

			// Current user can have different UID depending on where it’s running. We can’t mock it as we rely on current uid
			// in the process for authorization check. Just make it generic.
			if _, err := os.Stat(filepath.Join(adsysDir, "run", "users", currentUID)); err == nil {
				require.NoError(t, os.Rename(filepath.Join(adsysDir, "run", "users", currentUID),
					filepath.Join(adsysDir, "run", "users", "CURRENT_UID")),
					"Setup: can't rename current user directory to generic CURRENT_UID")
			}

			testutils.CompareTreesWithFiltering(t, filepath.Join(adsysDir, "run", "users"), filepath.Join(goldenPath, "run", "users"), update)
			testutils.CompareTreesWithFiltering(t, filepath.Join(adsysDir, "run", "machine"), filepath.Join(goldenPath, "run", "machine"), update)
		})
	}
}

func TestPolicyDebugGPOListScript(t *testing.T) {
	gpolistSrc, err := os.ReadFile(filepath.Join(rootProjectDir, "internal/ad/adsys-gpolist"))
	require.NoError(t, err, "Setup: failed to load source of adsys-gpolist")

	tests := map[string]struct {
		systemAnswer     string
		daemonNotStarted bool

		wantErr bool
	}{
		"Get adsys-gpolist script":     {systemAnswer: "polkit_yes"},
		"Version is always authorized": {systemAnswer: "polkit_no"},

		"Error on daemon not responding": {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			dbusAnswer(t, tc.systemAnswer)

			conf := createConf(t)
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			testutils.Chdir(t, os.TempDir())

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
		_, err = d.Write([]byte(l + "\n"))
		require.NoError(t, err, "Setup: can’t write to passwd temp file")
	}
	require.NoError(t, scanner.Err(), "Setup: can't write temporary passwd file")

	for i, u := range users {
		_, err = d.Write([]byte(fmt.Sprintf("%s:x:%d:%s::/nonexistent:/usr/bin/false", u, i+23450, group)))
		require.NoError(t, err, "Setup: can’t write to passwd temp file")
	}

	return dest
}

// setupSubprocessForTest prepares a subprocess with a mock passwd file for running the tests.
// Returns false if we are already in the subprocess and should continue.
// Returns true if we prepare the subprocess and reexec ourself.
func setupSubprocessForTest(t *testing.T, currentUser string, otherUsers ...string) bool {
	t.Helper()

	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		// Restore for subprocess the socket to connect to system daemons
		for _, mode := range dbusAnswerModes {
			dbusSockets[mode] = os.Getenv("DBUS_SYSTEM_BUS_ADDRESS_" + strings.ToUpper(mode))
		}
		return false
	}

	err := exec.Command("pkg-config", "--exists", "nss_wrapper").Run()
	require.NoError(t, err, "libnss-wrapper is not installed on disk, either skip integration tests or install it")

	mockWinbindLibPath := testutils.BuildWinbindMock(t, filepath.Join(rootProjectDir, "internal/ad/backends/winbind"))

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

	// #nosec G204: this is only for tests, under controlled args
	cmd := exec.Command(subArgs[0], subArgs[1:]...)

	admock, err := filepath.Abs(filepath.Join(rootProjectDir, "internal/testutils/admock"))
	require.NoError(t, err, "Setup: Failed to get current absolute path for ad mock")

	passwd := modifyAndAddUsers(t, currentUser, otherUsers...)

	// Setup correct child environment, including LD_PRELOAD for nss mock
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",

		// mock for ad python samba code
		fmt.Sprintf("PYTHONPATH=%s", admock),

		// override user and host database
		fmt.Sprintf("LD_PRELOAD=libnss_wrapper.so:%s", mockWinbindLibPath),
		fmt.Sprintf("NSS_WRAPPER_PASSWD=%s", passwd),
		"NSS_WRAPPER_GROUP=/etc/group",
	)
	// dbus addresses to be reset in child
	for _, mode := range dbusAnswerModes {
		cmd.Env = append(cmd.Env, fmt.Sprintf("DBUS_SYSTEM_BUS_ADDRESS_%s=%s", strings.ToUpper(mode), dbusSockets[mode]))
	}

	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	if err != nil {
		t.Fail() // The real failure will be written by the child test process
	}

	return true
}
