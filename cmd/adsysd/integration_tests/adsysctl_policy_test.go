package adsys_test

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/config"
)

func TestPolicyAdmx(t *testing.T) {
	tests := map[string]struct {
		arg              string
		distroOption     string
		polkitAnswer     string
		daemonNotStarted bool

		wantErr bool
	}{
		"LTS only content":               {arg: "lts-only", polkitAnswer: "yes"},
		"All supported releases content": {arg: "all", polkitAnswer: "yes"},

		"Accept distro option": {arg: "lts-only", distroOption: "Ubuntu", polkitAnswer: "yes"},

		"Need one valid argument": {polkitAnswer: "yes", wantErr: true},

		"Admx generation is always allowed": {arg: "lts-only", polkitAnswer: "no"},
		"Fail on non stored distro":         {arg: "lts-only", distroOption: "Tartanpion", polkitAnswer: "yes", wantErr: true},
		"Fail on invalid arg":               {arg: "something", polkitAnswer: "yes", wantErr: true},
		"Daemon not responding":             {arg: "lts-only", daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			polkitAnswer(t, tc.polkitAnswer)

			conf := createConf(t, "")
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}
			args := []string{"policy", "admx"}
			if tc.arg != "" {
				args = append(args, tc.arg)
			}
			distro := config.DistroID
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
		polkitAnswer      string
		daemonNotStarted  bool
		userGPORules      string
		noMachineGPORules bool

		wantErr bool
	}{
		"Current user applied gpos": {polkitAnswer: "yes"},
		// we use user "root" here as another user because the test user must exist on the machine for the authorizer.
		"Other user applied gpos":   {args: []string{"root"}, userGPORules: "root", polkitAnswer: "yes"},
		"Machine only applied gpos": {args: []string{hostname}, polkitAnswer: "yes"},

		"Detailed policy without override":               {args: []string{"--details"}, polkitAnswer: "yes"},
		"Detailed policy with overrides (all)":           {args: []string{"--all"}, polkitAnswer: "yes"},
		"Current user gpos no color":                     {args: []string{"--no-color"}, polkitAnswer: "yes"},
		"Detailed policy with overrides (all), no color": {args: []string{"--no-color", "--all"}, polkitAnswer: "yes"},

		// Error cases
		"Machine cache not available": {noMachineGPORules: true, polkitAnswer: "yes", wantErr: true},
		"User cache not available":    {userGPORules: "-", polkitAnswer: "yes", wantErr: true},
		"Applied denied":              {polkitAnswer: "no", wantErr: true},
		"Daemon not responding":       {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			polkitAnswer(t, tc.polkitAnswer)

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

			// // Compare golden files
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
	//prefix := testutils.CoverageToGoFormat(t, "../../../internal/policies/ad/adsys-gpolist")

	// update
	// no cache and no AD
	/*
		tests := map[string]struct {
			arg              string
			distroOption     string
			polkitAnswer     string
			daemonNotStarted bool

			wantErr bool
		}{
			"LTS only content":               {arg: "lts-only", polkitAnswer: "yes"},
			"All supported releases content": {arg: "all", polkitAnswer: "yes"},

			"Accept distro option": {arg: "lts-only", distroOption: "Ubuntu", polkitAnswer: "yes"},

			"Need one valid argument": {polkitAnswer: "yes", wantErr: true},

			"Admx generation denied":    {arg: "lts-only", polkitAnswer: "no"},
			"Fail on non stored distro": {arg: "lts-only", distroOption: "Tartanpion", polkitAnswer: "yes", wantErr: true},
			"Fail on invalid arg":       {arg: "something", polkitAnswer: "yes", wantErr: true},
			"Daemon not responding":     {arg: "lts-only", daemonNotStarted: true, wantErr: true},
		}
		for name, tc := range tests {
			tc := tc
			t.Run(name, func(t *testing.T) {
				defer polkitAnswer(t, tc.polkitAnswer)()
			})
		}
	*/
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
