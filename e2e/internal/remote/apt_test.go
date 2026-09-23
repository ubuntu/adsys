//go:build !windows

package remote

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestQuiesceAPTLeavesActiveUpgradeAlone(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, unit := range []string{"apt-daily.timer", "apt-daily-upgrade.timer", "dpkg-running"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, unit), nil, 0600))
	}
	const host = `systemctl() {
    shift 2
    for unit do
        case "$unit" in
            *.timer) rm -- "$unit" ;;
            apt-daily-upgrade.service) rm -- dpkg-running ;;
        esac
    done
}
tee() { cat > apt.conf; }
`
	// #nosec G204 -- Both shell snippets are fixed source constants.
	cmd := exec.CommandContext(t.Context(), "sh", "-c", host+fmt.Sprintf(quiesceAPTScript, ""))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	require.NoFileExists(t, filepath.Join(dir, "apt-daily.timer"))
	require.NoFileExists(t, filepath.Join(dir, "apt-daily-upgrade.timer"))
	require.FileExists(t, filepath.Join(dir, "dpkg-running"))
	config, err := os.ReadFile(filepath.Join(dir, "apt.conf"))
	require.NoError(t, err)
	require.Contains(t, string(config), `APT::Periodic::Enable "0";`)
	require.Contains(t, string(config), `DPkg::Lock::Timeout "600";`)
}

func TestAPTUpdateCmd(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, user string
		failures   int
		wantExit   int
		wantEvents string
	}{
		{name: "immediate success as root", user: "root", wantEvents: "update\ninstall\n"},
		{name: "recovery through sudo", user: "azureuser", failures: 2, wantEvents: "sudo\nupdate\nsleep\nsudo\nupdate\nsleep\nsudo\nupdate\ninstall\n"},
		{name: "exhaustion skips install", user: "root", failures: 10, wantExit: 1, wantEvents: strings.Repeat("update\nsleep\n", 9) + "update\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			const aptGet = `#!/bin/sh
[ "$*" = "-y update" ] || exit 2
printf 'update\n' >> events
attempts=$(grep -c '^update$' events)
[ "$attempts" -gt "$FAILURES" ]
`
			// #nosec G306 -- The private apt-get fixture must be executable.
			require.NoError(t, os.WriteFile(filepath.Join(dir, "apt-get"), []byte(aptGet), 0700))
			const host = `sudo() { printf 'sudo\n' >> events; "$@"; }
sleep() { printf 'sleep\n' >> events; }
`
			c := Client{config: &ssh.ClientConfig{User: tc.user}}
			// #nosec G204 -- Run the update command against the private apt-get fixture.
			cmd := exec.CommandContext(t.Context(), "sh", "-c", host+c.APTUpdateCmd()+" && printf 'install\\n' >> events")
			cmd.Dir = dir
			cmd.Env = append(cmd.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), fmt.Sprintf("FAILURES=%d", tc.failures))
			out, err := cmd.CombinedOutput()
			if tc.wantExit == 0 {
				require.NoError(t, err, "%s", out)
			} else {
				var exit *exec.ExitError
				require.ErrorAs(t, err, &exit, "%s", out)
				require.Equal(t, tc.wantExit, exit.ExitCode(), "%s", out)
			}
			events, err := os.ReadFile(filepath.Join(dir, "events"))
			require.NoError(t, err)
			require.Equal(t, tc.wantEvents, string(events))
		})
	}
}
