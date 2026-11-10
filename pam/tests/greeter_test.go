package pamtest

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGreeterSession(t *testing.T) {
	t.Parallel()

	gcc, err := exec.LookPath("gcc")
	require.NoError(t, err)
	harness := filepath.Join(t.TempDir(), "greeter-harness")
	//nolint:gosec // G204 - gcc was resolved with LookPath; paths are fixed or test-owned.
	cmd := exec.Command(gcc, "-I..", "../testdata/greeter_harness.c", "-o", harness, "-lpam")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "building PAM harness: %s", output)

	tests := []struct {
		name     string
		username string
		group    string
		want     string
	}{
		{"static Ubuntu greeter", "gdm", "gdm", "1"},
		{"dynamic Ubuntu greeter", "gdm-greeter-12", "gdm", "1"},
		{"dynamic Debian greeter", "Debian-gdm-greeter-2", "Debian-gdm", "1"},
		{"local user", "alice", "users", "0"},
		{"AD user", "alice@example.com", "domain users", "0"},
		{"name alone is not enough", "gdm-greeter-12", "users", "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			//nolint:gosec // G204 - The executable was built above; arguments come from the test table.
			output, err := exec.Command(harness, tc.username, tc.group).CombinedOutput()
			require.NoError(t, err, "running PAM harness: %s", output)
			require.Equal(t, tc.want, strings.TrimSpace(string(output)))
		})
	}
}
