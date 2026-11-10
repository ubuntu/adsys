package scripts_test

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/e2e/scripts"
)

func TestGDMUpgradeScenario(t *testing.T) {
	t.Parallel()

	dir, err := scripts.Dir()
	require.NoError(t, err)
	//nolint:gosec // G204 - The script path is derived from this repository's source, not user input.
	out, err := exec.Command("python3", "-B", filepath.Join(dir, "gdm_upgrade_test.py")).CombinedOutput()
	require.NoError(t, err, "GDM upgrade scenario tests: %s", out)
}
