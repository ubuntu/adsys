package scripts_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/e2e/scripts"
	"github.com/ubuntu/adsys/internal/testutils"
)

// TestReleasePatchesApplyCleanly ensures that every per-release patch under
// e2e/scripts/patches still applies to the current debian/ packaging tree,
// using the exact patch invocation performed by e2e/scripts/build-deb.sh.
//
// These patches only ever touch debian/control and debian/rules, so this is a
// cheap, deterministic, network-free check: it does not build any package,
// it merely replays build-deb.sh's `patch` invocation against a scratch copy
// of debian/. If debian/control or debian/rules drift (e.g. a Build-Depends
// or Go toolchain change) without the patches being refreshed, this test
// fails instead of only surfacing the problem later inside a Docker-based
// e2e build.
func TestReleasePatchesApplyCleanly(t *testing.T) {
	// patch is part of the normal Ubuntu/build-essential environment already
	// relied upon by this repository (e.g. build-deb.sh itself requires it).
	// Fail loudly rather than skipping if it is missing, since silently
	// skipping would defeat the purpose of this check as a CI guard against
	// stale patch context.
	_, err := exec.LookPath("patch")
	require.NoError(t, err, "Setup: patch command not available")

	rootDir, err := scripts.RootDir()
	require.NoError(t, err, "Setup: could not determine repository root directory")

	patchesDir := filepath.Join(rootDir, "e2e", "scripts", "patches")
	entries, err := os.ReadDir(patchesDir)
	require.NoError(t, err, "Setup: could not list patches directory")

	var codenames []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".patch") {
			continue
		}
		codenames = append(codenames, strings.TrimSuffix(entry.Name(), ".patch"))
	}
	require.NotEmpty(t, codenames, "Setup: expected to find at least one release patch to validate")

	for _, codename := range codenames {
		t.Run(codename, func(t *testing.T) {
			// Only debian/ is patched, so limit the scratch copy to it to
			// keep this check cheap.
			workDir := t.TempDir()
			testutils.Copy(t, filepath.Join(rootDir, "debian"), filepath.Join(workDir, "debian"))

			patchData, err := os.ReadFile(filepath.Join(patchesDir, codename+".patch"))
			require.NoErrorf(t, err, "Setup: could not read patch for %s", codename)

			rejectedPath := filepath.Join(workDir, "rejected")
			// Mirror build-deb.sh verbatim:
			//   patch --ignore-whitespace --no-backup-if-mismatch -r /tmp/rejected -p1 < /patches/${codename}.patch
			// #nosec G204 -- fixed trusted binary, no user-controlled arguments
			cmd := exec.Command("patch", "--ignore-whitespace", "--no-backup-if-mismatch", "-r", rejectedPath, "-p1")
			cmd.Dir = workDir
			cmd.Stdin = bytes.NewReader(patchData)
			out, err := cmd.CombinedOutput()
			if err != nil {
				msg := string(out)
				if rejected, rerr := os.ReadFile(rejectedPath); rerr == nil {
					msg += "\nRejected hunks:\n" + string(rejected)
				}
				t.Fatalf("%s.patch no longer applies cleanly to debian/control and debian/rules - refresh it:\n%s", codename, msg)
			}
		})
	}
}
