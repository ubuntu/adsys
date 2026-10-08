package certificate_test

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVendoredSambaMatchesPatchSeries checks that the vendored Samba code is the
// upstream snapshot kept in .github/samba with the patch series from
// .github/samba/_patches applied on top.
//
// The "Patch vendored Samba code" workflow regenerates the vendored code exactly
// that way, so any local change not captured by a patch is reverted by the next
// automated update.
func TestVendoredSambaMatchesPatchSeries(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("patch"); err != nil {
		t.Skip("patch is not available on this system")
	}

	root := projectRoot(t)
	snapshot := filepath.Join(root, ".github", "samba")
	vendored := filepath.Join(root, "internal", "policies", "certificate", "python", "vendor_samba")

	work := t.TempDir()
	err := os.CopyFS(work, os.DirFS(filepath.Join(snapshot, "python", "samba")))
	require.NoError(t, err, "Setup: can't copy the upstream Samba snapshot")

	patches, err := filepath.Glob(filepath.Join(snapshot, "_patches", "*.patch"))
	require.NoError(t, err, "Setup: can't list the patch series")
	require.NotEmpty(t, patches, "Setup: the patch series is empty")

	var series bytes.Buffer
	for _, p := range patches {
		content, err := os.ReadFile(p)
		require.NoError(t, err, "Setup: can't read patch %s", p)
		series.Write(content)
	}

	// Patches address python/samba/... as the workflow does: strip that prefix
	// along with the a/ and b/ ones to apply them on the copied subtree.
	// #nosec G204: arguments are controlled by the test.
	cmd := exec.Command("patch", "-f", "-p3", "--no-backup-if-mismatch", "-d", work)
	cmd.Stdin = &series
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "The patch series should apply cleanly on the upstream snapshot:\n%s", out)

	want, got := readTree(t, work), readTree(t, vendored)
	for rel := range got {
		_, ok := want[rel]
		require.True(t, ok, "%s is vendored but is neither in the upstream snapshot nor added by the patch series", rel)
	}
	for rel, content := range want {
		require.Contains(t, got, rel, "%s is missing from the vendored code", rel)
		if content == got[rel] {
			continue
		}
		// #nosec G204: arguments are controlled by the test.
		diff, _ := exec.Command("diff", "-u", filepath.Join(work, rel), filepath.Join(vendored, rel)).CombinedOutput()
		t.Errorf("%s differs from the upstream snapshot with the patch series applied. Capture the change as a patch in .github/samba/_patches:\n%s", rel, diff)
	}
}

// readTree returns the content of every regular file under dir, keyed by its relative path.
func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()

	fsys := os.DirFS(dir)
	tree := make(map[string]string)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "__pycache__" {
				return fs.SkipDir
			}
			return nil
		}
		content, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		tree[path] = string(content)
		return nil
	})
	require.NoError(t, err, "Setup: can't read the files under %s", dir)

	return tree
}

// projectRoot returns the directory holding the go.mod file of the project.
func projectRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err, "Setup: can't get current directory")
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "Setup: can't find the project root from %s", dir)
		dir = parent
	}
}
