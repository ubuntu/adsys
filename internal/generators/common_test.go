package generators_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/generators"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestCleanDirectory(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	err := os.WriteFile(filepath.Join(d, "somefile"), []byte("some data in file"), 0600)
	require.NoError(t, err, "Setup: couldn’t create existing data in directory")

	err = generators.CleanDirectory(d)
	require.NoError(t, err, "CleanDirectory should be successful")

	content, err := os.ReadDir(d)
	require.NoError(t, err, "New cleaned directory should exists")

	require.Equal(t, 0, len(content), "Directory should be empty")
}

func TestCleanDirectoryNoDirectoryExists(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	err := os.RemoveAll(d)
	require.NoError(t, err, "Setup: couldn’t remove destination directory")

	err = generators.CleanDirectory(d)
	require.NoError(t, err, "CleanDirectory should be successful")

	content, err := os.ReadDir(d)
	require.NoError(t, err, "New cleaned directory should exists")

	require.Equal(t, 0, len(content), "Directory should be empty")
}

func TestCleanDirectoryCantRemoveDirectory(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	err := os.WriteFile(filepath.Join(d, "somefile"), []byte("some data in file"), 0600)
	require.NoError(t, err, "Setup: couldn’t create existing data in directory")
	err = os.Chmod(d, 0400)
	require.NoError(t, err, "Setup: couldn’t make directory read only")

	err = generators.CleanDirectory(d)
	require.Error(t, err, "CleanDirectory should error out")

	// nolint:gosec //false positive, this is a directory
	err = os.Chmod(d, 0700)
	require.NoError(t, err, "Teardown: chmod directory for cleanup")
}

func TestInstallOnlyMode(t *testing.T) {
	require.False(t, generators.InstallOnlyMode(), "No environment variable is no install only mode")

	testutils.Setenv(t, "GENERATE_ONLY_INSTALL_TO_DESTDIR", "/some/directory")
	require.True(t, generators.InstallOnlyMode(), "The environment variable trigger install only mode")
}

func TestDestDirectory(t *testing.T) {
	got := generators.DestDirectory("/fallback")
	require.Equal(t, "/fallback", got, "Fallback path received when no environment variable is available")

	testutils.Setenv(t, "GENERATE_ONLY_INSTALL_TO_DESTDIR", "/some/directory")
	got = generators.DestDirectory("/fallback")
	require.Equal(t, "/some/directory", got, "Environment varilable value takes precedence over fallback")
}
