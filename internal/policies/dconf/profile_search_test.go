package dconf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProfileSearchDirs(t *testing.T) {
	configuredDir := filepath.Join(t.TempDir(), "share")
	overrideDir := filepath.Join(t.TempDir(), "override")

	tests := []struct {
		name         string
		xdgDataDirs  string
		testOverride *string

		want []string
	}{
		{
			name: "Defaults are used when XDG_DATA_DIRS is empty",
			want: []string{"/usr/local/share", "/usr/share"},
		},
		{
			name:        "Defaults are searched after the configured directories",
			xdgDataDirs: configuredDir + string(os.PathListSeparator) + "/usr/share",
			want:        []string{configuredDir, "/usr/share", "/usr/local/share"},
		},
		{
			name:        "Trailing separators don't duplicate the defaults",
			xdgDataDirs: "/usr/share/" + string(os.PathListSeparator) + "/usr/local/share/",
			want:        []string{"/usr/share", "/usr/local/share"},
		},
		{
			name:         "Test override replaces the search path entirely",
			xdgDataDirs:  configuredDir,
			testOverride: &overrideDir,
			want:         []string{overrideDir},
		},
		{
			name:         "Empty test override searches nothing",
			xdgDataDirs:  configuredDir,
			testOverride: new(string),
			want:         []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_DIRS", tc.xdgDataDirs)
			if tc.testOverride != nil {
				t.Setenv(profileDataDirsEnv, *tc.testOverride)
			} else {
				unsetEnv(t, profileDataDirsEnv)
			}

			manager := &Manager{}
			require.Equal(t, tc.want, manager.profileSearchDirs())
		})
	}
}

func TestProfileSearchDirsUsesConfiguredDirs(t *testing.T) {
	t.Setenv("XDG_DATA_DIRS", filepath.Join(t.TempDir(), "share"))
	t.Setenv(profileDataDirsEnv, filepath.Join(t.TempDir(), "override"))

	configuredDir := filepath.Join(t.TempDir(), "configured")
	manager := newWithDconfDirAndProfileDataDirs("", []string{configuredDir})
	require.Equal(t, []string{configuredDir}, manager.profileSearchDirs())
}

// unsetEnv removes key from the environment for the duration of the test.
func unsetEnv(t *testing.T, key string) {
	t.Helper()

	value, wasSet := os.LookupEnv(key)
	require.NoError(t, os.Unsetenv(key), "Setup: can't unset %s", key)
	if !wasSet {
		return
	}
	t.Cleanup(func() {
		require.NoError(t, os.Setenv(key, value), "Teardown: can't restore %s", key)
	})
}
