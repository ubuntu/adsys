package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateBaselinePackage(t *testing.T) {
	savedKey, savedPassword, savedBaseline := sshKey, adPassword, baselineDeb
	t.Cleanup(func() {
		sshKey, adPassword, baselineDeb = savedKey, savedPassword, savedBaseline
	})
	t.Setenv("AD_PASSWORD", "test-password")
	key := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(key, nil, 0600))

	for _, name := range []string{"adsys", "other-package", "malformed", "missing", "no baseline"} {
		t.Run(name, func(t *testing.T) {
			sshKey, baselineDeb = key, ""
			if name != "no baseline" {
				baselineDeb = filepath.Join(t.TempDir(), "baseline.deb")
				switch name {
				case "adsys", "other-package":
					source := t.TempDir()
					//nolint:gosec // G301 - dpkg-deb requires its control directory to be at least 0755.
					require.NoError(t, os.Mkdir(filepath.Join(source, "DEBIAN"), 0755))
					control := "Package: " + name + "\nVersion: 1\nArchitecture: all\n" +
						"Maintainer: Test <test@example.invalid>\nDescription: Test package\n"
					require.NoError(t, os.WriteFile(filepath.Join(source, "DEBIAN", "control"), []byte(control), 0600))
					//nolint:gosec // G204 - Both paths were created in this test's temporary directories.
					out, err := exec.Command("dpkg-deb", "--build", source, baselineDeb).CombinedOutput()
					require.NoError(t, err, "building baseline fixture: %s", out)
				case "malformed":
					require.NoError(t, os.WriteFile(baselineDeb, []byte("not a package"), 0600))
				}
			}
			err := validate(context.Background(), nil)
			if name == "adsys" || name == "no baseline" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
