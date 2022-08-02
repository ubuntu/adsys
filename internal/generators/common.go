// Package generators contains common helpers for generators
package generators

import (
	"fmt"
	"os"
	"os/exec"
)

const installVar = "GENERATE_ONLY_INSTALL_TO_DESTDIR"

// CleanDirectory removes a directory and recreates it.
func CleanDirectory(p string) error {
	if err := os.RemoveAll(p); err != nil {
		return fmt.Errorf("couldn't delete %q: %w", p, err)
	}
	if err := CreateDirectory(p, 0750); err != nil {
		return fmt.Errorf("couldn't create %q: %w", p, err)
	}
	return nil
}

// InstallOnlyMode returns if we only want to install and not affect current repository.
func InstallOnlyMode() bool {
	return os.Getenv(installVar) != ""
}

// DestDirectory returns the destination directory to generate to.
// It will prefer the adsys install directory if available, or will return path otherwise.
func DestDirectory(p string) string {
	installDir := os.Getenv(installVar)
	if installDir == "" {
		installDir = p
	}
	return installDir
}

// CreateDirectory creates a directory with the given permissions.
// If the directory already exists, it is left untouched.
// If the directory cannot be created, an error is returned.
//
// Prefer this way of creating directories instead of os.Mkdir as the latter
// could bypass fakeroot and cause unexpected confusion.
func CreateDirectory(dir string, perm uint32) error {
	// #nosec:G204 - we control the mode and directory we run mkdir on
	cmd := exec.Command("mkdir", "-m", fmt.Sprintf("%o", perm), "-p", dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Couldn't create dest directory: %v", string(output))
	}
	return nil
}
