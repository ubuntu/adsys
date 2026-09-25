// TiCS: disabled // Test helpers.

package testutils

import (
	"log"
	"os"
)

// IsolateDconfSystemProfiles points XDG_DATA_DIRS to an empty directory for the
// duration of the tests. Generated dconf profiles are seeded from the system
// profile they shadow, which would otherwise make the tests depend on the
// profiles installed on the host running them: a machine with GDM installed
// ships /usr/share/dconf/profile/gdm and would produce a different profile than
// a machine without it.
// It returns a function restoring the previous value.
func IsolateDconfSystemProfiles() func() {
	savedDataDirs, wasSet := os.LookupEnv("XDG_DATA_DIRS")

	dir, err := os.MkdirTemp("", "adsys-empty-xdg-data-dirs")
	if err != nil {
		log.Fatalf("couldn't create empty XDG data directory: %v", err)
	}
	if err := os.Setenv("XDG_DATA_DIRS", dir); err != nil {
		log.Fatalf("couldn't set XDG_DATA_DIRS: %v", err)
	}

	return func() {
		if err := os.RemoveAll(dir); err != nil {
			log.Fatalf("couldn't remove empty XDG data directory: %v", err)
		}

		if !wasSet {
			if err := os.Unsetenv("XDG_DATA_DIRS"); err != nil {
				log.Fatalf("couldn't unset XDG_DATA_DIRS: %v", err)
			}
			return
		}
		if err := os.Setenv("XDG_DATA_DIRS", savedDataDirs); err != nil {
			log.Fatalf("couldn't restore XDG_DATA_DIRS: %v", err)
		}
	}
}
