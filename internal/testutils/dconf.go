// TiCS: disabled // Test helpers.

package testutils

import (
	"log"
	"os"
)

// IsolateDconfSystemProfiles points the dconf policy manager at an empty
// directory when it looks up the system profiles generated profiles are seeded
// from. Without it, the tests would depend on the profiles installed on the
// host running them: a machine with GDM installed ships
// /usr/share/dconf/profile/gdm and would produce a different profile than a
// machine without it.
// It returns a function restoring the previous value.
func IsolateDconfSystemProfiles() func() {
	// Keep in sync with profileDataDirsEnv in internal/policies/dconf.
	const profileDataDirsEnv = "ADSYS_TESTS_DCONF_PROFILE_DATA_DIRS"

	savedDataDirs, wasSet := os.LookupEnv(profileDataDirsEnv)

	dir, err := os.MkdirTemp("", "adsys-empty-dconf-profile-data-dir")
	if err != nil {
		log.Fatalf("couldn't create empty dconf profile data directory: %v", err)
	}
	if err := os.Setenv(profileDataDirsEnv, dir); err != nil {
		log.Fatalf("couldn't set %s: %v", profileDataDirsEnv, err)
	}

	return func() {
		if err := os.RemoveAll(dir); err != nil {
			log.Fatalf("couldn't remove empty dconf profile data directory: %v", err)
		}

		if !wasSet {
			if err := os.Unsetenv(profileDataDirsEnv); err != nil {
				log.Fatalf("couldn't unset %s: %v", profileDataDirsEnv, err)
			}
			return
		}
		if err := os.Setenv(profileDataDirsEnv, savedDataDirs); err != nil {
			log.Fatalf("couldn't restore %s: %v", profileDataDirsEnv, err)
		}
	}
}
