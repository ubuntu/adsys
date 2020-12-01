package dconf

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies"
)

/*
	/etc/dconf/profile/<OBJECTNAME>
		user-db:user
		system-db:adsys_<OBJECTNAME>
		system-db:adsys_machine


	/etc/dconf/db/adsys_<OBJECTNAME>.d/
	/etc/dconf/db/adsys_<OBJECTNAME>.d/defaults
	/etc/dconf/db/adsys_<OBJECTNAME>.d/locks

	/etc/dconf/db/adsys_machine.d/
	/etc/dconf/db/adsys_machine.d/defaults
	/etc/dconf/db/adsys_machine.d/locks


*/

const (
	profilesPath = "/etc/dconf/profile"
	dbsPath      = "/etc/dconf/db"
)

// TODO:
//   - Make sure operations are as atomic as possible to prevent a policy
//     from being partially removed or applies.
//   - lock on users
//   - Make code testable
//   - dconf update (ensuring that machine has been applied before running any user)
//   	-> dconf update: don’t run when machine is updating
//   - String values
//   - Default values

// ApplyPolicy generates a dconf computer or user policy based on a list of entries
func ApplyPolicy(objectName string, isComputer bool, entries []policies.Entry) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("can't apply dconf policy: %v"), err)
		}
	}()

	if isComputer {
		objectName = "machine"
	}
	dbPath := filepath.Join(dbsPath, objectName+".d")

	if !isComputer {
		// Ensure the machine db is created as we will reference it from users
		if err := os.MkdirAll(filepath.Join(dbsPath, "machine.d", "locks"), 0744); err != nil {
			return err
		}
	}
	// Reset db path content
	if err := os.RemoveAll(filepath.Join(dbsPath, objectName)); err != nil {
		return err
	}
	if err := os.MkdirAll(dbPath, 0744); err != nil {
		return err
	}

	// Create profiles for users only
	if !isComputer {
		profilePath := filepath.Join(profilesPath, objectName)
		data := []byte(fmt.Sprintf(`
user-db:user
system-db:adsys_%s
system-db:adsys_machine
`, objectName))
		if err := ioutil.WriteFile(profilePath+".adsys.new", data, 0600); err != nil {
			return err
		}
		if err := os.Rename(profilePath+".adsys.new", profilePath); err != nil {
			return err
		}
	}

	// Generate defaults and locks content from policy
	defaults := make(map[string][]string)
	var locks []string
	for _, e := range entries {
		if !e.Disabled {
			section := filepath.Dir(e.Key)
			// FIXME: quotes for string, default Values
			l := fmt.Sprintf("%s=%s", filepath.Base(e.Key), e.Value)
			defaults[section] = append(defaults[section], l)
		}
		locks = append(locks, e.Key)
	}

	// Prepare file contents
	var dataDefaults []string
	for s, defs := range defaults {
		dataDefaults = append(dataDefaults, s)
		for _, def := range defs {
			dataDefaults = append(dataDefaults, def)
		}
	}
	var dataLocks []string
	for _, l := range locks {
		dataLocks = append(dataLocks, l)
	}

	// Commit on disk
	defaultPath := filepath.Join(dbPath, "defaults")
	if err := ioutil.WriteFile(defaultPath+".adsys.new", []byte(strings.Join(dataDefaults, "\n")), 0600); err != nil {
		return err
	}
	if err := os.Rename(defaultPath+".adsys.new", defaultPath); err != nil {
		return err
	}
	locksPath := filepath.Join(dbPath, "locks", "defaults")
	if err := ioutil.WriteFile(defaultPath+".adsys.new", []byte(strings.Join(dataLocks, "\n")), 0600); err != nil {
		return err
	}
	if err := os.Rename(locksPath+".adsys.new", locksPath); err != nil {
		return err
	}

	return nil
}
