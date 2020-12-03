package dconf

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/smbsafe"
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

// Manager prevents running multiple dconf update process in parallel while parsing policy in ApplyPolicy
type Manager struct {
	dconfMu sync.RWMutex
}

// ApplyPolicy generates a dconf computer or user policy based on a list of entries
func (m *Manager) ApplyPolicy(objectName string, isComputer bool, entries []policies.Entry, updateDconf bool) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("can't apply dconf policy: %v"), err)
		} else {
			// request an update now that we released the read lock
			// we will call update multiple times.
			smbsafe.WaitExec()
			m.dconfMu.Lock()
			out, errExec := exec.Command("dconf", "update").CombinedOutput()
			m.dconfMu.Unlock()
			smbsafe.DoneExec()
			if errExec != nil {
				err = fmt.Errorf(i18n.G("can't refresh dconf policy via dconf update: %v"), out)
			}
		}
	}()
	m.dconfMu.RLock()
	defer m.dconfMu.RUnlock()

	if isComputer {
		objectName = "machine"
	}
	dbPath := filepath.Join(dbsPath, objectName+".d")

	if !isComputer {
		if _, err := os.Stat(filepath.Join(dbsPath, "machine.d", "locks", "adsys")); err != nil {
			return fmt.Errorf(i18n.G("machine dconf database is required before generating a policy for an user. This one returns: %v"), err)
		}
	}

	// Create profiles for users only
	if !isComputer {
		if err := writeProfile(objectName, profilesPath); err != nil {
			return err
		}
	}

	// Generate defaults and locks content from policy
	dataWithGroups := make(map[string][]string)
	var locks []string
	for _, e := range entries {
		if !e.Disabled {
			section := filepath.Dir(e.Key)
			// FIXME: quotes for string, default Values
			l := fmt.Sprintf("%s=%s", filepath.Base(e.Key), e.Value)
			dataWithGroups[section] = append(dataWithGroups[section], l)
		}
		locks = append(locks, e.Key)
	}

	// Prepare file contents
	var data []string
	for s, defs := range dataWithGroups {
		data = append(data, s)
		for _, def := range defs {
			data = append(data, def)
		}
	}
	var dataLocks []string
	for _, l := range locks {
		dataLocks = append(dataLocks, l)
	}

	// Commit on disk
	defaultPath := filepath.Join(dbPath, "adsys")
	if err := ioutil.WriteFile(defaultPath+".new", []byte(strings.Join(data, "\n")), 0600); err != nil {
		return err
	}
	if err := os.Rename(defaultPath+".new", defaultPath); err != nil {
		return err
	}
	locksPath := filepath.Join(dbPath, "locks", "adsys")
	if err := ioutil.WriteFile(locksPath+".new", []byte(strings.Join(dataLocks, "\n")), 0600); err != nil {
		return err
	}
	if err := os.Rename(locksPath+".new", locksPath); err != nil {
		return err
	}
	return nil
}

// writeProfile creates or updates a dconf profile file.
func writeProfile(user, profilesPath string) error {
	profilePath := filepath.Join(profilesPath, user)
	endProfile := `system-db:%s
system-db:machine
`

	// Read existing content and create file if doesn’t exists
	content, err := ioutil.ReadFile(profilePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		return ioutil.WriteFile(profilePath, []byte(fmt.Sprintf(`user-db:user\n%s`, endProfile)), 0600)
	}

	// Is file already up to date?
	if bytes.HasSuffix(content, []byte(endProfile)) {
		return nil
	}

	// Otherwise, read the end, even if one of the entry is already anywhere in the file, we want them at the bottom
	// of the stack.
	content = append(content, []byte(endProfile)...)
	if err := ioutil.WriteFile(profilePath+".adsys.new", content, 0600); err != nil {
		return err
	}
	if err := os.Rename(profilePath+".adsys.new", profilePath); err != nil {
		return err
	}
	return nil
}
