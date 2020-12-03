package dconf

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/godbus/dbus"
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
	var errMsgs []string
	for _, e := range entries {
		if !e.Disabled {
			section := filepath.Dir(e.Key)

			// normalize common user error cases and check gsettings schema signature match.
			e.Value, err = normalizeValue(e.Meta, e.Value)
			if err != nil {
				errMsgs = append(errMsgs, fmt.Sprintf(i18n.G("- error on %s: %v"), e.Key, err))
				continue
			}
			if err := checkSignature(e.Meta, e.Value); err != nil {
				errMsgs = append(errMsgs, fmt.Sprintf(i18n.G("- error on %s: %v"), e.Key, err))
				continue
			}

			l := fmt.Sprintf("%s=%s", filepath.Base(e.Key), e.Value)
			dataWithGroups[section] = append(dataWithGroups[section], l)
		}
		locks = append(locks, e.Key)
	}

	// Stop on any error
	if errMsgs != nil {
		return errors.New(strings.Join(errMsgs, "\n"))
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

// normalizeValue simplify user entry by handling common mistakes on key types
func normalizeValue(keyType, value string) (string, error) {
	value = strings.TrimSpace(value)
	switch keyType {
	case "s":
		return quoteValue(value, "'", "'"), nil
	case "as":
		return quoteASVariant(value)
	case "ai":
		return quoteValue(value, "[", "]"), nil
	}

	return value, nil
}

// quoteValue ensures start is the first and end the last element of s.
// We will escape each non leading start and end character in s.
func quoteValue(s, start, end string) string {
	v := s
	if !strings.HasPrefix(s, start) {
		v = start + s
	}
	if !strings.HasSuffix(s, end) {
		v += end
	}
	// Escape start characters
	if len(v)-2 > 0 {
		// Don’t escape the first and last character we just added
		v = v[0:1] + strings.ReplaceAll(v[1:len(v)-2], start, `\`+start) + v[len(v)-1:]
	}
	// Escape end characters
	if end != start && len(v)-2 > 0 {
		v = v[0:1] + strings.ReplaceAll(v[1:len(v)-2], end, `\`+end) + v[len(v)-1:]
	}
	return v
}

// quoteASVariant returns an variant array of string properly quoted
func quoteASVariant(v string) (string, error) {
	orig := v
	v = strings.TrimRight(strings.TrimLeft(v, " ["), " ]")

	// Quoted string case
	if strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'") {
		// Remove leading/trailing quote and split on "','" (with optional spaces)
		v = strings.Trim(v, "'")
		re := regexp.MustCompile(`'\s*,\s*'`)
		t := re.Split(v, -1)

		// Look for unescaped ' by:
		// - join the whole string
		// - remove any escaped '
		// - check
		if strings.Contains(strings.Replace(strings.Join(t, ""), `\'`, "", -1), "'") {
			return "", fmt.Errorf(i18n.G("partially quoted string: %q"), orig)
		}
		var r []string
		for _, e := range t {
			r = append(r, quoteValue(e, "'", "'"))
		}
		return fmt.Sprintf("['%s']", strings.Join(t, "', '")), nil
	}

	// Unquoted string
	// Must split on "," but not on "\,"
	// Negative look behind is not supported in Go, so workaround by rejoining previous escaped element
	// https://github.com/google/re2/wiki/Syntax
	// Regex: `\s*(?<!\\),\s*`
	t := strings.Split(v, ",")
	// rebuild the slice, rejoining "\,"
	var tokens []string
	for i, e := range t {
		if i == 0 {
			tokens = append(tokens, e)
			continue
		}
		// If the previous element was escaped (counting the number of \), merge it.
		if strings.HasSuffix(t[i-1], `\`) && ((len(t[i-1])-len(strings.TrimRight(t[i-1], `\`)))%2 == 1) {
			tokens[len(tokens)-1] += "," + e
			continue
		}
		tokens = append(tokens, e)
	}
	var r []string
	for _, e := range tokens {
		r = append(r, quoteValue(strings.TrimSpace(e), "'", "'"))
	}

	if strings.Contains(strings.Replace(strings.Join(r, ","), `\'`, "", -1), "'") {
		return "", fmt.Errorf(i18n.G("partially quoted string: %q"), orig)
	}
	return fmt.Sprintf("[%s]", strings.Join(r, ", ")), nil
}

// checkSignature returns an error if the value doesn't match the expected variant signature
func checkSignature(meta, value string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("error while checking signature: %v"), err)
		}
	}()

	sig, err := dbus.ParseSignature(meta)
	if err != nil {
		return fmt.Errorf(i18n.G("%s is not a valid gsettings signature: %v"), meta, err)
	}
	_, err = dbus.ParseVariant(value, sig)
	if err != nil {
		return fmt.Errorf(i18n.G("can't parse %q as %q: %v"), value, meta, err)
	}

	return nil
}
