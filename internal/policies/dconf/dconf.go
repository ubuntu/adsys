package dconf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
)

// Manager prevents running multiple dconf update process in parallel while parsing policy in ApplyPolicy
type Manager struct {
	dconfMu sync.RWMutex

	dconfDir string
}

// ApplyPolicy generates a dconf computer or user policy based on a list of entries
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry) (err error) {
	dconfDir := m.dconfDir
	if dconfDir == "" {
		dconfDir = "/etc/dconf"
	}

	defer func() {
		if err == nil {
			// request an update now that we released the read lock
			// we will call update multiple times.
			smbsafe.WaitExec()
			m.dconfMu.Lock()
			out, errExec := exec.Command("dconf", "update", filepath.Join(dconfDir, "db")).CombinedOutput()
			m.dconfMu.Unlock()
			smbsafe.DoneExec()
			if errExec != nil {
				err = fmt.Errorf(i18n.G("can't refresh dconf policy via dconf update: %v"), out)
			}
		}
		if err != nil {
			err = fmt.Errorf(i18n.G("can't apply dconf policy: %v"), err)
		}
	}()
	m.dconfMu.RLock()
	defer m.dconfMu.RUnlock()

	log.Debugf(ctx, "ApplyPolicy dconf policy to %s", objectName)

	if isComputer {
		objectName = "machine"
	}
	profilesPath := filepath.Join(dconfDir, "profile")
	dbsPath := filepath.Join(dconfDir, "db")
	dbPath := filepath.Join(dbsPath, objectName+".d")

	if !isComputer {
		if _, err := os.Stat(filepath.Join(dbsPath, "machine.d", "locks", "adsys")); err != nil {
			return fmt.Errorf(i18n.G("machine dconf database is required before generating a policy for an user. This one returns: %v"), err)
		}
	}

	// Create profiles for users only
	if !isComputer {
		if err := os.MkdirAll(profilesPath, 0755); err != nil {
			return err
		}
		if err := writeProfile(ctx, objectName, profilesPath); err != nil {
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
			e.Value = normalizeValue(e.Meta, e.Value)
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
	// Order sections to have a reliable output
	var data []string
	sections := make([]string, 0, len(dataWithGroups))
	for s := range dataWithGroups {
		sections = append(sections, s)
	}
	sort.Strings(sections)
	for _, s := range sections {
		data = append(data, fmt.Sprintf("[%s]", s))
		for _, def := range dataWithGroups[s] {
			data = append(data, def)
		}
	}

	var dataLocks []string
	for _, l := range locks {
		dataLocks = append(dataLocks, l)
	}

	// Commit on disk
	if err := os.MkdirAll(filepath.Join(dbPath, "locks"), 0755); err != nil {
		return err
	}
	defaultPath := filepath.Join(dbPath, "adsys")
	if err := ioutil.WriteFile(defaultPath+".new", []byte(strings.Join(data, "\n")+"\n"), 0600); err != nil {
		return err
	}
	if err := os.Rename(defaultPath+".new", defaultPath); err != nil {
		return err
	}
	locksPath := filepath.Join(dbPath, "locks", "adsys")
	if err := ioutil.WriteFile(locksPath+".new", []byte(strings.Join(dataLocks, "\n")+"\n"), 0600); err != nil {
		return err
	}
	if err := os.Rename(locksPath+".new", locksPath); err != nil {
		return err
	}
	return nil
}

// writeProfile creates or updates a dconf profile file.
// The adsys systemd-db should always be the first systemd-db in the file to enforce their values
// (upper systemd-db in the profile wins).
func writeProfile(ctx context.Context, user, profilesPath string) error {
	profilePath := filepath.Join(profilesPath, user)
	log.Debugf(ctx, "Update user profile %s", profilePath)

	adsysMachineDB := "system-db:machine"
	adsysUserDB := fmt.Sprintf("system-db:%s", user)

	// Read existing content and create file if doesn’t exists
	content, err := ioutil.ReadFile(profilePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		return ioutil.WriteFile(profilePath, []byte(fmt.Sprintf("user-db:user\n%s\n%s", adsysMachineDB, adsysUserDB)), 0644)
	}

	// Read file to insert after first user-db group
	var insertsDone bool
	var out []string
	for _, d := range bytes.Split(content, []byte("\n")) {
		if insertsDone {
			if string(d) == adsysMachineDB || string(d) == adsysUserDB {
				continue
			}
			out = append(out, string(d))
			continue
		}
		if bytes.HasPrefix(d, []byte("user-db:")) {
			out = append(out, string(d))
			continue
		}
		out = append(out, adsysMachineDB)
		out = append(out, adsysUserDB)
		insertsDone = true
		// Add current line if it’s not an adsys one
		if string(d) == adsysMachineDB || string(d) == adsysUserDB {
			continue
		}
		out = append(out, string(d))
	}

	newContent := []byte(strings.Join(out, "\n"))

	// Is file already up to date?
	if string(content) == string(newContent) {
		return nil
	}

	// Otherwise, update the file.
	if err := ioutil.WriteFile(profilePath+".adsys.new", newContent, 0600); err != nil {
		return err
	}
	if err := os.Rename(profilePath+".adsys.new", profilePath); err != nil {
		return err
	}
	return nil
}

// normalizeValue simplify user entry by handling common mistakes on key types
func normalizeValue(keyType, value string) string {
	value = strings.TrimSpace(value)
	switch keyType {
	case "s":
		return quoteValue(value)
	case "b":
		return normalizeBoolean(value)
	case "as":
		return quoteASVariant(value)
	case "ai":
		value = strings.TrimSpace(value)
		if !strings.HasPrefix(value, "[") {
			value = "[" + value
		}
		if !strings.HasSuffix(value, "]") {
			value += "]"
		}
		return strings.Replace(strings.Replace(value, " ", "", -1), ",", ", ", -1)
	}

	return value
}

// quoteValue ensures the string starts and ends with ' in s.
// We will escape each non leading character in s.
func quoteValue(s string) string {
	// quote automatically single quote
	if s == "'" {
		s = `'''`
	} else if s == `\'` {
		s = `'\''`
	}

	s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "'"), "'")
	return fmt.Sprintf("'%s'", strings.Join(splitOnNonEscaped(s, "'"), `\'`))
}

// normalizeBoolean will try to convert any value to false/true to be compatible with dconf.
// The following is accepted, is case insensitive and spaces are trimmed:
// y|yes|n|no
// true|false
// on|On|ON|off
func normalizeBoolean(v string) string {
	lv := strings.TrimSpace(strings.ToLower(v))
	switch lv {
	case "y", "yes", "true", "on":
		return "true"
	case "n", "no", "false", "off":
		return "false"
	}
	return v
}

// quoteASVariant returns an variant array of string properly quoted
func quoteASVariant(v string) string {
	//orig := v
	v = strings.TrimRight(strings.TrimLeft(v, " ["), " ]")

	// Quoted string case
	if strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'") {
		// Remove leading/trailing quote and split on "','" (with optional spaces)
		v = strings.Trim(v, "'")
		re := regexp.MustCompile(`'\s*,\s*'`)
		t := re.Split(v, -1)

		var r []string
		for _, e := range t {
			r = append(r, quoteValue(e))
		}
		return fmt.Sprintf("[%s]", strings.Join(r, ", "))
	}

	// Unquoted string
	// Must split on "," but not on "\,"
	// Negative look behind is not supported in Go, so workaround by rejoining previous escaped element
	// https://github.com/google/re2/wiki/Syntax
	// Regex: `\s*(?<!\\),\s*`
	var r []string
	for _, e := range splitOnNonEscaped(v, ",") {
		e = fmt.Sprintf("'%s'", strings.TrimSpace(e))
		r = append(r, quoteValue(e))
	}

	return fmt.Sprintf("[%s]", strings.Join(r, ", "))
}

// splitOnNonEscaped splits v by sep, only if sep is not escaped.
func splitOnNonEscaped(v, sep string) []string {
	t := strings.Split(v, sep)
	// rebuild the slice, rejoining "\,"
	var tokens []string
	for i, e := range t {
		if i == 0 {
			tokens = append(tokens, e)
			continue
		}
		// If the previous element was escaped (counting the number of \), merge it.
		if strings.HasSuffix(t[i-1], `\`) && ((len(t[i-1])-len(strings.TrimRight(t[i-1], `\`)))%2 == 1) {
			tokens[len(tokens)-1] += sep + e
			continue
		}
		tokens = append(tokens, e)
	}
	return tokens
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
