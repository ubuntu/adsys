package dconf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
)

/*
	Notes:
	dconf applies default values and lock from bottom to top of the profile.
	It will stop to check values at the first corresponding lock layer it encounters.

	We always append to the profile the following dbs:
	system-db:<username>
	system-db:machine

	For common keys between user and machine:
	  1. Machine is not configured (no value, no lock) -> upper layers will be taken into account, which can be the user
	     one or user default value.

	  2. Machine is configured (value, and lock) -> the lock will "stick" our desired value and enforce it.

	  3. Machine configuration is set to deleted, conveying "I want the default value from the system" (no value, and lock)
	     -> the lock will "stick" the desired value to the layer of current value of Machine. As machine doesn’t have any
		 value and is the lowest in the stack (the first one to be processed), this will thus enforce the default system
		 configuration for that setting.
*/

// Manager prevents running multiple dconf update process in parallel while parsing policy in ApplyPolicy.
type Manager struct {
	dconfMu sync.RWMutex

	dconfDir string
}

// NewWithDconfDir creates a manager with a specific dconf directory.
func NewWithDconfDir(dir string) *Manager {
	return &Manager{dconfDir: dir}
}

// ApplyPolicy generates a dconf computer or user policy based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply dconf policy to %s"), objectName)

	dconfDir := m.dconfDir
	if dconfDir == "" {
		dconfDir = consts.DefaultDconfDir
	}

	m.dconfMu.RLock()

	log.Debugf(ctx, "Applying dconf policy to %s", objectName)

	if isComputer {
		objectName = "machine"
	}
	profilesPath := filepath.Join(dconfDir, "profile")
	dbsPath := filepath.Join(dconfDir, "db")
	dbPath := filepath.Join(dbsPath, objectName+".d")

	if !isComputer {
		if _, err := os.Stat(filepath.Join(dbsPath, "machine.d", "locks", "adsys")); err != nil {
			m.dconfMu.RUnlock()
			return fmt.Errorf(i18n.G("machine dconf database is required before generating a policy for an user. This one returns: %v"), err)
		}
	}

	// Create profiles for users only
	if !isComputer {
		// Profile must be readable by everyone
		// #nosec G301
		if err := os.MkdirAll(profilesPath, 0755); err != nil {
			m.dconfMu.RUnlock()
			return err
		}
		if err := writeProfile(ctx, objectName, profilesPath); err != nil {
			m.dconfMu.RUnlock()
			return err
		}
	}

	// Generate defaults and locks content from policy
	dataWithGroups := make(map[string][]string)
	var locks []string
	var errMsgs []string
	for _, e := range entries {
		log.Debugf(ctx, "Analyzing entry %+v", e)

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
		locks = append(locks, "/"+e.Key)
	}

	// Stop on any error
	if errMsgs != nil {
		m.dconfMu.RUnlock()
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
		data = append(data, dataWithGroups[s]...)
	}

	var needsRefresh bool

	// Commit on disk
	// Locks must be readable by everyone
	// #nosec G301
	if err := os.MkdirAll(filepath.Join(dbPath, "locks"), 0755); err != nil {
		m.dconfMu.RUnlock()
		return err
	}

	defaultPath := filepath.Join(dbPath, "adsys")
	changed, err := writeIfChanged(defaultPath, strings.Join(data, "\n")+"\n")
	if err != nil {
		m.dconfMu.RUnlock()
		return err
	}
	needsRefresh = needsRefresh || changed

	locksPath := filepath.Join(dbPath, "locks", "adsys")
	changed, err = writeIfChanged(locksPath, strings.Join(locks, "\n")+"\n")
	if err != nil {
		m.dconfMu.RUnlock()
		return err
	}
	needsRefresh = needsRefresh || changed

	m.dconfMu.RUnlock()

	// update if any profile changed, or if any compiled db is missing
	needsRefresh = needsRefresh || dconfNeedsUpdate(filepath.Join(dbsPath, "machine"))
	if !isComputer {
		needsRefresh = needsRefresh || dconfNeedsUpdate(filepath.Join(dbsPath, objectName))
	}
	if !needsRefresh {
		return nil
	}

	// request an update now that we released the read lock
	// we will call update multiple times.
	smbsafe.WaitExec()
	m.dconfMu.Lock()
	// #nosec G204 - we control the input
	out, errExec := exec.Command("dconf", "update", filepath.Join(dconfDir, "db")).CombinedOutput()
	m.dconfMu.Unlock()
	smbsafe.DoneExec()
	if errExec != nil {
		err = fmt.Errorf(i18n.G("dconf update failed: %v"), out)
	}

	return nil
}

// writeIfChanged will only write to path if content is different from current content.
func writeIfChanged(path string, content string) (done bool, err error) {
	defer decorate.OnError(&err, i18n.G("can't save %s"), path)

	if oldContent, err := os.ReadFile(path); err == nil && string(oldContent) == content {
		return false, nil
	}

	// #nosec G306. This asset needs to be world-readable.
	if err := os.WriteFile(path+".new", []byte(content), 0644); err != nil {
		return false, err
	}
	if err := os.Rename(path+".new", path); err != nil {
		return false, err
	}

	return true, nil
}

// writeProfile creates or updates a dconf profile file.
// The adsys systemd-db should always be the first systemd-db in the file to enforce their values
// (upper systemd-db in the profile wins).
func writeProfile(ctx context.Context, user, profilesPath string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't update user profile %s"), profilesPath)

	profilePath := filepath.Join(profilesPath, user)
	log.Debugf(ctx, "Update user profile %s", profilePath)

	adsysMachineDB := "system-db:machine"
	adsysUserDB := fmt.Sprintf("system-db:%s", user)

	// Read existing content and create file if doesn’t exists
	content, err := os.ReadFile(profilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		// #nosec G306. This asset needs to be world-readable.
		return os.WriteFile(profilePath, []byte(fmt.Sprintf("user-db:user\n%s\n%s", adsysUserDB, adsysMachineDB)), 0644)
	}

	// Read file to insert them at the end, removing duplicates
	var out []string
	for _, d := range bytes.Split(bytes.TrimSpace(content), []byte("\n")) {
		// Add current line if it’s not an adsys one
		if string(d) == adsysMachineDB || string(d) == adsysUserDB {
			continue
		}
		out = append(out, string(d))
	}
	out = append(out, adsysUserDB, adsysMachineDB)

	newContent := []byte(strings.Join(out, "\n"))

	// Is file already up to date?
	if string(content) == string(newContent) {
		return nil
	}

	// Otherwise, update the file.
	// #nosec G306. This asset needs to be world-readable.
	if err := os.WriteFile(profilePath+".adsys.new", newContent, 0644); err != nil {
		return err
	}
	if err := os.Rename(profilePath+".adsys.new", profilePath); err != nil {
		return err
	}
	return nil
}

// dconfNeedsUpdate will notify if we need to run dconf update for that binary database.
// For now, it only checks its existence.
func dconfNeedsUpdate(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return true
	}

	return false
}

// normalizeValue simplify user entry by handling common mistakes on key types.
func normalizeValue(keyType, value string) string {
	value = strings.TrimSpace(value)
	switch keyType {
	case "s":
		return quoteValue(value)
	case "b":
		return normalizeBoolean(value)
	case "i":
		return strings.ReplaceAll(strings.ReplaceAll(value, `"`, ""), "'", "")
	case "as":
		return quoteASVariant(value)
	case "ai":
		return normalizeAIVariant(value)
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
// on|On|ON|off.
func normalizeBoolean(v string) string {
	lv := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(strings.ToLower(v)), `"`, ""), "'", "")
	switch lv {
	case "y", "yes", "true", "on":
		return "true"
	case "n", "no", "false", "off":
		return "false"
	}
	return v
}

// quoteASVariant returns a variant array of string properly quoted and separated.
func quoteASVariant(v string) string {
	v = strings.TrimRight(strings.TrimLeft(v, " ["), " ]")

	// Remove any empty \n elements
	var elems []string
	for _, e := range strings.Split(v, "\n") {
		if strings.TrimSpace(e) == "" {
			continue
		}
		elems = append(elems, e)
	}
	v = strings.Join(elems, ",")

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

// normalizeAIVariant returns a variant array of int with proper separator.
func normalizeAIVariant(v string) string {
	v = strings.TrimRight(strings.TrimLeft(v, " ["), " ]")

	// Remove any empty \n elements
	var elems []string

	for _, e := range strings.Split(v, "\n") {
		if strings.TrimSpace(e) == "" {
			continue
		}
		elems = append(elems, e)
	}

	// normalize separator spaces
	v = strings.Join(elems, ",")
	v = strings.ReplaceAll(strings.ReplaceAll(v, " ", ""), ",", ", ")

	return fmt.Sprintf("[%s]", v)
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

// checkSignature returns an error if the value doesn't match the expected variant signature.
func checkSignature(meta, value string) (err error) {
	defer decorate.OnError(&err, i18n.G("error while checking signature"))

	if meta == "" {
		return fmt.Errorf(i18n.G("empty signature for %v"), meta)
	}

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
