// Package privilege is the policy manager for privilege escalation entry types.
//
// This manager allows (and denies) privilege escalation on the client by configuring sudo and polkit
// files. In order to do that, it modifies 2 files (one for sudo and one for polkit) and their default
// locations are, respectively:
//   - /etc/sudoers.d/99-adsys-privilege-enforcement
//   - /etc/polkit-1/localauthority.conf.d/99-adsys-privilege-enforcement
//
// This is an all or nothing type of policy and, therefore, requires a lot of attention during setup.
// If the policy is setup improperly, users could end up with too much (or too little) privilege,
// which could compromise the safety and/or usability of the machine until the policy gets updated.
// If the policy is set without any value (or it's disabled) the files are removed and the default
// privilege configuration is restored.
// Should the manager fail to create the files with the requested values, it will return an error and
// authentication will be prevented.
package privilege

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/leonelquinteros/gotext"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/decorate"
	"gopkg.in/ini.v1"
)

/*
	Notes:
	privilege allows and deny privilege escalation on the client.

	It does so in modifying policykit and sudo files to override default distribution rules.

	This is all or nothing, similarly to the sudo policy files in most default distribution setup.

	We are modifying 2 files:
	- one for sudo, named 99-adsys-privilege-enforcement in sudoers.d
	- one under 00-adsys-privilege-enforcement.rules for policykit

	Both are installed under respective /etc directories.
*/

const (
	adsysBaseSudoersName = "99-adsys-privilege-enforcement"

	adsysOldPolkitName  = "99-adsys-privilege-enforcement"
	adsysBasePolkitName = "00-adsys-privilege-enforcement"

	polkitSystemReservedPath = "/usr/share/polkit-1"
)

// Templates to generate the polkit configuration files.
const (
	policyKitConfTemplate  = "%s[Configuration]\nAdminIdentities=%s"
	policyKitRulesTemplate = `%spolkit.addAdminRule(function(action, subject){
	return [%s];
});`
)

type option struct {
	policyKitSystemDir string
}

// Option is a functional option for the manager.
type Option func(*option)

// Manager prevents running multiple privilege update process in parallel while parsing policy in ApplyPolicy.
type Manager struct {
	sudoersDir   string
	policyKitDir string

	// This is for testing purposes only
	policyKitSystemDir string
}

// NewWithDirs creates a manager with a specific root directory.
func NewWithDirs(sudoersDir, policyKitDir string, opts ...Option) *Manager {
	o := &option{
		policyKitSystemDir: polkitSystemReservedPath,
	}
	for _, opt := range opts {
		opt(o)
	}

	return &Manager{
		sudoersDir:         sudoersDir,
		policyKitDir:       policyKitDir,
		policyKitSystemDir: o.policyKitSystemDir,
	}
}

// ApplyPolicy generates a privilege policy based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, gotext.Get("can't apply privilege policy to %s", objectName))

	// We only have privilege escalation on computers.
	if !isComputer {
		return nil
	}

	sudoersDir := m.sudoersDir
	if sudoersDir == "" {
		sudoersDir = consts.DefaultSudoersDir
	}
	sudoersConf := filepath.Join(sudoersDir, adsysBaseSudoersName)

	policyKitDir := m.policyKitDir
	if policyKitDir == "" {
		policyKitDir = consts.DefaultPolicyKitDir
	}
	policyKitConf := filepath.Join(policyKitDir, "rules.d", adsysBasePolkitName+".rules")

	// Polkit versions before 124 use a different directory for admin configuration and a different file extension and syntax
	var oldPolkit bool
	if oldPolkit = isOldPolkit(policyKitDir, m.policyKitSystemDir); oldPolkit {
		policyKitConf = filepath.Join(policyKitDir, "localauthority.conf.d", adsysOldPolkitName+".conf")
	}

	log.Debugf(ctx, "Applying privilege policy to %s", objectName)

	// We don’t create empty files if there is no entries. Still remove any previous version.
	if len(entries) == 0 {
		if err := os.Remove(sudoersConf); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := os.Remove(policyKitConf); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}

	// Create our temp files and parent directories
	// nolint:gosec // G301 match distribution permission
	if err := os.MkdirAll(filepath.Dir(sudoersConf), 0755); err != nil {
		return err
	}
	// nolint:gosec // G302 match distribution permission
	sudoersF, err := os.OpenFile(sudoersConf+".new", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0440)
	if err != nil {
		return err
	}
	defer sudoersF.Close()
	// nolint:gosec // G301 match distribution permission
	if err := os.MkdirAll(filepath.Dir(policyKitConf), 0755); err != nil {
		return err
	}
	// nolint:gosec // G302 match distribution permission
	policyKitConfF, err := os.OpenFile(policyKitConf+".new", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer policyKitConfF.Close()

	systemPolkitAdmins, err := m.getSystemPolkitAdminIdentities(ctx, policyKitDir, oldPolkit)
	if err != nil {
		return err
	}

	// Parse our rules and write to temp files
	var headerWritten bool
	header := `# This file is managed by adsys.
# Do not edit this file manually.
# Any changes will be overwritten.

`

	allowLocalAdmins := true
	var polkitAdditionalUsersGroups []string

	for _, entry := range entries {
		var contentSudo string

		if !headerWritten {
			contentSudo = header
		}

		switch entry.Key {
		case "allow-local-admins":
			allowLocalAdmins = !entry.Disabled
			if allowLocalAdmins {
				continue
			}
			contentSudo += "%admin	ALL=(ALL) !ALL\n"
			contentSudo += "%sudo	ALL=(ALL:ALL) !ALL\n"
		case "client-admins":
			if entry.Disabled {
				continue
			}

			var polkitElem []string
			for _, e := range splitAndNormalizeUsersAndGroups(ctx, entry.Value) {
				contentSudo += fmt.Sprintf("\"%s\"	ALL=(ALL:ALL) ALL\n", e)
				polkitID := fmt.Sprintf("unix-user:%s", e)
				if strings.HasPrefix(e, "%") {
					polkitID = fmt.Sprintf("unix-group:%s", strings.TrimPrefix(e, "%"))
				}
				polkitElem = append(polkitElem, polkitID)
			}
			if len(polkitElem) < 1 {
				continue
			}
			polkitAdditionalUsersGroups = polkitElem
		}

		// Write to our files
		if _, err := sudoersF.WriteString(contentSudo + "\n"); err != nil {
			return err
		}
		headerWritten = true
	}
	// PolicyKitConf files depends on multiple keys, so we need to write it at the end
	if !allowLocalAdmins || polkitAdditionalUsersGroups != nil {
		polkitTemplate := policyKitRulesTemplate
		sep := ","
		if oldPolkit {
			polkitTemplate = policyKitConfTemplate
			sep = ";"
		}

		// We need to write username between "" in the new format (Polkit version >= 124)
		if !oldPolkit {
			for i, user := range polkitAdditionalUsersGroups {
				polkitAdditionalUsersGroups[i] = fmt.Sprintf("\"%s\"", user)
			}
		}
		users := strings.Join(polkitAdditionalUsersGroups, sep)

		// We need to set system local admin here as we override the key from the previous file
		// otherwise, they will be disabled.
		if allowLocalAdmins {
			if systemPolkitAdmins != "" {
				systemPolkitAdmins += sep
			}
			users = systemPolkitAdmins + users
		}

		if _, err := policyKitConfF.WriteString(fmt.Sprintf(polkitTemplate, header, users) + "\n"); err != nil {
			return err
		}
	}

	// Move temp files to their final destination
	if err := os.Rename(sudoersConf+".new", sudoersConf); err != nil {
		return err
	}
	if err := os.Rename(policyKitConf+".new", policyKitConf); err != nil {
		return err
	}

	// If we applied the policy in the new format (Polkit version >= 124), we need to remove the old one
	if !oldPolkit {
		err := os.Remove(filepath.Join(policyKitDir, "localauthority.conf.d", adsysOldPolkitName+".conf"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Debug(ctx, gotext.Get("Failed to remove old polkit configuration file: %v", err))
		}
	}

	return nil
}

// splitAndNormalizeUsersAndGroups allow splitting on lines and ,.
// We remove any invalid characters and empty elements.
// All will have the form of user@domain.
func splitAndNormalizeUsersAndGroups(ctx context.Context, v string) []string {
	var elems []string
	elems = append(elems, strings.Split(v, "\n")...)
	v = strings.Join(elems, ",")
	elems = nil
	for _, e := range strings.Split(v, ",") {
		initialValue := e
		// Invalid chars in Windows user names: '/[]:|<>+=;,?*%"
		isgroup := strings.HasPrefix(e, "%")
		for _, c := range []string{"/", "[", "]", ":", "|", "<", ">", "=", ";", "?", "*", "%"} {
			e = strings.ReplaceAll(e, c, "")
		}
		if isgroup {
			e = "%" + e
		}

		// domain\user becomes user@domain
		ud := strings.SplitN(e, `\`, 2)
		if len(ud) == 2 {
			e = fmt.Sprintf("%s@%s", ud[1], ud[0])
			e = strings.ReplaceAll(e, `\`, "")
		}

		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if e != initialValue {
			log.Warningf(ctx, "Changed user or group %q to %q: Invalid characters or domain\\user format", initialValue, e)
		}
		elems = append(elems, e)
	}

	return elems
}

// getSystemPolkitAdminIdentities parses the system polkit configuration (based on its version) to get the
// list of admin identities.
func (m *Manager) getSystemPolkitAdminIdentities(ctx context.Context, policyKitDir string, oldPolkit bool) (adminIdentities string, err error) {
	if oldPolkit {
		return polkitAdminIdentitiesFromConf(ctx, policyKitDir)
	}
	return polkitAdminIdentitiesFromRules(ctx, []string{
		policyKitDir,
		m.policyKitSystemDir,
	})
}

// polkitAdminIdentitiesFromRules parses the polkit rules files to get the list of admin identities.
//
// Since polkit >= 124 now only cares about the first valid return, this function will sort the files from all the
// specified directories (priority: lesser ascii value, higher priority), parse them and identify the first valid return.
func polkitAdminIdentitiesFromRules(ctx context.Context, rulesDirPaths []string) (adminIdentities string, err error) {
	// Compile the regex needed to parse the polkit admin rules.
	// Matches: polkit.addAdminRule(function(action, subject){(.*)});
	adminRulesRegex, err := regexp.Compile(`polkit\.addAdminRule\s*\(\s*function\s*\(\s*action\s*\,\s*subject\s*\)\s*{\s*[^\}]*}\s*\)\s*\;`)
	if err != nil {
		return "", err
	}
	// Matches for: { return [(.*)] }
	returnRegex, err := regexp.Compile(`\{\s*return\s*\[(\s*([^\]]*))*\s*\]\s*;\s*\}`)
	if err != nil {
		return "", err
	}
	// Matches for: "someuser" or 'someuser'
	userRegex, err := regexp.Compile(`(["']+([^,]*)["']+)`)
	if err != nil {
		return "", err
	}

	var ruleFiles []string
	for _, path := range rulesDirPaths {
		files, err := filepath.Glob(filepath.Join(path, "rules.d", "*.rules"))
		if err != nil {
			return "", err
		}
		ruleFiles = append(ruleFiles, files...)
	}

	// Sort the files respecting the priority that Polkit assigns to them.
	slices.SortFunc(ruleFiles, func(i, j string) int {
		// If the files have different name, we return the one with the lowest ascii value.
		if order := strings.Compare(filepath.Base(i), filepath.Base(j)); order != 0 {
			return order
		}

		// If the files have the same name, we respect the directory priority in rulesDirPaths (lesser index, higher prio).
		var idxI, idxJ int
		for idx, dir := range rulesDirPaths {
			if strings.Contains(i, dir) {
				idxI = idx
			}
			if strings.Contains(j, dir) {
				idxJ = idx
			}
		}
		return idxI - idxJ
	})

	for _, path := range ruleFiles {
		if filepath.Base(path) == adsysBasePolkitName+".rules" {
			continue
		}

		b, err := os.ReadFile(path)
		if err != nil {
			pathErr := &os.PathError{}
			if errors.As(err, &pathErr) && pathErr.Op == "open" {
				// This means that we couldn't open the file for reading, likely due to permission errors.
				// If so, we can not ensure that we will match the expected admin identities from the system
				// and we should return an error.
				return "", err
			}
			// If we get an error when reading the file, it's likely due to it being a directory.
			// This case we can ignore and continue to the next file.
			log.Debug(ctx, gotext.Get("Ignoring %s: %v", path, err))
			continue
		}
		rules := string(b)

		// Check if the file contains the rule we are looking for
		if !strings.Contains(rules, "polkit.addAdminRule") {
			continue
		}

		for _, adminRule := range adminRulesRegex.FindAllString(rules, -1) {
			returnStmt := returnRegex.FindString(adminRule)
			if returnStmt == "" {
				continue
			}

			log.Debug(ctx, gotext.Get("Using polkit admin identities from %q", path))
			return strings.Join(userRegex.FindAllString(returnStmt, -1), ","), nil
		}
	}

	return adminIdentities, nil
}

// polkitAdminIdentitiesFromConf returns the list of configured system polkit admins as a string.
// It lists /etc/polkit-1/localauthority.conf.d and take the highest file in ascii order to match
// from the [configuration] section AdminIdentities value.
func polkitAdminIdentitiesFromConf(ctx context.Context, policyKitDir string) (adminIdentities string, err error) {
	defer decorate.OnError(&err, gotext.Get("can't get existing system polkit administrators in %s", policyKitDir))

	polkitConfFiles, err := filepath.Glob(filepath.Join(policyKitDir, "localauthority.conf.d", "*.conf"))
	if err != nil {
		return "", err
	}
	sort.Strings(polkitConfFiles)
	for _, p := range polkitConfFiles {
		fi, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		if fi.IsDir() {
			log.Warning(ctx, gotext.Get("%s is a directory. Ignoring.", p))
			continue
		}

		// Ignore ourself
		if filepath.Base(p) == adsysOldPolkitName+".conf" {
			continue
		}

		cfg, err := ini.LoadSources(ini.LoadOptions{IgnoreInlineComment: true}, p)
		if err != nil {
			return "", err
		}

		adminIdentities = cfg.Section("Configuration").Key("AdminIdentities").String()
	}

	return adminIdentities, nil
}

// isOldPolkit checks current polkit-1 configuration to determine if the current version < 124.
//
// To determine the version, we follow the steps:
//  1. If the old configuration directory does not exist or is empty -> version < 124.
//  2. If the old configuration directory only contains the adsys generated file -> version < 124.
//
// If the previous checks are valid, we still need to check if the new configuration file exists as the user
// could have installed the compatibility package (polkitd-pkla), which adds old configuration files even if
// the polkit version is >= 124.
func isOldPolkit(policyKitDir, policyKitReservedDir string) bool {
	dirEntries, err := os.ReadDir(filepath.Join(policyKitDir, "localauthority.conf.d"))
	nEntries := len(dirEntries)
	if err != nil || nEntries == 0 {
		return false
	}

	// If the directory only contains the adsys generated file, we can assume that the version is >= 124
	if nEntries == 1 && dirEntries[0].Name() == adsysOldPolkitName+".conf" {
		return false
	}

	// If the old directory isn't empty and there's no new configuration file, we can assume that the version is < 124.
	if _, err := os.Stat(filepath.Join(policyKitReservedDir, "rules.d/49-ubuntu-admin.rules")); err != nil {
		return true
	}

	// If the new configuration file exists but the old directory is not empty, it likely means that the user
	// installed the compatibility package (polkitd-pkla), but polkit version is still >= 124.
	return false
}
