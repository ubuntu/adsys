// Package mount implements the manager responsible to handle the file sharing
// policy of adsys, parsing the GPO rules and setting up the mount process for
// the requested drives. User mounts will be handled by a systemd user service and
// computer mounts will be handled directly by systemd, via mount units.
package mount

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/coreos/go-systemd/unit"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
)

/*

The mount policy for adsys works as follows:

Should the manager fail to setup the policy with the requested entries and its values,
an error will be returned and the login is prevented.

However, if the manager creates the files needed and setup all the required steps,
it's up to the correctness of the specified entries values and gvfs to mount the
requested shared drives. Should an error occur during this step, adsys will log it
without preventing the authentication.

*/

type options struct {
	systemctlCmd  []string
	userLookup    func(string) (*user.User, error)
	systemUnitDir string
}

// Option represents an optional function that is able to alter a default behavior used in mount.
type Option func(*options)

//go:embed adsys-mount-template.mount
var unitTemplate string

// Manager holds information needed for handling the mount policies.
type Manager struct {
	mountsMu map[string]*sync.Mutex
	muMu     sync.Mutex

	runDir        string
	systemUnitDir string

	userLookup   func(string) (*user.User, error)
	systemCtlCmd []string
}

// New creates a Manager to handle mount policies.
func New(runDir string, systemUnitDir string, opts ...Option) (m *Manager, err error) {
	defer decorate.OnError(&err, i18n.G("failed to create new mount manager"))
	o := options{
		userLookup:    user.Lookup,
		systemUnitDir: systemUnitDir,
		systemctlCmd:  []string{"systemctl"},
	}

	for _, opt := range opts {
		opt(&o)
	}

	// Multiple users will be in users/ subdirectory. Create the main one.
	// #nosec G301 - multiple users will be in users/ subdirectory, we want all of them to be able to access its own subdirectory.
	if err := os.MkdirAll(filepath.Join(runDir, "users"), 0750); err != nil {
		return nil, err
	}

	// This creates the specified systemUnitDir if it does not exist already.
	// This is mostly used when setting up a custom dir for the units, as the
	// default value is the systemd directory and it is supposed to always be
	// there on linux systems.
	// #nosec G301 - /etc/systemd/system permissions are 0755, so we should keep the same pattern.
	if err := os.MkdirAll(systemUnitDir, 0755); err != nil {
		return nil, err
	}

	return &Manager{
		mountsMu: make(map[string]*sync.Mutex),

		runDir:        runDir,
		userLookup:    o.userLookup,
		systemCtlCmd:  o.systemctlCmd,
		systemUnitDir: systemUnitDir,
	}, nil
}

// ApplyPolicy generates mount policies based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply mount policy to %s"), objectName)

	log.Debugf(ctx, "Applying mount policy to %s", objectName)

	// Mutexes are per user1, user2, computer
	m.muMu.Lock()
	if _, exists := m.mountsMu[objectName]; !exists {
		m.mountsMu[objectName] = &sync.Mutex{}
	}
	m.muMu.Unlock()
	m.mountsMu[objectName].Lock()
	defer m.mountsMu[objectName].Unlock()

	if len(entries) == 0 {
		if err := m.cleanup(ctx, objectName, isComputer); err != nil {
			return err
		}
		return nil
	}

	if !isComputer {
		for _, entry := range entries {
			switch entry.Key {
			case "user-mounts":
				if e := m.applyUserMountsPolicy(ctx, objectName, entry); e != nil {
					err = e
				}

			default:
				log.Debugf(ctx, "Key %q is currently not supported by the mount manager", entry.Key)
			}
		}
	} else {
		for _, entry := range entries {
			switch entry.Key {
			case "system-mounts":
				if e := m.applySystemMountsPolicy(ctx, objectName, entry); e != nil {
					err = e
				}
			default:
				log.Debugf(ctx, "Key %q is currently not supported by the mount manager", entry.Key)
			}
		}
	}

	return err
}

func (m *Manager) applyUserMountsPolicy(ctx context.Context, username string, entry entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to apply policy for user %q"), username)

	log.Debugf(ctx, "Applying mount policy to user %q", username)

	var uid, gid int
	u, err := m.userLookup(username)
	if err != nil {
		return fmt.Errorf(i18n.G("could not retrieve user for %q: %w"), err)
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return fmt.Errorf(i18n.G("couldn't convert %q to a valid uid for %q"), u.Uid, username)
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return fmt.Errorf(i18n.G("couldn't convert %q to a valid gid for %q"), u.Gid, username)
	}

	objectPath := filepath.Join(m.runDir, "users", u.Uid)
	mountsPath := filepath.Join(objectPath, "mounts")

	// This creates the user directory and set its ownership to the current user.
	if err := mkdirAllWithUIDGID(objectPath, uid, gid); err != nil {
		return fmt.Errorf(i18n.G("can't create user directory %q for %q: %v"), objectPath, username, err)
	}

	parsedValues, err := parseEntryValues(entry)
	if err != nil {
		return err
	}

	s := strings.Join(parsedValues, "\n")
	if s == "" {
		if err = m.cleanupMountsFile(ctx, u.Uid); err != nil {
			return err
		}
		return nil
	}

	if err = writeFileWithUIDGID(mountsPath, uid, gid, s); err != nil {
		return err
	}

	return nil
}

func (m *Manager) applySystemMountsPolicy(ctx context.Context, machineName string, entry entry.Entry) (err error) {
	decorate.OnError(&err, "error when applying mount policy to machine %q", machineName)

	log.Debugf(ctx, "Applying mount policy to machine %q", machineName)

	var failures []string

	prevUnits := m.currentSystemMountUnits()
	newUnits, err := createUnits(parseEntryValues(entry))
	if err != nil {
		failures = append(failures, fmt.Sprintf("error when creating new units: %v", err))
	}

	// Marks shares to write as new units and removes from map units that shouldn't change
	needsReload := false
	var unitsToEnable []string

	for name, content := range newUnits {
		written, err := writeIfChanged(filepath.Join(m.systemUnitDir, name), content)
		if err != nil {
			failures = append(failures, fmt.Sprintf("failed to write new unit: %v", err))
		}
		if written {
			unitsToEnable = append(unitsToEnable, name)
		}
		needsReload = needsReload || written

		delete(prevUnits, name)
	}

	// The units left in the map should be cleaned from the system.
	unitsToClean := make([]string, 0, len(prevUnits))
	for k := range prevUnits {
		unitsToClean = append(unitsToClean, k)
	}

	if err = m.cleanupMountUnits(ctx, unitsToClean); err != nil {
		failures = append(failures, fmt.Sprintf("failed when cleaning units: %v", err))
	}

	if !needsReload {
		if failures != nil {
			err = fmt.Errorf("%s", strings.Join(failures, "\n"))
		}
		return err
	}

	// Trigger a daemon reload
	if err := m.execSystemCtlCmd(ctx, "daemon-reload"); err != nil {
		failures = append(failures, fmt.Sprintf("failed to reload daemon: %v", err))
		return fmt.Errorf("%s", strings.Join(failures, "\n"))
	}

	// Channel to control the error messages emitted by the routines.
	ch := make(chan string, len(unitsToEnable))
	// Enables and starts new units.
	for _, name := range unitsToEnable {
		name := name
		go func() {
			if err := m.execSystemCtlCmd(ctx, "enable", name); err != nil {
				ch <- fmt.Sprintf("failed to enable unit %q: %v", name, err)
				return
			}
			if err := m.execSystemCtlCmd(ctx, "start", name); err != nil {
				ch <- fmt.Sprintf("failed to start unit %q: %v", name, err)
				return
			}
			ch <- ""
		}()
	}

	for i := 0; i < len(unitsToEnable); {
		failure := <-ch
		if failure != "" {
			failures = append(failures, failure)
		}
		i++
	}

	if failures != nil {
		return fmt.Errorf("%s", strings.Join(failures, "\n"))
	}

	return nil
}

// createUnits formats the adsys-.mount template with the specified paths.
func createUnits(mountPaths []string) (units map[string]string, err error) {
	defer decorate.OnError(&err, "failed when writing requested units")

	var failures []string
	units = make(map[string]string)

	for _, mp := range mountPaths {
		opts := []string{}

		// Checks if anonymous was requested
		p := strings.TrimPrefix(mp, "[anonymous]")
		if p != mp {
			opts = append(opts, "users")
		}

		_, s, found := strings.Cut(p, ":")
		if !found {
			failures = append(failures, fmt.Sprintf("badly formatted entry %q", mp))
			continue
		}

		// Skips the // from the path
		s = s[2:]

		content := fmt.Sprintf(unitTemplate,
			mp,                      // Description
			p,                       // What
			s,                       // Where
			strings.Join(opts, ","), // Options
		)

		name := fmt.Sprintf("adsys-%s.mount", unit.UnitNameEscape(p))
		units[name] = content
	}

	if failures != nil {
		return units, fmt.Errorf("%s", strings.Join(failures, "\n"))
	}

	return units, nil
}

// parseEntryValues parses the entry value, trimming whitespaces and removing duplicates.
func parseEntryValues(entry entry.Entry) (p []string, err error) {
	defer decorate.OnError(&err, i18n.G("failed to parse entry values"))

	if entry.Err != nil {
		return nil, fmt.Errorf(i18n.G("entry is errored: %v"), entry.Err)
	}

	seen := make(map[string]struct{})
	for _, v := range strings.Split(entry.Value, "\n") {
		v := strings.TrimSpace(v)
		if _, ok := seen[v]; ok || v == "" {
			continue
		}

		if err := checkValue(v); err != nil {
			return nil, err
		}

		p = append(p, v)
		seen[v] = struct{}{}
	}

	return p, nil
}

// checkValue checks if the entry value respects the defined formatting directive: <protocol>://<hostname-or-ip>/<shared-path>.
func checkValue(value string) error {
	// Removes the kerberos auth tag, if it exists
	tmp := strings.TrimPrefix(value, "[krb5]")

	// Value left: protocol://<hostname-or-ip>/<shared-path>
	if _, hostnameAndPath, found := strings.Cut(tmp, ":"); !found || !strings.HasPrefix(hostnameAndPath, "//") {
		return fmt.Errorf(i18n.G("entry %q is badly formatted"), value)
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

// writeFileWithUIDGID writes the content into the specified path and changes its ownership to the specified uid/gid.
func writeFileWithUIDGID(path string, uid, gid int, content string) (err error) {
	defer decorate.OnError(&err, i18n.G("failed when writing file %s"), path)

	// #nosec G306. This should be world-readable.
	if err = os.WriteFile(path+".new", []byte(content+"\n"), 0600); err != nil {
		return err
	}

	// Fixes the file ownership before renaming it.
	if err = chown(path+".new", nil, uid, gid); err != nil {
		return err
	}

	if err = os.Rename(path+".new", path); err != nil {
		return err
	}

	return nil
}

// mkdirAllWithUIDGID create a directory and sets its ownership to the specified uid and gid.
func mkdirAllWithUIDGID(p string, uid, gid int) error {
	if err := os.MkdirAll(p, 0750); err != nil {
		return fmt.Errorf(i18n.G("can't create directory %q: %v"), p, err)
	}

	return chown(p, nil, uid, gid)
}

// chown either chown the file descriptor attached, or the path if this one is null to uid and gid.
// It will know if we should skip chown for tests.
func chown(p string, f *os.File, uid, gid int) (err error) {
	defer decorate.OnError(&err, i18n.G("can't chown %q"), p)

	if os.Getenv("ADSYS_SKIP_ROOT_CALLS") != "" {
		uid = -1
		gid = -1
	}

	if f == nil {
		// Ensure that if p is a symlink, we only change the symlink itself, not what was pointed by it.
		return os.Lchown(p, uid, gid)
	}

	return f.Chown(uid, gid)
}

// cleanup removes the files generated when applying the mount policy to an object.
func (m *Manager) cleanup(ctx context.Context, objectName string, isComputer bool) (err error) {
	defer decorate.OnError(&err, "failed to clean up mount policy files for %q", objectName)

	log.Debugf(ctx, "Cleaning up mount policy files for %q", objectName)

	if !isComputer {
		var u *user.User
		if u, err = m.userLookup(objectName); err != nil {
			return err
		}
		return m.cleanupMountsFile(ctx, u.Uid)
	}
	return m.cleanupMountUnits(ctx, nil)
}

// cleanupMountsFile removes the mounts file, if there is any, created for the user with the specified uid.
func (m *Manager) cleanupMountsFile(ctx context.Context, uid string) (err error) {
	defer decorate.OnError(&err, "failed to clean up mounts file")

	log.Debugf(ctx, "Cleaning up mounts file for user with uid %q", uid)

	p := filepath.Join(m.runDir, "users", uid, "mounts")

	// Since the function might be called even if there is not a mounts file, we
	// must ignore the ErrNotExist returned by os.Remove.
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// cleanupMountUnits removes all the mount units generated by adsys for the current system.
// If the units slice is nil, all mount units will be removed.
func (m *Manager) cleanupMountUnits(ctx context.Context, units []string) (err error) {
	defer decorate.OnError(&err, "failed to clean up the mount units")

	if units == nil {
		tmp := m.currentSystemMountUnits()
		for k := range tmp {
			units = append(units, k)
		}
	}

	var failures []string
	for _, unit := range units {
		// Stops and disables the unit before removing it
		if err = m.execSystemCtlCmd(ctx, "stop", unit); err != nil {
			failures = append(failures, fmt.Sprintf("failed to stop unit %q: %v", unit, err))
		}

		if err = m.execSystemCtlCmd(ctx, "disable", unit); err != nil {
			failures = append(failures, fmt.Sprintf("failed to disable unit %q: %v", unit, err))
		}

		if err = os.Remove(filepath.Join(m.systemUnitDir, unit)); err != nil {
			failures = append(failures, fmt.Sprintf("could not remove file %q: %v", unit, err))
		}
	}

	if failures != nil {
		return fmt.Errorf("failed to remove units: %s", strings.Join(failures, "\n"))
	}

	return nil
}

// execSystemCtlCmd wraps the specified args into a systemctl command execution.
func (m *Manager) execSystemCtlCmd(ctx context.Context, args ...string) (err error) {
	cmdArgs := append([]string{}, m.systemCtlCmd...)
	cmdArgs = append(cmdArgs, args...)

	// #nosec G204 - We are in control of the arguments
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)

	smbsafe.WaitExec()
	if out, err := cmd.CombinedOutput(); err != nil {
		smbsafe.DoneExec()
		return fmt.Errorf("failed when running systemctl cmd: %w -> %s", err, out)
	}
	smbsafe.DoneExec()
	return nil
}

// currentSystemMountUnits reads the unit directory and returns a map containing the adsys mount units found.
func (m *Manager) currentSystemMountUnits() (units map[string]struct{}) {
	paths, _ := filepath.Glob(filepath.Join(m.systemUnitDir, "adsys-*.mount"))

	units = make(map[string]struct{})
	for _, path := range paths {
		units[filepath.Base(path)] = struct{}{}
	}

	return units
}
