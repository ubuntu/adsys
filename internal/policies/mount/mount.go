// Package mount provides the policy manager to handle file sharing policies.
//
// The manager behavior differs depending on the object type:
//   - System mounts: Systemd mount units are created to handle the mount process of the
//     requested shared locations;
//   - User mounts:   The policy values are parsed into a mounts file that will handled by a
//     helper binary that will mount the shared locations using gio.
//
// Should the manager fail to write the required assets, an error will be returned.
// However, if the manager setup all the required steps, it's up to the correctness of the specified
// entries values and gvfs to mount the requested shared drives.
// Should an error occur during this step, it will be logged (in the system journal for the system
// or in the adsys-user-mounts.service for the user).
package mount

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/coreos/go-systemd/v22/unit"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/decorate"
)

type options struct {
	userLookup    func(string) (*user.User, error)
	systemUnitDir string
}

// Option represents an optional function that is able to alter a default behavior used in mount.
type Option func(*options)

//go:embed adsys-mount-template.mount
var systemdUnitTemplate string

const krbTag string = "[krb5]"
const defaultMountTimeoutSec int = 30

// Manager holds information needed for handling the mount policies.
type Manager struct {
	runDir        string
	systemUnitDir string
	systemdCaller systemdCaller

	userLookup func(string) (*user.User, error)
}

type systemdCaller interface {
	StartUnit(context.Context, string) error
	StopUnit(context.Context, string) error
	EnableUnit(context.Context, string) error
	DisableUnit(context.Context, string) error
	DaemonReload(context.Context) error
}

// New creates a Manager to handle mount policies.
func New(runDir string, systemUnitDir string, systemdCaller systemdCaller, opts ...Option) (m *Manager, err error) {
	defer decorate.OnError(&err, i18n.G("failed to create new mount manager"))

	o := options{
		userLookup:    user.Lookup,
		systemUnitDir: systemUnitDir,
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
		runDir:        runDir,
		systemUnitDir: systemUnitDir,
		systemdCaller: systemdCaller,

		userLookup: o.userLookup,
	}, nil
}

// ApplyPolicy generates mount policies based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply mount policy to %s"), objectName)

	log.Debugf(ctx, "Applying mount policy to %s", objectName)

	if len(entries) == 0 {
		return m.cleanup(ctx, objectName, isComputer)
	}

	key := "user"
	if isComputer {
		key = "system"
	}

	i := slices.IndexFunc(entries, func(e entry.Entry) bool {
		return e.Key == key+"-mounts"
	})

	if i == -1 {
		log.Debugf(ctx, i18n.G("The provided entries are not supported by the %s mount manager: %v"), key, entries)
		return m.cleanup(ctx, objectName, isComputer)
	}

	if entries[i].Disabled {
		log.Debugf(ctx, i18n.G("The entry %q is disabled and will be skipped"), entries[i].Key)
		return m.cleanup(ctx, objectName, isComputer)
	}

	if key == "user" {
		return m.applyUserMountsPolicy(ctx, objectName, entries[i])
	}
	return m.applySystemMountsPolicy(ctx, objectName, entries[i])
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
		return fmt.Errorf(i18n.G("can't create user directory %q for %q: %w"), objectPath, username, err)
	}

	parsedValues, err := parseEntryValues(ctx, entry)
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
	defer decorate.OnError(&err, i18n.G("error when applying mount policy to machine %q"), machineName)

	log.Debugf(ctx, i18n.G("Applying mount policy to machine %q"), machineName)

	parsedValues, err := parseEntryValues(ctx, entry)
	if err != nil {
		return err
	}
	newUnits := createUnits(parsedValues)

	// Marks shares to write as new units and removes from map units that shouldn't change
	needsReload := false
	var unitsToEnable []string

	prevUnits := m.currentSystemMountUnits()

	// Removes from the map all the units that are supposed to be written or updated.
	for name := range newUnits {
		delete(prevUnits, name)
	}

	var unitsToClean []string
	for name := range prevUnits {
		unitsToClean = append(unitsToClean, name)
	}

	if err := m.cleanupMountUnits(ctx, unitsToClean); err != nil {
		return err
	}

	for name, content := range newUnits {
		written, err := writeIfChanged(filepath.Join(m.systemUnitDir, name), content)
		if err != nil {
			return err
		}
		if written {
			unitsToEnable = append(unitsToEnable, name)
		}
		needsReload = needsReload || written
	}

	if !needsReload {
		return nil
	}

	// Trigger a daemon reload
	if err := m.systemdCaller.DaemonReload(ctx); err != nil {
		return err
	}

	// Enables and starts new units.
	for _, name := range unitsToEnable {
		if err := m.systemdCaller.EnableUnit(ctx, name); err != nil {
			return err
		}
		if err := m.systemdCaller.StartUnit(ctx, name); err != nil {
			log.Warningf(ctx, i18n.G("failed to start unit %q: %v"), name, err)
		}
	}

	return nil
}

// mountInfo stores relevant information about a mount.
type mountInfo struct {
	hostname   string
	sharedPath string
	protocol   string
	options    []string
}

// createUnits formats the adsys-.mount template with the specified paths.
func createUnits(mountPaths []string) map[string]string {
	units := make(map[string]string)

	for _, mp := range mountPaths {
		mi := parseMountPath(mp)

		what := whatStringFromInfo(mi)
		where := filepath.Join("/", "adsys", mi.protocol, mi.hostname, mi.sharedPath)

		opts := "defaults"
		if mi.options != nil {
			opts = strings.Join(mi.options, ",")
		}

		content := fmt.Sprintf(systemdUnitTemplate,
			mp,                     // Description
			what,                   // What
			where,                  // Where
			mi.protocol,            // Type
			opts,                   // Options
			defaultMountTimeoutSec, // TimeoutSec
		)

		n := fmt.Sprintf("%s.mount", unit.UnitNameEscape(where[1:]))
		units[n] = content
	}

	return units
}

// parseMountPath takes a mount path <protocol>://<hostname>/<shared_path> and parses it
// into the richer type mountInfo.
func parseMountPath(path string) mountInfo {
	var info mountInfo

	// path = [krb5]protocol://hostname/shared_path
	krb5 := strings.HasPrefix(path, krbTag)
	if krb5 {
		path = strings.TrimPrefix(path, krbTag)
		// Using krb5i since it's supported by both cifs and nfs, while krb5p is only supported by nfs.
		info.options = append(info.options, "sec=krb5i")
	}

	// path = protocol://hostname/shared_path
	protocol, path, _ := strings.Cut(path, ":")

	// Some aliases for common mounts protocols, as they need to be converted to a type
	// recognized by systemd and the mount command.
	switch protocol {
	case "smb":
		info.protocol = "cifs"
	case "ftp":
		info.protocol = "fuse"
	default:
		info.protocol = protocol
	}

	// path = //hostname/shared_path
	path = path[2:]

	// path = hostname/shared_path
	info.hostname, info.sharedPath, _ = strings.Cut(path, "/")

	return info
}

// whatStringFromInfo creates the What value of a systemd mount unit from the
// specified info as some protocols have quite different What values.
// If the protocol is not recognized, the What string will be that of a partition
// protocol.
func whatStringFromInfo(mi mountInfo) string {
	var what string

	switch mi.protocol {
	case "cifs":
		// What=//hostname/shared_path e.g. //domain.com/cifs_share
		what = fmt.Sprintf("//%s/%s", mi.hostname, mi.sharedPath)
	case "nfs":
		// What=hostname:/shared_path e.g. domain.com:/nfs_share
		what = fmt.Sprintf("%s:/%s", mi.hostname, mi.sharedPath)
	case "fuse":
		// What=curlftpfs#hostname e.g. curlftpfs#ftp.domain.com
		what = fmt.Sprintf("curlftpfs#%s", mi.hostname)
	default:
		// The default case will treat the protocol as a partition one (ext4, usb...)
		// What=/hostname/shared_path
		what = fmt.Sprintf("/%s/%s", mi.hostname, mi.sharedPath)
	}

	return what
}

// parseEntryValues parses the entry value, trimming whitespaces and removing duplicates.
func parseEntryValues(ctx context.Context, e entry.Entry) (p []string, err error) {
	defer decorate.OnError(&err, i18n.G("failed to parse entry values"))

	if e.Err != nil {
		return nil, fmt.Errorf(i18n.G("entry is errored: %w"), e.Err)
	}

	seen := make(map[string]string)
	for _, v := range strings.Split(e.Value, "\n") {
		v := strings.TrimSpace(v)
		if v == "" {
			continue
		}

		// Compares "normal" and prefixed values the same way, since the unit name will be the same.
		tmp := strings.TrimPrefix(v, krbTag)
		if prev, ok := seen[tmp]; ok {
			if prev == v {
				log.Debugf(ctx, i18n.G("Value %q is duplicated."), v)
			} else {
				log.Warningf(ctx, i18n.G("The location %q was already set up to be mounted with different options or authentication. The first provided value %q will be used instead."), v, prev)
			}
			continue
		}

		if err := checkValue(v); err != nil {
			return nil, err
		}

		p = append(p, v)
		seen[tmp] = v
	}

	return p, nil
}

// checkValue checks if the entry value respects the defined formatting directive: <protocol>://<hostname-or-ip>/<shared-path>.
func checkValue(value string) error {
	// Removes the kerberos auth tag, if it exists
	tmp := strings.TrimPrefix(value, krbTag)

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
	defer decorate.OnError(&err, i18n.G("failed to clean up mount policy files for %q"), objectName)

	log.Debugf(ctx, i18n.G("Cleaning up mount policy files for %q"), objectName)

	if !isComputer {
		var u *user.User
		if u, err = m.userLookup(objectName); err != nil {
			return err
		}
		return m.cleanupMountsFile(ctx, u.Uid)
	}

	var units []string
	for k := range m.currentSystemMountUnits() {
		units = append(units, k)
	}
	return m.cleanupMountUnits(ctx, units)
}

// cleanupMountsFile removes the mounts file, if there is any, created for the user with the specified uid.
func (m *Manager) cleanupMountsFile(ctx context.Context, uid string) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to clean up mounts file"))

	log.Debugf(ctx, i18n.G("Cleaning up mounts file for user with uid %q"), uid)

	p := filepath.Join(m.runDir, "users", uid, "mounts")

	// Since the function might be called even if there is not a mounts file, we
	// must ignore the ErrNotExist returned by os.Remove.
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// cleanupMountUnits removes all the mount units generated by adsys for the current system.
func (m *Manager) cleanupMountUnits(ctx context.Context, units []string) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to clean up the mount units"))

	for _, unit := range units {
		// Tries to stop the unit before disabling and removing it.
		if err := m.systemdCaller.StopUnit(ctx, unit); err != nil {
			log.Warningf(ctx, i18n.G("Failed to stop unit %q: %v"), unit, err)
		}

		// Disables the unit before removing it.
		if err := m.systemdCaller.DisableUnit(ctx, unit); err != nil {
			return err
		}

		if err := os.Remove(filepath.Join(m.systemUnitDir, unit)); err != nil {
			return fmt.Errorf(i18n.G("could not remove file %q: %w"), unit, err)
		}
	}

	return nil
}

// currentSystemMountUnits reads the unit directory and returns a map containing the adsys mount units found.
func (m *Manager) currentSystemMountUnits() map[string]struct{} {
	paths, _ := filepath.Glob(filepath.Join(m.systemUnitDir, "adsys-*.mount"))

	units := make(map[string]struct{})
	for _, path := range paths {
		units[filepath.Base(path)] = struct{}{}
	}

	return units
}
