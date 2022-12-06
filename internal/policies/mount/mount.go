// Package mount implements the manager responsible to handle the file sharing
// policy of adsys, parsing the GPO rules and setting up the mount process for
// the requested drives. User mounts will be handled by a systemd user service and
// computer mounts will be handled directly by systemd, via mount units.
package mount

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
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
	systemctlCmd []string
	userLookup   func(string) (*user.User, error)
}

// Option represents an optional function that is able to alter a default behavior used in mount.
type Option func(*options)

// Manager holds information needed for handling the mount policies.
type Manager struct {
	mountsMu map[string]*sync.Mutex
	muMu     sync.Mutex

	runDir string

	userLookup   func(string) (*user.User, error)
	systemCtlCmd []string
}

// New creates a Manager to handle mount policies.
func New(runDir string, opts ...Option) (m *Manager, err error) {
	defer decorate.OnError(&err, i18n.G("failed to create new mount manager"))
	o := options{
		userLookup: user.Lookup,
	}

	for _, opt := range opts {
		opt(&o)
	}

	// Multiple users will be in users/ subdirectory. Create the main one.
	// #nosec G301 - multiple users will be in users/ subdirectory, we want all of them to be able to access its own subdirectory.
	if err := os.MkdirAll(filepath.Join(runDir, "users"), 0750); err != nil {
		return nil, err
	}

	return &Manager{
		mountsMu: make(map[string]*sync.Mutex),

		runDir:       runDir,
		userLookup:   o.userLookup,
		systemCtlCmd: o.systemctlCmd,
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
		err = m.cleanupMountsFile(ctx, u.Uid)
	}
	return err
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
