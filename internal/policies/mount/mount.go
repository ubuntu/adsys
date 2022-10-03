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

	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
)

type options struct {
	runDir       string
	systemctlCmd []string
	userLookup   func(string) (*user.User, error)
}

// Option represents an optional function that is able to alter a default behavior used in mount.
type Option func(*options)

// WithRunDir overrides the default path for the run directory.
func WithRunDir(p string) Option {
	return func(o *options) {
		o.runDir = p
	}
}

// Manager holds information needed for handling the mount policies.
type Manager struct {
	mountsMu map[string]*sync.Mutex
	muMu     sync.Mutex

	runDir string

	userLookup   func(string) (*user.User, error)
	systemCtlCmd []string
}

// New creates a Manager to handle mount policies.
func New(opts ...Option) (m *Manager, err error) {
	defer decorate.OnError(&err, i18n.G("failed to create new mount manager"))
	o := options{
		runDir:     consts.DefaultRunDir,
		userLookup: user.Lookup,
	}

	for _, opt := range opts {
		opt(&o)
	}

	// Multiple users will be in users/ subdirectory. Create the main one.
	// #nosec G301 - multiple users will be in users/ subdirectory, we want all of them to be able to access its own subdirectory.
	if err := os.MkdirAll(filepath.Join(o.runDir, "users"), 0750); err != nil {
		return nil, err
	}

	return &Manager{
		mountsMu: make(map[string]*sync.Mutex),

		runDir:       o.runDir,
		userLookup:   o.userLookup,
		systemCtlCmd: o.systemctlCmd,
	}, nil
}

// ApplyPolicy generates mount policies based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply mount policy to %s"), objectName)

	if len(entries) == 0 {
		return nil
	}

	log.Debugf(ctx, "Applying mount policy to %s", objectName)

	// Mutexes are per user1, user2, computer
	m.muMu.Lock()
	if _, exists := m.mountsMu[objectName]; !exists {
		m.mountsMu[objectName] = &sync.Mutex{}
	}
	m.muMu.Unlock()
	m.mountsMu[objectName].Lock()
	defer m.mountsMu[objectName].Unlock()

	for _, entry := range entries {
		switch entry.Key {
		case "user-mounts":
			if isComputer {
				break
			}

			if e := m.applyUserPolicy(ctx, objectName, entry); e != nil {
				err = e
			}

		default:
			log.Debugf(ctx, "Key %q is currently not supported by the mount manager", entry.Key)
		}
	}

	return err
}

func (m *Manager) applyUserPolicy(ctx context.Context, username string, entry entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to apply policy for user %q"), username)

	log.Debugf(ctx, "Applying mount policy to user %q", username)

	var uid, gid int
	usr, err := m.userLookup(username)
	if err != nil {
		return fmt.Errorf(i18n.G("could not retrieve user for %q: %w"), err)
	}
	if uid, err = strconv.Atoi(usr.Uid); err != nil {
		return fmt.Errorf(i18n.G("couldn't convert %q to a valid uid for %q"), usr.Uid, username)
	}
	if gid, err = strconv.Atoi(usr.Gid); err != nil {
		return fmt.Errorf(i18n.G("couldn't convert %q to a valid gid for %q"), usr.Gid, username)
	}

	objectPath := filepath.Join(m.runDir, "users", usr.Uid)
	mountsPath := filepath.Join(objectPath, "mounts")

	// Removes the current mounts file, if it exists, before continuing applying the policy.
	if err = os.Remove(mountsPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// This creates userDir directory.
	// We chown userDir to uid:gid of the user. Nothing is done for the machine
	if err := mkdirAllWithUIDGID(objectPath, uid, gid); err != nil {
		return fmt.Errorf(i18n.G("can't create mounts directory %q: %v"), objectPath, err)
	}

	s := strings.Join(parseEntryValues(entry), "\n")
	if s == "" {
		return nil
	}

	if err = writeFileWithUIDGID(mountsPath, uid, gid, s); err != nil {
		return err
	}

	return nil
}

// parseEntryValues parses the entry value, trimming whitespaces and removing duplicates.
func parseEntryValues(entry entry.Entry) (p []string) {
	if entry.Err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	for _, v := range strings.Split(entry.Value, "\n") {
		v := strings.TrimSpace(v)
		if _, ok := seen[v]; ok || v == "" {
			continue
		}
		p = append(p, v)
		seen[v] = struct{}{}
	}

	return p
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
		return fmt.Errorf(i18n.G("can't create mounts directory %q: %v"), p, err)
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
