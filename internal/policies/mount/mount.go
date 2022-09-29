// Package mount implements the manager responsible to handle the file sharing
// policy of adsys, parsing the GPO rules and properly mounting the requested
// drives / folders.
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
	perm         os.FileMode
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
func New(opts ...Option) (m *Manager, err error) {
	defer decorate.OnError(&err, i18n.G("failed to create new mount manager"))
	o := options{
		runDir:     consts.DefaultRunDir,
		userLookup: user.Lookup,
		perm:       0750,
	}

	for _, opt := range opts {
		opt(&o)
	}

	// Multiple users will be in users/ subdirectory. Create the main one.
	// #nosec G301 - multiple users will be in users/ subdirectory, we want all of them to be able to access its own subdirectory.
	if err := os.MkdirAll(filepath.Join(o.runDir, "users"), o.perm); err != nil {
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

	log.Debugf(ctx, "Applying mount policy to %s", objectName)

	if isComputer {
		return fmt.Errorf(i18n.G("computer mounts are currently not supported"))
	}

	var uid, gid int
	usr, err := m.userLookup(objectName)
	if err != nil {
		return fmt.Errorf(i18n.G("could not retrieve user for %q: %w"), err)
	}
	if uid, err = strconv.Atoi(usr.Uid); err != nil {
		return fmt.Errorf(i18n.G("couldn't convert %q to a valid uid for %q"), usr.Uid, objectName)
	}
	if gid, err = strconv.Atoi(usr.Gid); err != nil {
		return fmt.Errorf(i18n.G("couldn't convert %q to a valid gid for %q"), usr.Gid, objectName)
	}

	usrDir := filepath.Join(m.runDir, "users", usr.Uid)
	mountsPath := filepath.Join(usrDir, "mounts")

	// Mutexes are per user1, user2, computer
	m.muMu.Lock()
	if _, exists := m.mountsMu[mountsPath]; !exists {
		m.mountsMu[mountsPath] = &sync.Mutex{}
	}
	m.muMu.Unlock()
	m.mountsMu[mountsPath].Lock()
	defer m.mountsMu[mountsPath].Unlock()

	// Removes the current mounts file, if it exists, before continuing applying the policy.
	if err = os.Remove(mountsPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if len(entries) == 0 {
		return nil
	}

	// This creates usrDir directory.
	// We chown usrDir to uid:gid of the user. Nothing is done for the machine
	if err := mkdirAllWithUIDGID(usrDir, uid, gid); err != nil {
		return fmt.Errorf(i18n.G("can't create mounts directory %q: %v"), usrDir, err)
	}

	err = writeMountsFile(mountsPath, entries)
	if err != nil {
		return err
	}

	// Fix the ownership of the directory and the mounts file.
	if err = chown(mountsPath, nil, uid, gid); err != nil {
		defer os.Remove(mountsPath)
		return err
	}

	return nil
}

func writeMountsFile(mountsPath string, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("failed when writing mounts file %s"), mountsPath)

	seen := make(map[string]struct{})
	p := []string{}
	for _, entry := range entries {
		if entry.Err != nil {
			continue
		}

		values := strings.Split(entry.Value, "\n")
		for _, v := range values {
			if _, ok := seen[v]; ok || v == "" {
				continue
			}
			p = append(p, v)
			seen[v] = struct{}{}
		}
	}

	// #nosec G306. This should be world-readable.
	if err := os.WriteFile(mountsPath+".new", []byte(strings.Join(p, "\n")+"\n"), 0644); err != nil {
		return err
	}
	if err := os.Rename(mountsPath+".new", mountsPath); err != nil {
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
