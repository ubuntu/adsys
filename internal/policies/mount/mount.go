// Package mount implements the manager responsible to handle the file sharing
// policy of adsys, parsing the GPO rules and properly mounting the requested
// drives / folders.
package mount

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
)

type option struct {
	mountsFilePath       string
	userMountServicePath string
	userLookupFunc       func(string) (*user.User, error)
}

// Option represents an optional function that is able to alter a default behavior used in mount.
type Option func(*option)

// WithMountsFilePath overrides the default path for the mounts file.
func WithMountsFilePath(p string) Option {
	return func(opt *option) {
		opt.mountsFilePath = p
	}
}

// WithUserMountServicePath overrides the default path for the user service.
func WithUserMountServicePath(p string) Option {
	return func(opt *option) {
		opt.userMountServicePath = p
	}
}

// WithUserLookup defines a custom userLookup function for tests.
func WithUserLookup(f func(string) (*user.User, error)) Option {
	return func(opt *option) {
		opt.userLookupFunc = f
	}
}

// Manager holds information needed for handling the mount policies.
type Manager struct {
	// mountMu              sync.RWMutex // Still wondering if the mutex is needed for this policy.
	userLookup           func(string) (*user.User, error)
	mountsFilePath       string
	userMountServicePath string
}

// New creates a Manager to handle mount policies.
func New(opts ...Option) (m *Manager) {
	o := option{
		mountsFilePath:       consts.DefaultMountsFilePath,
		userMountServicePath: consts.DefaultUserMountServicePath,
		userLookupFunc:       user.Lookup,
	}

	for _, opt := range opts {
		opt(&o)
	}

	return &Manager{
		userLookup:           o.userLookupFunc,
		mountsFilePath:       o.mountsFilePath,
		userMountServicePath: o.userMountServicePath,
	}
}

// ApplyPolicy generates mount policies based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply mount policy to %s"), objectName)

	log.Debugf(ctx, "Applying mount policy to %s", objectName)

	if isComputer {
		return fmt.Errorf(i18n.G("computer mounts are currently not supported"))
	}

	if len(entries) == 0 {
		return nil
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

	if err = os.MkdirAll(filepath.Dir(m.mountsFilePath), 0755); err != nil {
		return err
	}

	err = writeMountsFile(ctx, entries, WithMountsFilePath(m.mountsFilePath))
	if err != nil {
		return err
	}

	// Fix the ownership of the directory and the mounts file.
	if err = os.Chown(filepath.Dir(m.mountsFilePath), uid, gid); err != nil {
		return err
	}
	if err = os.Chown(m.mountsFilePath, uid, gid); err != nil {
		return err
	}

	return nil
}

func writeMountsFile(ctx context.Context, entries []entry.Entry, opts ...Option) (err error) {
	o := option{
		mountsFilePath: consts.DefaultMountsFilePath,
	}

	for _, opt := range opts {
		opt(&o)
	}

	decorate.OnError(&err, i18n.G("failed when writing mounts file %s"), o.mountsFilePath)

	p := []string{}
	for _, entry := range entries {
		if entry.Err != nil {
			continue
		}
		p = append(p, entry.Value)
	}

	err = os.WriteFile(o.mountsFilePath, []byte(strings.Join(p, "\n")), 0755)
	if err != nil {
		return err
	}

	return nil
}
