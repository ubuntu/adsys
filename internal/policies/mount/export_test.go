package mount

import (
	"os"
	"os/user"
)

// WithUserLookup defines a custom userLookup function for tests.
func WithUserLookup(f func(string) (*user.User, error)) Option {
	return func(o *options) {
		o.userLookup = f
	}
}

// WithSystemCtlCmd allow to mock systemctl call.
func WithSystemCtlCmd(cmd []string) Option {
	return func(o *options) {
		o.systemctlCmd = cmd
	}
}

// WithRunDir overrides the default path for the run directory.
func WithRunDir(p string) Option {
	return func(o *options) {
		o.runDir = p
	}
}

// WithPerm overrides the default permissions of the runDir/users directory for tests.
func WithPerm(perm os.FileMode) Option {
	return func(o *options) {
		o.perm = perm
	}
}
