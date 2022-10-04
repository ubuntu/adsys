package mount

import (
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
