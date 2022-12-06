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

// SetSystemCtlCmd allows to override the systemCtlCmd of the Manager for the tests.
// This is used instead of a option function because we need to control the systemctl command
// in multiple occasions during tests.
func (m *Manager) SetSystemCtlCmd(args []string) {
	m.systemCtlCmd = append(args, "systemctl")
}
