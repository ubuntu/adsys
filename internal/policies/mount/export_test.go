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

// SetSystemdCaller allows to override the systemdCaller of the Manager for the tests.
// This is used instead of a option function because we need to control the
// behavior of the mock in multiple occasions during tests.
func (m *Manager) SetSystemdCaller(systemdCaller systemdCaller) {
	m.systemdCaller = systemdCaller
}
