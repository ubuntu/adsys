package mount

import (
	"context"
	"os/user"

	"github.com/ubuntu/adsys/internal/policies/entry"
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

// ApplyUserPolicy exports the internal applyUserPolicy for tests.
func (m *Manager) ApplyUserPolicy(ctx context.Context, username string, e entry.Entry) error {
	return m.applyUserPolicy(ctx, username, e)
}
