package scripts

import "os/user"

const (
	InSessionFlag = inSessionFlag
)

// WithSystemCtlCmd allow to mock systemctl call.
func WithSystemCtlCmd(cmd []string) Option {
	return func(o *options) {
		o.systemctlCmd = cmd
	}
}

// withUserLookup allow to mock system user lookup.
func WithUserLookup(userLookup func(string) (*user.User, error)) Option {
	return func(o *options) {
		o.userLookup = userLookup
	}
}
