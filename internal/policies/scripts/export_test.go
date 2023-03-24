package scripts

import (
	"os/user"
)

const (
	InSessionFlag = inSessionFlag
)

// WithUserLookup allows to mock system user lookup.
func WithUserLookup(userLookup func(string) (*user.User, error)) Option {
	return func(o *options) {
		o.userLookup = userLookup
	}
}
