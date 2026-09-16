package scripts

import (
	"context"
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

// RunScriptsWithBusyScriptRetryHook executes scripts and calls hook when a
// script execution fails with ETXTBSY and will be retried.
func RunScriptsWithBusyScriptRetryHook(ctx context.Context, order string, allowOrderMissing bool, hook func()) error {
	return runScripts(ctx, order, allowOrderMissing, hook)
}
