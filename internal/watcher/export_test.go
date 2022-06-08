package watcher

import "time"

// WithRefreshDuration allows overriding default refresh duration on tests.
func WithRefreshDuration(refreshDuration time.Duration) func(o *options) error {
	return func(o *options) error {
		o.refreshDuration = refreshDuration
		return nil
	}
}

// RefreshDuration returns the refresh duration used by the watcher.
func (w Watcher) RefreshDuration() time.Duration {
	return w.refreshDuration
}
