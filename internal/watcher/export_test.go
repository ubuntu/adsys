package watcher

import "time"

// WithRefreshDuration allows overriding default refresh duration on tests.
func WithRefreshDuration(refreshDuration time.Duration) func(o *options) error {
	return func(o *options) error {
		o.refreshDuration = refreshDuration
		return nil
	}
}

// WithEventProcessed reports when the watcher has processed a filesystem event.
// The timestamp is captured immediately before the refresh timer is reset.
func WithEventProcessed(f func(string, time.Time)) func(o *options) error {
	return func(o *options) error {
		o.eventProcessed = f
		return nil
	}
}

// RefreshDuration returns the refresh duration used by the watcher.
func (w Watcher) RefreshDuration() time.Duration {
	return w.refreshDuration
}
