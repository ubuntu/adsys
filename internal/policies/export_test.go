package policies

import "github.com/ubuntu/adsys/internal/policies/dconf"

// WithDconf specifies a personalized dconf manager
func WithDconf(d *dconf.Manager) func(o *options) error {
	return func(o *options) error {
		o.dconf = d
		return nil
	}
}
