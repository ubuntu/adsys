package policies

import (
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/gdm"
)

// WithDconf specifies a personalized dconf manager
func WithDconf(m *dconf.Manager) func(o *options) error {
	return func(o *options) error {
		o.dconf = m
		return nil
	}
}

// WithGDM specifies a personalized gdm manager
func WithGDM(m *gdm.Manager) func(o *options) error {
	return func(o *options) error {
		o.gdm = m
		return nil
	}
}
