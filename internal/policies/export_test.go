package policies

import (
	"github.com/ubuntu/adsys/internal/policies/gdm"
)

// WithGDM specifies a personalized gdm manager
func WithGDM(m *gdm.Manager) func(o *options) error {
	return func(o *options) error {
		o.gdm = m
		return nil
	}
}
