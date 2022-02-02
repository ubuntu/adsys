package policies

import (
	"context"

	"github.com/ubuntu/adsys/internal/policies/gdm"
)

const (
	PoliciesAssetsFileName = policiesAssetsFileName
	PoliciesFileName       = policiesFileName
)

// WithGDM specifies a personalized gdm manager.
func WithGDM(m *gdm.Manager) Option {
	return func(o *options) error {
		o.gdm = m
		return nil
	}
}

// GetSubscriptionState forces a refresh of a subscription state. Exported for tests only.
func (m *Manager) GetSubscriptionState(ctx context.Context) (subscriptionEnabled bool) {
	return m.getSubscriptionState(ctx)
}

func (pols Policies) HasAssets() bool {
	return pols.assets != nil
}
