package policies

import (
	"github.com/ubuntu/adsys/internal/policies/dynamicvalues"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/policies/gdm"
)

const (
	PoliciesAssetsFileName = policiesAssetsFileName
	PoliciesFileName       = policiesFileName
)

// SanitizeAssetContent exposes sanitizeAssetContent for testing.
func SanitizeAssetContent(content []byte) []byte {
	return sanitizeAssetContent(content)
}

// WithGDM specifies a personalized gdm manager.
func WithGDM(m *gdm.Manager) Option {
	return func(o *options) error {
		o.gdm = m
		return nil
	}
}

func (pols Policies) HasAssets() bool {
	return pols.assets != nil
}

// DynamicValuesContext exposes dynamicValuesContext for testing.
func (m *Manager) DynamicValuesContext(objectName string, isComputer bool) (dynamicvalues.Context, error) {
	return m.dynamicValuesContext(objectName, isComputer)
}

// ExpandDynamicValues exposes expandDynamicValues for testing.
func ExpandDynamicValues(rules map[string][]entry.Entry, dynCtx dynamicvalues.Context) error {
	return expandDynamicValues(rules, dynCtx)
}
