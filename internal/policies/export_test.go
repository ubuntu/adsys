package policies

import (
	"errors"

	"github.com/godbus/dbus/v5"
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

func (pols Policies) HasAssets() bool {
	return pols.assets != nil
}

// ProxyApplierMock is a mock for the proxy apply object.
type ProxyApplierMock struct {
	WantApplyError bool
}

// Call mocks the proxy apply call.
func (d *ProxyApplierMock) Call(_ string, _ dbus.Flags, _ ...interface{}) *dbus.Call {
	var errApply error

	if d.WantApplyError {
		errApply = errors.New("proxy apply error")
	}

	return &dbus.Call{Err: errApply}
}
