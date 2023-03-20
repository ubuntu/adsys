package proxy

import (
	"errors"

	"github.com/godbus/dbus/v5"
)

// ProxyApplierMock is a mock for the proxy apply object.
type ProxyApplierMock struct {
	WantApplyError bool
	WantNoService  bool

	args []string
}

// Call mocks the proxy apply call.
func (d *ProxyApplierMock) Call(method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	var errApply error

	for _, arg := range args {
		if arg, ok := arg.(string); ok {
			d.args = append(d.args, arg)
		}
	}

	if d.WantApplyError {
		errApply = dbus.MakeFailedError(errors.New("proxy apply error"))
	}

	if d.WantNoService {
		errApply = dbus.Error{Name: errDBusServiceUnknownName, Body: []interface{}{"The name com.ubuntu.ProxyManager was not provided by any .service files"}}
	}

	return &dbus.Call{Err: errApply}
}

func (d *ProxyApplierMock) Args() []string {
	return d.args
}
