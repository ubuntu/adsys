// Package proxy provides a manager to apply system-wide proxy settings.
//
// The policy manager silently returns if there are no entries to apply.
//
// If there are entries and ubuntu-proxy-manager is not installed, it will log a
// warning and return.
// If there are entries and ubuntu-proxy-manager is installed, it will call its
// Apply method via D-Bus service. Any error returned by the Apply call will be
// returned by the manager.
//
// Entry keys passed to the proxy manager that are not part of the supportedKeys
// list will be ignored and logged as a warning.
package proxy

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/decorate"
	"golang.org/x/exp/slices"
)

// Caller is the interface to call a method on a D-Bus object.
type Caller interface {
	Call(method string, flags dbus.Flags, args ...interface{}) *dbus.Call
}

// supportedKeys are the entry keys supported by the proxy manager.
var supportedKeys = []string{"http", "https", "ftp", "socks", "no-proxy", "auto"}

// errDBusServiceUnknownName is the error name returned by D-Bus when the proxy manager service is not found.
const errDBusServiceUnknownName = "org.freedesktop.DBus.Error.ServiceUnknown"

// Manager prevents running multiple apparmor update processes in parallel while parsing policy in ApplyPolicy.
type Manager struct {
	mu           sync.Mutex
	proxyApplier Caller
}

// WithProxyApplier overrides the default proxy applier.
func WithProxyApplier(c Caller) func(*options) {
	return func(a *options) {
		a.proxyApplier = c
	}
}

type options struct {
	proxyApplier Caller
}

// Option reprents an optional function to change the proxy manager.
type Option func(*options)

// New returns a new proxy policy manager.
func New(bus *dbus.Conn, args ...Option) *Manager {
	proxyApplier := bus.Object("com.ubuntu.ProxyManager", "/com/ubuntu/ProxyManager")

	// Set default options
	opts := options{
		proxyApplier: proxyApplier,
	}

	// Apply given options
	for _, f := range args {
		f(&opts)
	}

	return &Manager{
		proxyApplier: opts.proxyApplier,
	}
}

// ApplyPolicy applies the system proxy policy (via a D-Bus call to ubuntu-proxy-manager).
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply proxy policy"))

	// Proxy policies are currently only supported on computers
	if !isComputer {
		return nil
	}

	// Exit early if we don't have any entries to apply
	if len(entries) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	args := make(map[string]string)
	for _, e := range entries {
		key := e.Key[strings.LastIndex(e.Key, "/")+1:]
		if !slices.Contains(supportedKeys, key) {
			log.Warningf(ctx, i18n.G("Encountered unsupported key '%s' while parsing proxy entries, skipping it"), key)
		}
		args[key] = e.Value
	}

	// Idempotency is handled by the proxy manager service
	log.Debugf(ctx, "Applying system proxy policy to %s", objectName)

	if err := m.proxyApplier.Call(
		"com.ubuntu.ProxyManager.Apply",
		dbus.FlagAllowInteractiveAuthorization,
		args["http"],
		args["https"],
		args["ftp"],
		args["socks"],
		args["no-proxy"],
		args["auto"]).Err; err != nil {
		var dbusErr dbus.Error
		if errors.As(err, &dbusErr) && dbusErr.Name == errDBusServiceUnknownName {
			log.Warningf(ctx, i18n.G("Not applying proxy settings as ubuntu-proxy-manager is not installed: %s"), dbusErr.Error())
			return nil
		}
		return err
	}

	return nil
}
