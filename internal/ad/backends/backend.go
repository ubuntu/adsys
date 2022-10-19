// package backends is the common interface and errors supported by ad backends.
package backends

import (
	"context"
	"errors"

	"github.com/ubuntu/adsys/internal/i18n"
)

// Backend is the common interface for all backends.
type Backend interface {
	// Domain returns current server domain.
	Domain() string
	// ServerURL returns current server URL.
	// It returns first any static configuration and goes dynamic if the backend provides this.
	// If the dynamic lookup worked, but there is still no server URL found (for instance, backend
	// if offline), the error raised is of type ErrorNoActiveServer.
	ServerURL(context.Context) (string, error)
	// HostKrb5CCNAME returns the absolute path of the machine krb5 ticket.
	HostKrb5CCNAME() string
	// DefaultDomainSuffix returns current default domain suffix.
	DefaultDomainSuffix() string
	// IsOnline refresh and returns if we are online.
	IsOnline() (bool, error)
	// Config returns a stringified configuration of the backend.
	Config() string
}

var (
	// ErrorNoActiveServer is an error receive when there is no active server and no static configuration
	// This is received in ServerURL.
	ErrorNoActiveServer = errors.New(i18n.G("no active server found"))
)
