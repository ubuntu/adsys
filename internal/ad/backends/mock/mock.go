// Package mock gives a mock backend to tweak its usage.
package mock

import "errors"

// Backend is a mock backend where we control some returned value.
type Backend struct {
	Dom                string
	ServURL            string
	HostKrb5CCNAMEPath string

	Online      bool
	ErrIsOnline bool
}

// Domain returns current server domain.
func (m Backend) Domain() string {
	return m.Dom
}

// ServerURL returns current server URL.
// It returns first any static configuration and goes dynamic if the backend provides this.
// If the dynamic lookup worked, but there is still no server URL found (for instance, backend
// if offline), the error raised is of type ErrorNoActiveServer.
func (m Backend) ServerURL() string {
	return m.ServURL
}

// HostKrb5CCNAME returns the absolute path of the machine krb5 ticket.
func (m Backend) HostKrb5CCNAME() string {
	return m.HostKrb5CCNAMEPath
}

// DefaultDomainSuffix returns current default domain suffix.
func (m Backend) DefaultDomainSuffix() string {
	return m.Dom
}

// IsOnline refresh and returns if we are online.
func (m Backend) IsOnline() (bool, error) {
	if m.ErrIsOnline {
		return false, errors.New("IsOnline returned an error")
	}
	return m.Online, nil
}

// Config returns a stringified configuration for SSSD backend.
func (m Backend) Config() string {
	return "backend static config"
}
