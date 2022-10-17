package ad

// Backend is the common interface for all backends.
type Backend interface {
	// Domain returns current server domain.
	Domain() string
	// ServerURL returns current server URL.
	ServerURL() string
	// HostKrb5CCNAME returns the absolute path of the machine krb5 ticket.
	HostKrb5CCNAME() string
	// DefaultDomainSuffix returns current default domain suffix.
	DefaultDomainSuffix() string
	// IsOnline refresh and returns if we are online.
	IsOnline() (bool, error)
	// Config returns a stringified configuration of the backend.
	Config() string
}
