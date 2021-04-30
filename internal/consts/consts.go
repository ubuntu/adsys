// Package consts defines the constants used by the project
package consts

import log "github.com/sirupsen/logrus"

const (
	// DefaultLogLevel is the default logging level selected without any option
	DefaultLogLevel = log.WarnLevel

	// Version is the version of the executable
	Version = "dev"

	// DefaultSocket is the default socket path
	DefaultSocket = "/run/adsysd.sock"

	// DefaultCacheDir is the default path for adsys system cache directory
	DefaultCacheDir = "/var/cache/adsys"

	// DefaultRunDir is the default path for adsys run directory
	DefaultRunDir = "/run/adsys"

	// DefaultClientTimeout is the default time in seconds  between 2 server activity before the client returns.
	DefaultClientTimeout = 30

	// DefaultServiceTimeout is the default time in seconds without any active request before the service exits.
	DefaultServiceTimeout = 120

	// DistroID is the distro ID which can be overridden at build time
	DistroID = "Ubuntu"
)
