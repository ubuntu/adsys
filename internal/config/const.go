package config

import log "github.com/sirupsen/logrus"

const (
	defaultLevel = log.WarnLevel
)

var (
	// Version is the version of the executable
	Version = "dev"

	// DefaultSocket is the default socket path
	DefaultSocket = "/tmp/socket.default"

	// DefaultClientTimeout is the default time in seconds  between 2 server activity before the client returns.
	DefaultClientTimeout = 30

	// DefaultServiceTimeout is the default time in seconds without any active request before the service exits.
	DefaultServiceTimeout = 120

	// DistroID is the distro ID which can be overriden at build time
	DistroID = "Ubuntu"
)
