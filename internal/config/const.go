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

	// DefaultClientTimeout is the default client time between 2 server activity before the client returns.
	DefaultClientTimeout = 30
)
