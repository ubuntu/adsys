package config

import log "github.com/sirupsen/logrus"

const (
	defaultLevel = log.WarnLevel
)

var (
	// Version is the version of the executable
	Version = "dev"
)
