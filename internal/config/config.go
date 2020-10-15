package config

import (
	log "github.com/sirupsen/logrus"
)

// TEXTDOMAIN is the gettext domain for l10n
const TEXTDOMAIN = "adsys"

// SetVerboseMode change ErrorFormat and logs between very, middly and non verbose
func SetVerboseMode(level int) {
	if level > 2 {
		level = 2
	}
	switch level {
	default:
		log.SetLevel(defaultLevel)
	case 1:
		log.SetLevel(log.InfoLevel)
	case 2:
		log.SetLevel(log.DebugLevel)
	}
}
