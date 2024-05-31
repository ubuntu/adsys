// Package main is the entry point for admxgen command line.
//
// admxgen is a tool used in CI to refresh policy definition files and generates admx/adml.
package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/cmd/admxgen/commands"
)

type app interface {
	Run() error
	UsageError() bool
}

func run(a app) int {
	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		DisableTimestamp:       true,
	})

	if err := a.Run(); err != nil {
		log.Error(err)

		if a.UsageError() {
			return 2
		}
		return 1
	}

	return 0
}

func main() {
	os.Exit(run(commands.New()))
}
