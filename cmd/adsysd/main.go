package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/cmd/adsysd/client"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/i18n"
)

func main() {
	os.Exit(run(os.Args))
}

type app interface {
	Run() error
	UsageError() bool
	Hup() bool
	Quit()
}

func run(args []string) int {
	i18n.InitI18nDomain(config.TEXTDOMAIN)
	var a app

	switch filepath.Base(args[0]) {
	case daemon.CmdName:
		a = daemon.New()
	default:
		a = client.New()
	}
	//a = daemon.New()

	installSignalHandler(a)

	if err := a.Run(); err != nil {
		// This is a usage Error (we don't prefix E commands other than usage)
		// Usage error should be the same format than other errors and we didn’t setup the logger yet.
		if a.UsageError() {
			log.SetFormatter(&log.TextFormatter{
				DisableLevelTruncation: true,
				DisableTimestamp:       true,
			})
			log.Error(err)
			return 2
		}

		// User or runtime error.
		if errors.Is(err, context.Canceled) {
			err = errors.New(i18n.G("Service took too long to respond. Disconnecting client."))
		}
		log.Error(err)
		return 1
	}

	return 0
}

func installSignalHandler(a app) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			switch <-c {
			case syscall.SIGINT:
				fallthrough
			case syscall.SIGTERM:
				a.Quit()
				return
			case syscall.SIGHUP:
				if a.Hup() {
					return
				}
			}
		}
	}()
}
