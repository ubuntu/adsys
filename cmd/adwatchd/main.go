// Package main is the adwatchd entry point to start the Windows or Linux service.
package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/cmd/adwatchd/commands"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/po"
	"github.com/ubuntu/go-i18n"
)

type app interface {
	Run() error
	UsageError() bool
	Quit(syscall.Signal) error
}

func run(a app) int {
	i18n.InitI18nDomain(consts.TEXTDOMAIN, po.Files)
	defer installSignalHandler(a)()
	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		DisableTimestamp:       true,

		// support colors on Windows, ref:
		// https://github.com/sirupsen/logrus/pull/957
		ForceColors: true,
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

func installSignalHandler(a app) func() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			switch v, ok := <-c; v {
			case syscall.SIGINT, syscall.SIGTERM:
				if err := a.Quit(syscall.SIGINT); err != nil {
					log.Fatalf("failed to quit: %v", err)
				}
				return
			default:
				// channel was closed: we exited
				if !ok {
					return
				}
			}
		}
	}()

	return func() {
		signal.Stop(c)
		close(c)
		wg.Wait()
	}
}

func main() {
	os.Exit(run(commands.New()))
}
