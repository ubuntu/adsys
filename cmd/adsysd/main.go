package main

import (
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

//go:generate go run ../generate_compl_man_readme.go completion ../../generated
//go:generate go run ../generate_compl_man_readme.go man ../../generated
//go:generate go run ../generate_compl_man_readme.go update-readme

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
