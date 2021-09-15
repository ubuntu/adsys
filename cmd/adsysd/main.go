package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/cmd/adsysd/client"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/i18n"
)

//go:generate go run ../generate_completion_documentation.go completion ../../generated
//go:generate go run ../generate_completion_documentation.go man ../../generated
//go:generate go run ../generate_completion_documentation.go update-readme
//go:generate go run ../generate_completion_documentation.go update-doc-cli-ref

func main() {
	var a app
	switch filepath.Base(os.Args[0]) {
	case daemon.CmdName:
		a = daemon.New()
	default:
		a = client.New()
	}
	os.Exit(run(a))
}

type app interface {
	Run() error
	UsageError() bool
	Hup() bool
	Quit()
}

func run(a app) int {
	i18n.InitI18nDomain(consts.TEXTDOMAIN)
	defer installSignalHandler(a)()

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

func installSignalHandler(a app) func() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			switch v, ok := <-c; v {
			case syscall.SIGINT:
				fallthrough
			case syscall.SIGTERM:
				a.Quit()
				return
			case syscall.SIGHUP:
				if a.Hup() {
					a.Quit()
					return
				}
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
