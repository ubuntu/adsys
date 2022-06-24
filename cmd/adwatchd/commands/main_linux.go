package commands

import (
	"context"
	"os"
	"syscall"

	"github.com/kardianos/service"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"golang.org/x/sys/unix"
)

// Quit gracefully exits the app. Shouldn't be in general necessary apart for
// integration tests where we might need to close the app manually.
func (a *App) Quit(sig syscall.Signal) error {
	a.WaitReady()
	if !service.Interactive() {
		log.Debug(context.Background(), i18n.G("Calling quit on a non-interactive service is useless"))
		return nil
	}

	p := os.Getpid()

	pgid, err := unix.Getpgid(p)
	if err != nil {
		return err
	}

	// use pgid, ref: http://unix.stackexchange.com/questions/14815/process-descendants
	if pgid == p {
		p = -1 * p
	}

	target, err := os.FindProcess(p)
	if err != nil {
		return err
	}
	return target.Signal(sig)
}
