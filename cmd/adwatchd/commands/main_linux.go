package commands

import (
	"fmt"
	"os"
	"syscall"

	"github.com/kardianos/service"
	"github.com/ubuntu/adsys/internal/i18n"
	"golang.org/x/sys/unix"
)

// Quit gracefully exits the app. Shouldn't be in general necessary apart for
// integration tests where we might need to close the app manually.
func (a *App) Quit(sig syscall.Signal) error {
	a.WaitReady()
	if !service.Interactive() {
		return fmt.Errorf(i18n.G("not running in interactive mode"))
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
