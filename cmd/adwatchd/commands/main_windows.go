package commands

import (
	"fmt"
	"os"
	"syscall"

	"github.com/kardianos/service"
	"github.com/ubuntu/adsys/internal/i18n"
	"golang.org/x/sys/windows"
)

// Quit gracefully exits the app. Shouldn't be in general necessary apart for
// integration tests where we might need to close the app manually.
func (a *App) Quit(_ syscall.Signal) error {
	a.WaitReady()
	if !service.Interactive() {
		return fmt.Errorf(i18n.G("not running in interactive mode"))
	}

	dll, err := windows.LoadDLL("kernel32.dll")
	if err != nil {
		return err
	}
	defer dll.Release()

	pid := os.Getpid()

	f, err := dll.FindProc("AttachConsole")
	if err != nil {
		return err
	}
	r1, _, err := f.Call(uintptr(pid))
	if r1 == 0 && err != syscall.ERROR_ACCESS_DENIED {
		return err
	}

	f, err = dll.FindProc("SetConsoleCtrlHandler")
	if err != nil {
		return err
	}
	r1, _, err = f.Call(0, 1)
	if r1 == 0 {
		return err
	}
	f, err = dll.FindProc("GenerateConsoleCtrlEvent")
	if err != nil {
		return err
	}
	r1, _, err = f.Call(windows.CTRL_BREAK_EVENT, uintptr(pid))
	if r1 == 0 {
		return err
	}
	r1, _, err = f.Call(windows.CTRL_C_EVENT, uintptr(pid))
	if r1 == 0 {
		return err
	}
	return nil
}
