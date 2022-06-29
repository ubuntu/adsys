package watchdservice

import (
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/ubuntu/adsys/internal/i18n"
	"golang.org/x/exp/slices"
)

// execStart represents the ExecStart option of a systemd service. It maps to
// the D-Bus property org.freedesktop.systemd1.Service.ExecStart.
// Type signature: a(sasbttttuii)
// Refer to the org.freedesktop.systemd1(5) man page for more information.
type execStart struct {
	BinPath string   // the binary path to execute
	Args    []string // an array with all arguments to pass to the executed command, starting with argument 0

	A bool
	B uint64
	C uint64
	D uint64
	E uint64
	F uint32
	G int32
	H int32
}

// serviceArgs returns the absolute binary path and the full command line
// arguments for the service.
func (s *WatchdService) serviceArgs() (string, string, error) {
	bus, err := newDbusConection()
	if err != nil {
		return "", "", err
	}

	svcUnit := bus.Object("org.freedesktop.systemd1",
		dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/systemd1/unit/%s",
			strings.ReplaceAll(strings.ReplaceAll(fmt.Sprintf("%s.service", s.Name()), ".", "_2e"), "-", "_2d"))))

	var execStarts []execStart
	err = svcUnit.StoreProperty("org.freedesktop.systemd1.Service.ExecStart", &execStarts)
	if err != nil || len(execStarts) == 0 {
		return "", "", fmt.Errorf(i18n.G("could not find %s unit on systemd bus: no service installed? %v"), s.Name(), err)
	}

	binPath := execStarts[0].BinPath
	args := execStarts[0].Args
	idx := slices.IndexFunc(args, func(arg string) bool { return arg == "run" })
	argsStr := strings.Join(args[idx+1:], " ")

	return binPath, argsStr, nil
}

// newDbusConection returns a new authenticated private connection to the system
// bus.
func newDbusConection() (*dbus.Conn, error) {
	bus, err := dbus.SystemBusPrivate()
	if err != nil {
		return nil, err
	}
	if err = bus.Auth(nil); err != nil {
		_ = bus.Close()
		return nil, err
	}
	if err = bus.Hello(); err != nil {
		_ = bus.Close()
		return nil, err
	}

	return bus, nil
}
