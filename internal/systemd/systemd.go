// Package systemd provides a wrapper around systemd dbus API that allows basic
// service operations (start/stop/enable/disable).
package systemd

import (
	"context"
	"errors"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/decorate"
)

// DefaultCaller is the default implementation of the systemd wrapper.
type DefaultCaller struct {
	conn *systemdDbus.Conn
}

// jobDone is the string returned by systemd when a job completed successfully.
const jobDone = "done"

// New returns a new systemdCaller using the given dbus connection.
func New(bus *dbus.Conn) (*DefaultCaller, error) {
	conn, err := systemdDbus.NewConnection(func() (*dbus.Conn, error) { return bus, nil })
	if err != nil {
		return nil, err
	}

	return &DefaultCaller{conn: conn}, nil
}

// StartUnit starts the given unit.
func (s DefaultCaller) StartUnit(ctx context.Context, unit string) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to start unit %s"), unit)

	reschan := make(chan string)
	if _, err = s.conn.StartUnitContext(ctx, unit, "replace", reschan); err != nil {
		return err
	}

	if job := <-reschan; job != jobDone {
		return errors.New(i18n.G("start job failed"))
	}
	return nil
}

// StopUnit stops the given unit.
func (s DefaultCaller) StopUnit(ctx context.Context, unit string) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to stop unit %s"), unit)

	reschan := make(chan string)
	if _, err = s.conn.StopUnitContext(ctx, unit, "replace", reschan); err != nil {
		return err
	}

	if job := <-reschan; job != jobDone {
		return errors.New(i18n.G("stop job failed"))
	}
	return nil
}

// EnableUnit enables the given unit.
func (s DefaultCaller) EnableUnit(ctx context.Context, unit string) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to enable unit %s"), unit)

	if _, _, err := s.conn.EnableUnitFilesContext(ctx, []string{unit}, false, true); err != nil {
		return err
	}
	return nil
}

// DisableUnit disables the given unit.
func (s DefaultCaller) DisableUnit(ctx context.Context, unit string) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to disable unit %s"), unit)

	if _, err := s.conn.DisableUnitFilesContext(ctx, []string{unit}, false); err != nil {
		return err
	}
	return nil
}

// DaemonReload scans and reloads unit files. This is an equivalent to systemctl daemon-reload.
func (s DefaultCaller) DaemonReload(ctx context.Context) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to reload units"))

	return s.conn.ReloadContext(ctx)
}
