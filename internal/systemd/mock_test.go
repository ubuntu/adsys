package systemd_test

import (
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/ubuntu/adsys/internal/consts"
)

var s systemdBus

type systemdBus struct {
	conn *dbus.Conn

	nextJobID   int
	reloadError bool

	mu sync.Mutex
}

var errNoSuchUnit = dbus.NewError(fmt.Sprintf("%s.NoSuchUnit", consts.SystemdDbusRegisteredName), []interface{}{"Unit not-a-service.service not found."})

const (
	absentUnit  = "not-a-service.service"
	failingUnit = "fail-to-start-stop.service"
)

func (s *systemdBus) StartUnit(name string, _ string) (dbus.ObjectPath, *dbus.Error) {
	if name == absentUnit {
		return dbus.ObjectPath("/"), errNoSuchUnit
	}

	return s.emitJobSignals(name), nil
}

func (s *systemdBus) StopUnit(name string, _ string) (dbus.ObjectPath, *dbus.Error) {
	if name == absentUnit {
		return dbus.ObjectPath("/"), errNoSuchUnit
	}

	return s.emitJobSignals(name), nil
}

func (s *systemdBus) EnableUnitFiles(names []string, _ bool, _ bool) (bool, [][]string, *dbus.Error) {
	if len(names) != 1 {
		panic("method is only expected to be called with a single name")
	}

	if name := names[0]; name == absentUnit {
		return false, nil, errNoSuchUnit
	}

	return true, [][]string{{"symlink", "/from/path", "/to/path"}}, nil
}

func (s *systemdBus) DisableUnitFiles(names []string, _ bool) ([][]string, *dbus.Error) {
	if len(names) != 1 {
		panic("method is only expected to be called with a single name")
	}

	if name := names[0]; name == absentUnit {
		return nil, errNoSuchUnit
	}

	return [][]string{{"symlink", "/from/path", "/to/path"}}, nil
}

func (s *systemdBus) Reload() *dbus.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.reloadError {
		return dbus.MakeFailedError(fmt.Errorf("reload error"))
	}

	return nil
}

func (s *systemdBus) setErrorOnReload() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reloadError = true
}

func (s *systemdBus) emitJobSignals(name string) dbus.ObjectPath {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Increment job ID
	s.nextJobID++
	jobPath := dbus.ObjectPath(fmt.Sprintf("%s/Job/%d", consts.SystemdDbusObjectPath, s.nextJobID))

	// Emit JobNew signal
	err := s.conn.Emit(
		dbus.ObjectPath(consts.SystemdDbusObjectPath),
		fmt.Sprintf("%s.JobNew", consts.SystemdDbusManagerInterface),
		s.nextJobID, jobPath, name,
	)
	if err != nil {
		panic(err)
	}

	jobStatus := "done"
	if name == failingUnit {
		jobStatus = "failed"
	}

	// Emit JobRemoved signal
	err = s.conn.Emit(
		dbus.ObjectPath(consts.SystemdDbusObjectPath),
		fmt.Sprintf("%s.JobRemoved", consts.SystemdDbusManagerInterface),
		s.nextJobID, jobPath, name, jobStatus,
	)
	if err != nil {
		panic(err)
	}

	return jobPath
}
