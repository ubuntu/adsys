package testutils

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/require"
)

var (
	sdbus sync.Once

	sdbusMU                sync.Mutex
	nbRunningTestsSdbus    uint
	stopDbus               context.CancelFunc
	dbusCmd                *exec.Cmd
	config                 string
	savedDbusSystemAddress string
)

// StartLocalSystemBus allows to start and set environment variable to a local bus, preventing polluting system ones.
func StartLocalSystemBus() func() {
	sdbusMU.Lock()
	defer sdbusMU.Unlock()
	nbRunningTestsSdbus++

	sdbus.Do(func() {
		dir, err := os.MkdirTemp("", "adsys-tests-dbus")
		if err != nil {
			log.Fatalf("Setup: can’t create dbus system directory: %v", err)
		}

		savedDbusSystemAddress = os.Getenv("DBUS_SYSTEM_BUS_ADDRESS")
		config = filepath.Join(dir, "dbus.config")
		err = os.WriteFile(config, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <keep_umask/>
  <listen>unix:tmpdir=/tmp</listen>
  <standard_system_servicedirs />
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>`), 0600)
		if err != nil {
			log.Fatalf("Setup: can’t create dbus configuration: %v", err)
		}
		var ctx context.Context
		ctx, stopDbus = context.WithCancel(context.Background())
		// #nosec G204 - this is only for tests, we are in control of the config
		dbusCmd = exec.CommandContext(ctx, "dbus-daemon", "--print-address=1", "--config-file="+config)
		dbusStdout, err := dbusCmd.StdoutPipe()
		if err != nil {
			_ = os.RemoveAll(dir)
			log.Fatalf("couldn't get stdout of dbus-daemon: %v", err)
		}
		if err := dbusCmd.Start(); err != nil {
			_ = os.RemoveAll(dir)
			log.Fatalf("couldn't start dbus-daemon: %v", err)
		}
		dbusAddr := make([]byte, 256)
		n, err := dbusStdout.Read(dbusAddr)
		if err != nil {
			_ = os.RemoveAll(dir)
			log.Fatalf("couldn't get dbus address: %v", err)
		}
		dbusAddr = dbusAddr[:n]
		if err := os.Setenv("DBUS_SYSTEM_BUS_ADDRESS", string(dbusAddr)); err != nil {
			_ = os.RemoveAll(dir)
			log.Fatalf("couldn't set DBUS_SYSTEM_BUS_ADDRESS: %v", err)
		}
	})

	return func() {
		sdbusMU.Lock()
		defer sdbusMU.Unlock()
		nbRunningTestsSdbus--

		if nbRunningTestsSdbus != 0 {
			return
		}

		stopDbus()
		// dbus command is killed
		_ = dbusCmd.Wait()

		if err := os.RemoveAll(filepath.Dir(config)); err != nil {
			log.Fatalf("couldn't remove dbus configuration directory: %v", err)
		}

		if err := os.Setenv("DBUS_SYSTEM_BUS_ADDRESS", savedDbusSystemAddress); err != nil {
			log.Fatalf("couldn't restore DBUS_SYSTEM_BUS_ADDRESS: %v", err)
		}

		// Restore dbus system launcher
		sdbus = sync.Once{}
	}
}

// NewDbusConn returns a system dbus connection which automatically close on test shutdown.
func NewDbusConn(t *testing.T) *dbus.Conn {
	t.Helper()

	bus, err := dbus.SystemBusPrivate()
	require.NoError(t, err, "Setup: can’t get a private system bus")

	t.Cleanup(func() {
		err = bus.Close()
		require.NoError(t, err, "Teardown: can’t close system dbus connection")
	})
	err = bus.Auth(nil)
	require.NoError(t, err, "Setup: can’t auth on private system bus")
	err = bus.Hello()
	require.NoError(t, err, "Setup: can’t send hello message on private system bus")

	return bus
}
