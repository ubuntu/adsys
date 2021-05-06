package authorizer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	sdbus sync.Once

	dbusStop sync.WaitGroup
)

// StartLocalSystemBus allows to start and set environment variable to a local bus, preventing polluting system ones
// The bus is shutted down when the test ends.
func StartLocalSystemBus(t *testing.T) {
	t.Helper()

	dbusStop.Add(1)

	sdbus.Do(func() {
		dir := t.TempDir()
		savedDbusSystemAddress := os.Getenv("DBUS_SYSTEM_BUS_ADDRESS")
		config := filepath.Join(dir, "dbus.config")
		os.WriteFile(config, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
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
</busconfig>`), 0666)
		ctx, stopDbus := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, "dbus-daemon", "--print-address=1", "--config-file="+config)
		dbusStdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatalf("couldn't get stdout of dbus-daemon: %v", err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatalf("couldn't start dbus-daemon: %v", err)
		}
		dbusAddr := make([]byte, 256)
		n, err := dbusStdout.Read(dbusAddr)
		if err != nil {
			t.Fatalf("couldn't get dbus address: %v", err)
		}
		dbusAddr = dbusAddr[:n]
		if err := os.Setenv("DBUS_SYSTEM_BUS_ADDRESS", string(dbusAddr)); err != nil {
			t.Fatalf("couldn't set DBUS_SYSTEM_BUS_ADDRESS: %v", err)
		}

		t.Cleanup(func() {
			// Wait for all tests that started to be done to cleanup properly
			dbusStop.Wait()
			stopDbus()
			cmd.Wait()

			if err := os.Setenv("DBUS_SYSTEM_BUS_ADDRESS", savedDbusSystemAddress); err != nil {
				t.Errorf("couldn't restore DBUS_SYSTEM_BUS_ADDRESS: %v", err)
			}

			// Restore dbus system launcher
			sdbus = sync.Once{}
			dbusStop = sync.WaitGroup{}
		})
	})

	t.Cleanup(dbusStop.Done)
}
