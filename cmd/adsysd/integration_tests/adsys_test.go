package adsys_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
)

func TestStartAndStopDaemon(t *testing.T) {
	_, quit := runDaemon(t)
	quit()
}

func runDaemon(t *testing.T) (conf string, quit func()) {
	t.Helper()

	dir := t.TempDir()

	// Create config
	confFile := filepath.Join(dir, "adsys.yaml")
	err := os.WriteFile(confFile, []byte(fmt.Sprintf(`
# Service and client configuration
verbose: 2
socket: %s/socket

# Service only configuration
cache_dir: %s/cache
run_dir: %s/run
servicetimeout: 30
ad_server: warthogs.biz
ad_domain: ldap://adc.warthogs.biz
`, dir, dir, dir)), 0644)
	require.NoError(t, err, "Setup: config file should be created")

	var wg sync.WaitGroup
	d := daemon.New()
	os.Args = []string{"tests", "-c", confFile}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := d.Run()
		require.NoError(t, err, "daemon should exit with no error")
	}()

	d.WaitReady()

	return confFile, func() {
		done := make(chan struct{})
		go func() {
			d.Quit()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("daemon should have stopped within second")
		}

		wg.Wait()
	}
}
