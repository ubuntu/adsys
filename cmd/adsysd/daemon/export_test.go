package daemon

import (
	"fmt"
	"time"
)

func (a *App) IsReady(timeout time.Duration) error {
	select {
	case <-a.ready:
	case <-time.After(timeout):
		return fmt.Errorf("App not ready after %s", timeout.String())
	}
	return nil
}

func (a App) Verbosity() int {
	return a.config.Verbose
}
