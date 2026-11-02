package client

import (
	"errors"
	"time"

	"github.com/spf13/cobra"
)

func (a *App) AddWaitCommand() {
	a.rootCmd.AddCommand(&cobra.Command{
		Use: "wait",
		RunE: func(_ *cobra.Command, _ []string) error {
			select {
			case <-time.After(50 * time.Millisecond):
				return errors.New("End of wait command reached")
			case <-a.ctx.Done():
			}
			return nil
		},
	})
}
