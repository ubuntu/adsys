package commands

import (
	"fmt"

	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	watchdconfig "github.com/ubuntu/adsys/internal/config/watchd"
	"github.com/ubuntu/adsys/internal/consts"
)

func (a *App) installVersion() {
	cmd := &cobra.Command{
		Use:   "version",
		Short: gotext.Get("Returns version of service and exits"),
		Args:  cobra.NoArgs,
		RunE:  func(_ *cobra.Command, _ []string) error { return getVersion() },
	}
	a.rootCmd.AddCommand(cmd)
}

// getVersion returns the current service version.
func getVersion() (err error) {
	fmt.Println(gotext.Get("%s\t%s", watchdconfig.CmdName, consts.Version))
	return nil
}
