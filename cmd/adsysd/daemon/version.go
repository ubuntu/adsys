package daemon

import (
	"fmt"

	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/consts"
)

func (a *App) installVersion() {
	cmd := &cobra.Command{
		Use:   "version",
		Short: gotext.Get("Returns version of service and exits"),
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return getVersion() },
	}
	a.rootCmd.AddCommand(cmd)
}

// getVersion returns the current service version.
func getVersion() (err error) {
	fmt.Println(gotext.Get("%s\t%s", CmdName, consts.Version))
	return nil
}
