package daemon

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installVersion() {
	cmd := &cobra.Command{
		Use:   "version",
		Short: i18n.G("Returns version of service and exits"),
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, args []string) { a.err = getVersion() },
	}
	a.rootCmd.AddCommand(cmd)
}

// getVersion returns the current service version.
func getVersion() (err error) {
	fmt.Printf(i18n.G("%s\t%s")+"\n", CmdName, config.Version)
	return nil
}
