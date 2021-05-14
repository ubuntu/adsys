package client

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installVersion() {
	cmd := &cobra.Command{
		Use:               "version",
		Short:             i18n.G("Returns version of client and service"),
		Args:              cobra.NoArgs,
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(cmd *cobra.Command, args []string) error { return a.getVersion() },
	}
	a.rootCmd.AddCommand(cmd)
}

// getVersion returns the current server and client versions.
func (a App) getVersion() (err error) {
	fmt.Printf(i18n.G("%s\t%s")+"\n", CmdName, consts.Version)

	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.Version(a.ctx, &adsys.Empty{})
	if err != nil {
		return err
	}

	version, err := singleMsg(stream)
	if err != nil {
		return err
	}
	fmt.Printf(i18n.G("%s\t\t%s")+"\n", "adsysd", version)

	return nil
}
