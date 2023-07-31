package client

import (
	"fmt"

	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/consts"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (a *App) installVersion() {
	cmd := &cobra.Command{
		Use:               "version",
		Short:             gotext.Get("Returns version of client and service"),
		Args:              cobra.NoArgs,
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(cmd *cobra.Command, args []string) error { return a.getVersion() },
	}
	a.rootCmd.AddCommand(cmd)
}

// getVersion returns the current server and client versions.
func (a App) getVersion() (err error) {
	fmt.Println(gotext.Get("%s\t%s", CmdName, consts.Version))

	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.Version(a.ctx, &emptypb.Empty{})
	if err != nil {
		return err
	}

	version, err := singleMsg(stream)
	if err != nil {
		return err
	}
	fmt.Println(gotext.Get("%s\t\t%s", "adsysd", version))

	return nil
}
