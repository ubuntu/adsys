package client

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installVersion() {
	cmd := &cobra.Command{
		Use:   "version",
		Short: i18n.G("Returns version of client and service"),
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return a.getVersion() },
	}
	a.rootCmd.AddCommand(cmd)
}

// getVersion returns the current server and client versions.
func (a App) getVersion() (err error) {
	fmt.Printf(i18n.G("%s\t%s")+"\n", CmdName, config.Version)

	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.Version(a.ctx, &adsys.Empty{})
	if err != nil {
		return err
	}

	for {
		version, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		fmt.Printf(i18n.G("%s\t\t%s")+"\n", "adsysd", version.GetVersion())
	}

	return nil
}
