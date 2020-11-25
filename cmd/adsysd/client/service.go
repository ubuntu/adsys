package client

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installService() {
	mainCmd := &cobra.Command{
		Use:   "service COMMAND",
		Short: i18n.G("Service management"),
		Args:  cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:  cmdhandler.NoCmd,
	}
	a.rootCmd.AddCommand(mainCmd)

	cmd := &cobra.Command{
		Use:   "cat",
		Short: i18n.G("Print service logs"),
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return a.serviceCat() },
	}
	mainCmd.AddCommand(cmd)

	var stopForce *bool
	cmd = &cobra.Command{
		Use:   "stop",
		Short: i18n.G("Requests to stop the service once all connections are done"),
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return a.serviceStop(*stopForce) },
	}
	stopForce = cmd.Flags().BoolP("force", "f", false, i18n.G("force will shut it down immediately and drop existing connections."))
	mainCmd.AddCommand(cmd)
}

func (a *App) serviceCat() error {
	// No timeout for cat command
	client, err := adsysservice.NewClient(a.config.Socket, 0)
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.Cat(a.ctx, &adsys.Empty{})
	if err != nil {
		return err
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		fmt.Print(msg.GetMsg())
	}

	return nil
}

func (a *App) serviceStop(force bool) error {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.Stop(a.ctx, &adsys.StopRequest{Force: force})
	if err != nil {
		return err
	}

	if _, err := stream.Recv(); err != nil && err != io.EOF {
		return err
	}

	return nil
}
