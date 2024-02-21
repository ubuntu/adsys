package client

import (
	"errors"
	"fmt"
	"io"

	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (a *App) installService() {
	mainCmd := &cobra.Command{
		Use:   "service COMMAND",
		Short: gotext.Get("Service management"),
		Args:  cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:  cmdhandler.NoCmd,
	}
	a.rootCmd.AddCommand(mainCmd)

	cmd := &cobra.Command{
		Use:               "cat",
		Short:             gotext.Get("Print service logs"),
		Args:              cobra.NoArgs,
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(_ *cobra.Command, _ []string) error { return a.serviceCat() },
	}
	mainCmd.AddCommand(cmd)

	cmd = &cobra.Command{
		Use:               "status",
		Short:             gotext.Get("Print service status"),
		Args:              cobra.NoArgs,
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(_ *cobra.Command, _ []string) error { return a.getStatus() },
	}
	mainCmd.AddCommand(cmd)

	var stopForce *bool
	cmd = &cobra.Command{
		Use:               "stop",
		Short:             gotext.Get("Requests to stop the service once all connections are done"),
		Args:              cobra.NoArgs,
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(_ *cobra.Command, _ []string) error { return a.serviceStop(*stopForce) },
	}
	stopForce = cmd.Flags().BoolP("force", "f", false, gotext.Get("force will shut it down immediately and drop existing connections."))
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
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		// TODO: write a ping command writing on stdout PONG and sending that to the client. We can cover it with the cat test
		fmt.Print(msg.GetMsg())
	}

	return nil
}

// getStatus returns the current server status.
func (a App) getStatus() (err error) {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.Status(a.ctx, &adsys.Empty{})
	if err != nil {
		return err
	}

	status, err := singleMsg(stream)
	if err != nil {
		return err
	}
	fmt.Println(status)

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

	if _, err := stream.Recv(); err != nil {
		// Ignore "transport is closing" error if force (i.e immediately drop all connections) was used.
		// EOF check is done on the same line to avoid test coverage drift when the Unavailable error is not triggered,
		// indicating that the underlying transport is already closed before we could get a response.
		// The error is harmless as it indicates that the server has already stopped.
		if (force && status.Code(err) == codes.Unavailable) || errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}

	return nil
}
