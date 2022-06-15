package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installService() {

	cmd := &cobra.Command{
		Use:   "service",
		Short: i18n.G("Manages the adwatchd service"),
		Long:  i18n.G(`The service command allows the user to interact with the adwatchd service. It can manage and query the service status, and also install and uninstall the service.`),
	}

	// Install service subcommands.
	cmd.AddCommand(a.serviceStart())
	cmd.AddCommand(a.serviceStop())
	cmd.AddCommand(a.serviceRestart())
	cmd.AddCommand(a.serviceStatus())
	cmd.AddCommand(a.serviceInstall())
	cmd.AddCommand(a.serviceUninstall())

	// Add the service command to the root command.
	a.rootCmd.AddCommand(cmd)
}

func (a *App) serviceStart() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: i18n.G("Starts the service"),
		Long:  i18n.G("Starts the adwatchd service."),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.service.Start(context.Background())
		},
	}
}

func (a *App) serviceStop() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: i18n.G("Stops the service"),
		Long:  i18n.G("Stops the adwatchd service."),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.service.Stop(context.Background())
		},
	}
}

func (a *App) serviceRestart() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: i18n.G("Restarts the service"),
		Long:  i18n.G("Restarts the adwatchd service."),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.service.Restart(context.Background())
		},
	}
}

func (a *App) serviceStatus() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: i18n.G("Returns service status"),
		Long:  i18n.G("Returns the status of the adwatchd service."),
		Run: func(cmd *cobra.Command, args []string) {
			if status, err := a.service.Status(context.Background()); err != nil {
				fmt.Println(err)
			} else {
				fmt.Println(status)
			}
		},
	}
}

func (a *App) serviceInstall() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: i18n.G("Installs the service"),
		Long: i18n.G(`Installs the adwatchd service.
		
The service will be installed as a Windows service.
`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.service.Install(context.Background())
		},
	}

	return cmd
}

func (a *App) serviceUninstall() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: i18n.G("Uninstalls the service"),
		Long:  i18n.G("Uninstalls the adwatchd service."),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.service.Uninstall(context.Background())
		},
	}
}
