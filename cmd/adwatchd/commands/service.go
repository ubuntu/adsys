package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	watchdconfig "github.com/ubuntu/adsys/internal/config/watchd"
	"github.com/ubuntu/adsys/internal/i18n"
)

var flagsToHide = []string{"config"}

func (a *App) installService() {
	cmd := &cobra.Command{
		Use:   "service COMMAND",
		Short: fmt.Sprintf(i18n.G("Manages the %s service"), watchdconfig.CmdName),
		Long:  fmt.Sprintf(i18n.G(`The service command allows the user to interact with the %s service. It can manage and query the service status, and also install and uninstall the service.`), watchdconfig.CmdName),
		Args:  cmdhandler.SubcommandsRequiredWithSuggestions,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if a.rootCmd.Flags().Changed("config") {
				return fmt.Errorf(i18n.G("cannot use --config with this subcommand"))
			}

			return a.rootCmd.PersistentPreRunE(cmd, args)
		},
		RunE: cmdhandler.NoCmd,
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
	cmd := &cobra.Command{
		Use:   "start",
		Short: i18n.G("Starts the service"),
		Long:  fmt.Sprintf(i18n.G("Starts the %s service."), watchdconfig.CmdName),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.service.Start(context.Background())
		},
	}
	// Hide config flag from the command.
	cmd.SetHelpFunc(cmdhandler.HideFlags(flagsToHide))

	return cmd
}

func (a *App) serviceStop() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: i18n.G("Stops the service"),
		Long:  fmt.Sprintf(i18n.G("Stops the %s service."), watchdconfig.CmdName),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.service.Stop(context.Background())
		},
	}
	// Hide config flag from the command.
	cmd.SetHelpFunc(cmdhandler.HideFlags(flagsToHide))

	return cmd
}

func (a *App) serviceRestart() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restart",
		Short: i18n.G("Restarts the service"),
		Long:  fmt.Sprintf(i18n.G("Restarts the %s service."), watchdconfig.CmdName),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.service.Restart(context.Background())
		},
	}

	// Hide config flag from the command.
	cmd.SetHelpFunc(cmdhandler.HideFlags(flagsToHide))

	return cmd
}

func (a *App) serviceStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: i18n.G("Returns service status"),
		Long:  fmt.Sprintf(i18n.G("Returns the status of the %s service."), watchdconfig.CmdName),
		RunE: func(cmd *cobra.Command, args []string) error {
			status, err := a.service.Status(context.Background())
			if err != nil {
				return err
			}
			fmt.Println(status)

			return nil
		},
	}

	// Hide config flag from the command.
	cmd.SetHelpFunc(cmdhandler.HideFlags(flagsToHide))

	return cmd
}

func (a *App) serviceInstall() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: i18n.G("Installs the service"),
		Long: fmt.Sprintf(i18n.G(`Installs the %s service.

The service will be installed as a Windows service.
`), watchdconfig.CmdName),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Call the root command's PersistentPreRunE directly as this is the
			// only service subcommand that allows specifying a config file.
			return a.rootCmd.PersistentPreRunE(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.service.Install(context.Background())
		},
	}
}

func (a *App) serviceUninstall() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: i18n.G("Uninstalls the service"),
		Long:  fmt.Sprintf(i18n.G("Uninstalls the %s service."), watchdconfig.CmdName),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.service.Uninstall(context.Background())
		},
	}

	// Hide config flag from the command.
	cmd.SetHelpFunc(cmdhandler.HideFlags(flagsToHide))

	return cmd
}
