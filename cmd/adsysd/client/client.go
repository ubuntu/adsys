package client

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
)

// CmdName is the binary name for the client.
const CmdName = "adsysctl"

// App encapsulate commands and options of the CLI, which can be controlled by env variables.
type App struct {
	rootCmd cobra.Command

	config daemonConfig
}

type daemonConfig struct {
	Verbose int
	Socket  string
}

// New registers commands and return a new App.
func New() *App {
	a := App{}
	a.rootCmd = cobra.Command{
		Use:   fmt.Sprintf("%s COMMAND", CmdName),
		Short: i18n.G("AD integration client"),
		Long:  i18n.G(`Active Directory integration bridging toolset command line tool.`),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// command parsing has been successfull. Returns runtime (or configuration) error now and so, don’t print usage.
			a.rootCmd.SilenceUsage = true
			return config.Configure("adsys", a.rootCmd, func(configPath string) error {
				var newConfig daemonConfig
				if err := config.DefaultLoadConfig(&newConfig); err != nil {
					return err
				}

				// config reload
				if configPath != "" {
					// No change in config file: skip.
					if a.config == newConfig {
						return nil
					}
					log.Infof(context.Background(), "Config file %q changed. Reloading.", configPath)
				}

				oldVerbose := a.config.Verbose
				a.config = newConfig

				// Reload necessary parts
				if oldVerbose != a.config.Verbose {
					config.SetVerboseMode(a.config.Verbose)
				}
				return nil
			})
		},
		Args: cmdhandler.SubcommandsRequiredWithSuggestions,
		Run:  cmdhandler.NoCmd,
		// We display usage error ourselves
		SilenceErrors: true,
	}

	cmdhandler.InstallVerboseFlag(&a.rootCmd)
	cmdhandler.InstallSocketFlag(&a.rootCmd, config.DefaultSocket)

	// subcommands
	cmdhandler.InstallCompletionCmd(&a.rootCmd)
	a.installService()
	a.installVersion()

	return &a
}

// Run executes the command and associated process. It returns an error on syntax/usage error.
func (a *App) Run() error {
	return a.rootCmd.Execute()
}

// UsageError returns if the error is a command parsing or runtime one.
func (a App) UsageError() bool {
	return !a.rootCmd.SilenceUsage
}

// Hup call Quit() and return true to signal quitting.
func (a App) Hup() (shouldQuit bool) {
	a.Quit()
	return true
}

// Quit exits and send an cancellation request to the service.
func (a App) Quit() {
}

// RootCmd returns a copy of the root command for the app. Shouldn’t be in general necessary apart when running generators.
func (a App) RootCmd() cobra.Command {
	return a.rootCmd
}
