package client

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
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
}

func (c daemonConfig) Verbosity() int {
	return c.Verbose
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
			return config.Configure("adsys", a.rootCmd, func() error {
				return config.DefaultLoadConfig(&a.config)
			})
		},
		Args: cmdhandler.SubcommandsRequiredWithSuggestions,
		Run:  cmdhandler.NoCmd,
		// We display usage error ourselves
		SilenceErrors: true,
	}

	cmdhandler.InstallVerboseFlag(&a.rootCmd)

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
