package daemon

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/i18n"
)

// CmdName is the binary name for the daemon.
const CmdName = "adsysd"

// App encapsulate commands and options of the daemon, which can be controlled by env variables and config files.
type App struct {
	rootCmd   cobra.Command
	err       error
	verbosity int
}

// New registers commands and return a new App.
func New() App {
	a := App{}
	a.rootCmd = cobra.Command{
		Use:   fmt.Sprintf("%s COMMAND", CmdName),
		Short: i18n.G("AD integration daemon"),
		Long:  i18n.G(`Active Directory integration bridging toolset daemon.`),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			config.SetVerboseMode(a.verbosity)
		},
		Args: cmdhandler.SubcommandsRequiredWithSuggestions,
		Run:  cmdhandler.NoCmd,
		// We display usage error ourselves
		SilenceErrors: true,
	}

	cmdhandler.InstallVerboseFlag(&a.rootCmd, &a.verbosity)

	// subcommands
	cmdhandler.InstallCompletionCmd(&a.rootCmd)
	a.installVersion()

	return a
}

// Run executes the command and associated process. It returns an error on syntax/usage error.
func (a App) Run() error {
	return a.rootCmd.Execute()
}

// Err returns the potential error returned by the command.
func (a App) Err() error {
	return a.err
}

// Hup reloads configuration file on disk and return false to signal you shouldn't quit.
func (a App) Hup() (shouldQuit bool) {
	return false
}

// Quit gracefully shutdown the service.
func (a App) Quit() {
}
