package client

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/grpc/grpcerror"
	"github.com/ubuntu/adsys/internal/i18n"
)

// CmdName is the binary name for the client.
const CmdName = "adsysctl"

// App encapsulate commands and options of the CLI, which can be controlled by env variables.
type App struct {
	rootCmd cobra.Command
	viper   *viper.Viper

	ctx    context.Context
	cancel context.CancelFunc

	config daemonConfig
}

type daemonConfig struct {
	Verbose       int
	Socket        string
	ClientTimeout int `mapstructure:"client_timeout"`
}

// New registers commands and return a new App.
func New() *App {
	a := App{}
	a.ctx, a.cancel = context.WithCancel(context.Background())
	a.rootCmd = cobra.Command{
		Use:   fmt.Sprintf("%s COMMAND", CmdName),
		Short: i18n.G("AD integration client"),
		Long:  i18n.G(`Active Directory integration bridging toolset command line tool.`),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// command parsing has been successful. Returns runtime (or configuration) error now and so, don’t print usage.
			a.rootCmd.SilenceUsage = true
			err := config.Init("adsys", a.rootCmd, a.viper, func(refreshed bool) error {
				var newConfig daemonConfig
				if err := config.LoadConfig(&newConfig, a.viper); err != nil {
					return err
				}

				// First run: just init configuration.
				if !refreshed {
					a.config = newConfig
					return nil
				}

				// Config reload

				// No change in config file: skip.
				if a.config == newConfig {
					return nil
				}

				// Reload necessary parts
				oldVerbose := a.config.Verbose
				a.config = newConfig
				if oldVerbose != a.config.Verbose {
					config.SetVerboseMode(a.config.Verbose)
				}
				// Timeout reload is ignored
				return nil
			})
			// Set configured verbose status for the daemon.
			config.SetVerboseMode(a.config.Verbose)
			return err
		},
		Args: cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE: cmdhandler.NoCmd,
		// We display usage error ourselves
		SilenceErrors: true,
	}
	a.viper = viper.New()

	cmdhandler.InstallVerboseFlag(&a.rootCmd, a.viper)
	cmdhandler.InstallConfigFlag(&a.rootCmd, true)
	cmdhandler.InstallSocketFlag(&a.rootCmd, a.viper, consts.DefaultSocket)

	a.rootCmd.PersistentFlags().IntP("timeout", "t", consts.DefaultClientTimeout, i18n.G("time in seconds before cancelling the client request when the server gives no result. 0 for no timeout."))
	decorate.LogOnError(a.viper.BindPFlag("client_timeout", a.rootCmd.PersistentFlags().Lookup("timeout")))

	// subcommands
	a.installDoc()
	a.installPolicy()
	a.installService()
	a.installVersion()

	return &a
}

// Run executes the command and associated process. It returns an error on syntax/usage error.
func (a *App) Run() error {
	err := a.rootCmd.Execute()
	return grpcerror.Format(err, "adsys")
}

// UsageError returns if the error is a command parsing or runtime one.
func (a App) UsageError() bool {
	return !a.rootCmd.SilenceUsage
}

// Hup call Quit() and return true to signal quitting.
func (a *App) Hup() (shouldQuit bool) {
	a.Quit()
	return true
}

// Quit exits and send an cancellation request to the service.
func (a *App) Quit() {
	a.cancel()
}

// RootCmd returns a copy of the root command for the app. Shouldn’t be in general necessary apart when running generators.
func (a App) RootCmd() cobra.Command {
	return a.rootCmd
}

func (a App) getTimeout() time.Duration {
	return time.Duration(a.config.ClientTimeout * int(time.Second))
}

// SetArgs changes the root command args. Shouldn’t be in general necessary apart for integration tests.
func (a *App) SetArgs(args []string) {
	a.rootCmd.SetArgs(args)
}
