package daemon

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/daemon"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
)

// CmdName is the binary name for the daemon.
const CmdName = "adsysd"

// App encapsulate commands and options of the daemon, which can be controlled by env variables and config files.
type App struct {
	rootCmd cobra.Command

	config daemonConfig
	daemon *daemon.Daemon
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
		Short: i18n.G("AD integration daemon"),
		Long:  i18n.G(`Active Directory integration bridging toolset daemon.`),
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
				oldSocket := a.config.Socket
				a.config = newConfig

				// Reload necessary parts
				if oldVerbose != a.config.Verbose {
					config.SetVerboseMode(a.config.Verbose)
				}
				if oldSocket != a.config.Socket {
					a.changeServerSocket(a.config.Socket)
				}
				return nil
			})
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			adsys := adsysservice.Service{}
			d, err := daemon.New(adsys.RegisterGRPCServer, a.config.Socket)
			if err != nil {
				return err
			}
			a.daemon = d
			return a.daemon.Listen()
		},
		// We display usage error ourselves
		SilenceErrors: true,
	}

	cmdhandler.InstallVerboseFlag(&a.rootCmd)
	cmdhandler.InstallSocketFlag(&a.rootCmd, config.DefaultSocket)

	// subcommands
	cmdhandler.InstallCompletionCmd(&a.rootCmd)
	a.installVersion()

	return &a
}

// changeServerSocket change the socket on server.
func (a *App) changeServerSocket(socket string) error {
	if a.daemon == nil {
		return nil
	}
	return a.daemon.UseSocket(socket)
}

// Run executes the command and associated process. It returns an error on syntax/usage error.
func (a *App) Run() error {
	return a.rootCmd.Execute()
}

// UsageError returns if the error is a command parsing or runtime one.
func (a App) UsageError() bool {
	return !a.rootCmd.SilenceUsage
}

// Hup reloads configuration file on disk and return false to signal you shouldn't quit.
func (a App) Hup() (shouldQuit bool) {
	return false
}

// Quit gracefully shutdown the service.
func (a App) Quit() {
	a.daemon.Quit()
}

// RootCmd returns a copy of the root command for the app. Shouldn’t be in general necessary apart when running generators.
func (a App) RootCmd() cobra.Command {
	return a.rootCmd
}
