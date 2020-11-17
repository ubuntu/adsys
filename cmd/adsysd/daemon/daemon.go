package daemon

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	Verbose        int
	Socket         string
	ServiceTimeout int
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
				oldTimeout := a.config.ServiceTimeout
				a.config = newConfig

				// Reload necessary parts
				if oldVerbose != a.config.Verbose {
					config.SetVerboseMode(a.config.Verbose)
				}
				if oldSocket != a.config.Socket {
					if err := a.changeServerSocket(a.config.Socket); err != nil {
						log.Error(context.Background(), err)
					}
				}
				if oldTimeout != a.config.ServiceTimeout {
					a.changeServiceTimeout(time.Duration(a.config.ServiceTimeout) * time.Second)
				}
				return nil
			})
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			timeout := time.Duration(a.config.ServiceTimeout) * time.Second
			adsys := adsysservice.Service{}
			d, err := daemon.New(adsys.RegisterGRPCServer, a.config.Socket, daemon.WithTimeout(timeout))
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
	cmdhandler.InstallConfigFlag(&a.rootCmd)
	cmdhandler.InstallSocketFlag(&a.rootCmd, config.DefaultSocket)

	a.rootCmd.PersistentFlags().IntP("timeout", "t", config.DefaultServiceTimeout, i18n.G("time in seconds without activity before the service exists. 0 for no timeout."))
	viper.BindPFlag("servicetimeout", a.rootCmd.PersistentFlags().Lookup("timeout"))

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

// changeServiceTimeout change the timeout used on server.
func (a *App) changeServiceTimeout(timeout time.Duration) {
	if a.daemon == nil {
		return
	}
	a.daemon.ChangeTimeout(timeout)
}

// Run executes the command and associated process. It returns an error on syntax/usage error.
func (a *App) Run() error {
	return a.rootCmd.Execute()
}

// UsageError returns if the error is a command parsing or runtime one.
func (a App) UsageError() bool {
	return !a.rootCmd.SilenceUsage
}

// Hup prints all goroutine stack traces and return false to signal you shouldn't quit.
func (a App) Hup() (shouldQuit bool) {
	buf := make([]byte, 1<<16)
	runtime.Stack(buf, true)
	fmt.Printf("%s", buf)
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
