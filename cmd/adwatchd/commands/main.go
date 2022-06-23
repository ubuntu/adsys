package commands

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
	watchdconfig "github.com/ubuntu/adsys/internal/config/watchd"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/watchdservice"
	"github.com/ubuntu/adsys/internal/watchdtui"
	"golang.org/x/exp/slices"
)

// App encapsulates commands and options of the daemon, which can be controlled by env variables and config files.
type App struct {
	rootCmd cobra.Command
	viper   *viper.Viper

	config  watchdconfig.AppConfig
	service *watchdservice.WatchdService
	options options

	ready    chan struct{}
	configMu *sync.RWMutex
}

// options are the configurable functional options of the application.
type options struct {
	name string
}
type option func(*options)

// WithServiceName allows setting a custom name for the daemon. Shouldn't be in
// general necessary apart for integration tests where it helps with parallel
// execution.
func WithServiceName(name string) func(o *options) {
	return func(o *options) {
		o.name = name
	}
}

// New registers commands and return a new App.
func New(opts ...option) *App {
	// Set default options.
	args := options{
		name: watchdconfig.CmdName,
	}

	// Apply given options.
	for _, o := range opts {
		o(&args)
	}

	a := App{ready: make(chan struct{})}
	a.configMu = &sync.RWMutex{}
	a.options = args
	a.rootCmd = cobra.Command{
		Use:   fmt.Sprintf("%s [COMMAND]", watchdconfig.CmdName),
		Short: i18n.G("AD watch daemon"),
		Long:  i18n.G(`Watch directories for changes and bump the relevant GPT.ini versions.`),
		Args:  cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Command parsing has been successful. Returns runtime (or
			// configuration) error now and so, don't print usage.
			cmd.SilenceUsage = true
			err := config.Init(watchdconfig.CmdName, a.rootCmd, a.viper, func(refreshed bool) error {
				a.configMu.Lock()
				defer a.configMu.Unlock()
				var newConfig watchdconfig.AppConfig
				if err := config.LoadConfig(&newConfig, a.viper); err != nil {
					return err
				}

				// First run: just init configuration.
				if !refreshed {
					a.config = newConfig
					return nil
				}

				// Config reload

				// Reload verbosity and directories.
				oldVerbose := a.config.Verbose
				oldDirs := a.config.Dirs
				a.config = newConfig

				if oldVerbose != a.config.Verbose {
					config.SetVerboseMode(a.config.Verbose)
				}

				// Now deal with service only changes.
				if a.service == nil {
					return nil
				}

				if !slices.Equal(oldDirs, a.config.Dirs) {
					if err := a.service.UpdateDirs(context.Background(), a.config.Dirs); err != nil {
						log.Warningf(context.Background(), i18n.G("failed to update directories: %v"), err)
						a.config.Dirs = oldDirs
					}
				}

				return nil
			})

			// Set configured verbose status for the daemon before getting error output.
			config.SetVerboseMode(a.config.Verbose)
			if err != nil {
				close(a.ready)
				return err
			}

			// If we have a config file, pass it as an argument to the service.
			var configFile string
			if len(a.viper.ConfigFileUsed()) > 0 {
				absPath, err := filepath.Abs(a.viper.ConfigFileUsed())
				if err != nil {
					close(a.ready)
					return err
				}
				configFile = absPath
			}

			// Create main service and attach it to the app
			service, err := watchdservice.New(
				context.Background(),
				watchdservice.WithName(a.options.name),
				watchdservice.WithDirs(a.config.Dirs),
				watchdservice.WithConfig(configFile))

			if err != nil {
				close(a.ready)
				return err
			}
			a.service = service
			close(a.ready)

			return nil
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			if status, _ := a.service.Status(context.Background()); !strings.Contains(status, "not installed") {
				return fmt.Errorf(i18n.G(`Cannot run the interactive installer if the service is already installed.
If you wish to rerun the installer, please remove the service first.

This can be done via the Services UI or by running: %s service uninstall`), watchdconfig.CmdName)
			}

			configFileSet := a.rootCmd.Flags().Lookup("config").Changed
			if err := watchdtui.Start(context.Background(), a.viper.ConfigFileUsed(), !configFileSet); err != nil {
				return err
			}

			return nil
		},

		// We display usage error ourselves
		SilenceErrors: true,
	}

	a.viper = viper.New()

	cmdhandler.InstallConfigFlag(&a.rootCmd)
	cmdhandler.InstallVerboseFlag(&a.rootCmd, a.viper)

	// Install subcommands
	a.installRun()
	a.installService()
	a.installVersion()

	return &a
}

// Run executes the app.
func (a *App) Run() error {
	return a.rootCmd.Execute()
}

// UsageError returns if the error is a command parsing or runtime one.
func (a App) UsageError() bool {
	return !a.rootCmd.SilenceUsage
}

// SetArgs changes the root command args. Shouldn't be in general necessary apart for integration tests.
func (a *App) SetArgs(args []string, conf string) {
	// cmdhandler.InstallConfigFlag(&a.rootCmd)
	a.rootCmd.PersistentFlags().StringP("config", "c", conf, i18n.G("use a specific configuration file"))
	cmdhandler.InstallVerboseFlag(&a.rootCmd, a.viper)

	a.rootCmd.SetArgs(args)
}

// Dirs returns the configured directories. Shouldn't be in general necessary apart for integration tests.
func (a *App) Dirs() []string {
	a.configMu.RLock()
	defer a.configMu.RUnlock()

	return a.config.Dirs
}

// Verbosity returns the configured verbosity. Shouldn't be in general necessary apart for integration tests.
func (a *App) Verbosity() int {
	a.configMu.RLock()
	defer a.configMu.RUnlock()

	return a.config.Verbose
}

// Reset recreates the ready channel and reinstalls the persistent root flags.
// Shouldn't be in general necessary apart for integration tests, where multiple
// commands are executed on the same instance.
func (a *App) Reset() {
	a.rootCmd.ResetFlags()

	a.ready = make(chan struct{})
}

// WaitReady signals when the daemon is ready
// Note: we need to use a pointer to not copy the App object before the daemon is ready, and thus, creates a data race.
func (a *App) WaitReady() {
	<-a.ready

	// Give time for the watcher itself to start
	time.Sleep(time.Millisecond * 100)
}

// RootCmd returns a copy of the root command for the app. Shouldn't be in
// general necessary apart from running generators.
func (a App) RootCmd() cobra.Command {
	return a.rootCmd
}
