package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/watchdhelpers"
	"github.com/ubuntu/adsys/internal/watchdservice"
	"github.com/ubuntu/adsys/internal/watchdtui"
	"golang.org/x/exp/slices"
)

// App encapsulates commands and options of the daemon, which can be controlled by env variables and config files.
type App struct {
	rootCmd cobra.Command
	viper   *viper.Viper

	config  watchdhelpers.AppConfig
	service *watchdservice.WatchdService
	options options

	ready chan struct{}
}

// options are the configurable functional options of the application.
type options struct {
	name string
}
type option func(*options)

// New registers commands and return a new App.
func New(opts ...option) *App {
	// Set default options.
	args := options{
		name: "adwatchd",
	}

	// Apply given options.
	for _, o := range opts {
		o(&args)
	}

	a := App{ready: make(chan struct{})}
	a.options = args
	a.rootCmd = cobra.Command{
		Use:   "adwatchd [COMMAND]",
		Short: i18n.G("AD watch daemon"),
		Long:  i18n.G(`Watch directories for changes and bump the relevant GPT.ini versions.`),
		Args:  cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Command parsing has been successful. Returns runtime (or
			// configuration) error now and so, don't print usage.
			cmd.SilenceUsage = true
			err := config.Init("adwatchd", a.rootCmd, a.viper, func(refreshed bool) error {
				var newConfig watchdhelpers.AppConfig
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
				// TODO: check why Verbose does not update properly
				if oldVerbose != a.config.Verbose {
					config.SetVerboseMode(a.config.Verbose)
				}
				if !slices.Equal(oldDirs, a.config.Dirs) {
					if a.service != nil {
						if err := a.service.UpdateDirs(context.Background(), a.config.Dirs); err != nil {
							log.Warningf(context.Background(), i18n.G("failed to update directories: %v"), err)
							a.config.Dirs = oldDirs
						}
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
			var configFile []string
			if len(a.viper.ConfigFileUsed()) > 0 {
				absPath, err := filepath.Abs(a.viper.ConfigFileUsed())
				if err != nil {
					close(a.ready)
					return err
				}
				configFile = []string{"-c", absPath}
			}

			// Create main service and attach it to the app
			service, err := watchdservice.New(
				context.Background(),
				watchdservice.WithName(a.options.name),
				watchdservice.WithDirs(a.config.Dirs),
				watchdservice.WithArgs(configFile))

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

This can be done via the Services UI or by running: adwatchd service uninstall`))
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

	cmdhandler.InstallVerboseFlag(&a.rootCmd, a.viper)
	a.rootCmd.PersistentFlags().StringP(
		"config",
		"c",
		defaultConfigPath(),
		i18n.G("`path` to config file"),
	)

	// Install subcommands
	a.installRun()
	a.installService()
	a.installVersion()

	return &a
}

func defaultConfigPath() string {
	binPath, err := os.Executable()
	if err != nil {
		log.Warningf(context.Background(), i18n.G("failed to get executable path, using relative path for default config: %v"), err)
	}
	return filepath.Join(filepath.Dir(binPath), "adwatchd.yml")
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
func (a *App) SetArgs(args []string) {
	a.rootCmd.SetArgs(args)
}

// Dirs returns the configured directories. Shouldn't be in general necessary apart for integration tests.
func (a App) Dirs() []string {
	return a.config.Dirs
}

// Verbosity returns the configured verbosity. Shouldn't be in general necessary apart for integration tests.
func (a App) Verbosity() int {
	return a.config.Verbose
}

// Reset recreates the ready channel. Shouldn't be in general necessary apart
// for integration tests, where multiple commands are executed on the same
// instance.
func (a *App) Reset() {
	a.ready = make(chan struct{})
}

// Quit gracefully exits the app. Shouldn't be in general necessary apart for
// integration tests where we might need to close the app manually.
func (a *App) Quit(sig syscall.Signal) error {
	a.waitReady()
	if !service.Interactive() {
		return fmt.Errorf(i18n.G("not running in interactive mode"))
	}

	// The service package is responsible for handling the service stop. It
	// registers a signal handler and to trigger it we just have to send the
	// signal ourselves and not bother with actual cleanup.
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}

	return p.Signal(sig)
}

// WithServiceName allows setting a custom name for the daemon. Shouldn't be in
// general necessary apart for integration tests where it helps with parallel
// execution.
func WithServiceName(name string) func(o *options) {
	return func(o *options) {
		o.name = name
	}
}

// waitReady signals when the daemon is ready
// Note: we need to use a pointer to not copy the App object before the daemon is ready, and thus, creates a data race.
func (a *App) waitReady() {
	<-a.ready
}
