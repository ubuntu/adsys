// Package daemon represents the CLI UI for adsysd service.
package daemon

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/ad/backends/sss"
	"github.com/ubuntu/adsys/internal/ad/backends/winbind"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/daemon"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/decorate"
)

// CmdName is the binary name for the daemon.
const CmdName = "adsysd"

// App encapsulate commands and options of the daemon, which can be controlled by env variables and config files.
type App struct {
	rootCmd cobra.Command
	viper   *viper.Viper

	config daemonConfig
	daemon *daemon.Daemon

	ready chan struct{}
}

type daemonConfig struct {
	Verbose int

	Socket   string
	CacheDir string `mapstructure:"cache_dir"`
	RunDir   string `mapstructure:"run_dir"`

	DconfDir      string `mapstructure:"dconf_dir"`
	SudoersDir    string `mapstructure:"sudoers_dir"`
	PolicyKitDir  string `mapstructure:"policykit_dir"`
	ApparmorDir   string `mapstructure:"apparmor_dir"`
	ApparmorFsDir string `mapstructure:"apparmorfs_dir"`
	SystemUnitDir string `mapstructure:"systemunit_dir"`

	AdBackend     string         `mapstructure:"ad_backend"`
	SSSdConfig    sss.Config     `mapstructure:"sssd"`
	WinbindConfig winbind.Config `mapstructure:"winbind"`

	ServiceTimeout int `mapstructure:"service_timeout"`
}

// New registers commands and return a new App.
func New() *App {
	a := App{ready: make(chan struct{})}
	a.rootCmd = cobra.Command{
		Use:   fmt.Sprintf("%s COMMAND", CmdName),
		Short: gotext.Get("AD integration daemon"),
		Long:  gotext.Get(`Active Directory integration bridging toolset daemon.`),
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
				oldSocket := a.config.Socket
				oldTimeout := a.config.ServiceTimeout
				a.config = newConfig
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
			// Set configured verbose status for the daemon.
			config.SetVerboseMode(a.config.Verbose)
			return err
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			adsys, err := adsysservice.New(context.Background(),
				adsysservice.WithCacheDir(a.config.CacheDir),
				adsysservice.WithRunDir(a.config.RunDir),
				adsysservice.WithDconfDir(a.config.DconfDir),
				adsysservice.WithSudoersDir(a.config.SudoersDir),
				adsysservice.WithPolicyKitDir(a.config.PolicyKitDir),
				adsysservice.WithApparmorDir(a.config.ApparmorDir),
				adsysservice.WithApparmorFsDir(a.config.ApparmorFsDir),
				adsysservice.WithSystemUnitDir(a.config.SystemUnitDir),
				adsysservice.WithADBackend(a.config.AdBackend),
				adsysservice.WithSSSConfig(a.config.SSSdConfig),
				adsysservice.WithWinbindConfig(a.config.WinbindConfig),
			)
			if err != nil {
				close(a.ready)
				return err
			}

			timeout := time.Duration(a.config.ServiceTimeout) * time.Second
			d, err := daemon.New(adsys.RegisterGRPCServer, a.config.Socket,
				daemon.WithTimeout(timeout),
				daemon.WithServerQuit(adsys.Quit))
			if err != nil {
				close(a.ready)
				return err
			}
			a.daemon = d
			close(a.ready)
			return a.daemon.Listen()
		},
		// We display usage error ourselves
		SilenceErrors: true,
	}
	a.viper = viper.New()

	cmdhandler.InstallVerboseFlag(&a.rootCmd, a.viper)
	cmdhandler.InstallConfigFlag(&a.rootCmd, true)
	cmdhandler.InstallSocketFlag(&a.rootCmd, a.viper, consts.DefaultSocket)

	a.rootCmd.PersistentFlags().StringP("cache-dir", "", consts.DefaultCacheDir, gotext.Get("directory where ADsys caches GPOs downloads and policies."))
	decorate.LogOnError(a.viper.BindPFlag("cache_dir", a.rootCmd.PersistentFlags().Lookup("cache-dir")))
	a.rootCmd.PersistentFlags().StringP("run-dir", "", consts.DefaultRunDir, gotext.Get("directory where ADsys stores transient information erased on reboot."))
	decorate.LogOnError(a.viper.BindPFlag("run_dir", a.rootCmd.PersistentFlags().Lookup("run-dir")))

	a.rootCmd.PersistentFlags().IntP("timeout", "t", consts.DefaultServiceTimeout, gotext.Get("time in seconds without activity before the service exists. 0 for no timeout."))
	decorate.LogOnError(a.viper.BindPFlag("service_timeout", a.rootCmd.PersistentFlags().Lookup("timeout")))

	a.rootCmd.PersistentFlags().StringP("ad-backend", "", "sssd", gotext.Get("Active Directory authentication backend"))
	decorate.LogOnError(a.viper.BindPFlag("ad_backend", a.rootCmd.PersistentFlags().Lookup("ad-backend")))
	a.rootCmd.PersistentFlags().StringP("sssd.config", "", consts.DefaultSSSConf, gotext.Get("SSSd config file path"))
	decorate.LogOnError(a.viper.BindPFlag("sssd.config", a.rootCmd.PersistentFlags().Lookup("sssd.config")))
	a.rootCmd.PersistentFlags().StringP("sssd.cache-dir", "", consts.DefaultSSSCacheDir, gotext.Get("SSSd cache directory"))
	decorate.LogOnError(a.viper.BindPFlag("sssd.cache_dir", a.rootCmd.PersistentFlags().Lookup("sssd.cache-dir")))

	// subcommands
	a.installVersion()
	a.installRunScripts()
	a.installMount()
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
func (a *App) Quit() {
	a.WaitReady()
	if a.daemon == nil {
		return
	}
	a.daemon.Quit(false)
}

// RootCmd returns a copy of the root command for the app. Shouldn’t be in general necessary apart when running generators.
func (a App) RootCmd() cobra.Command {
	return a.rootCmd
}

// WaitReady signals when the daemon is ready
// Note: we need to use a pointer to not copy the App object before the daemon is ready, and thus, creates a data race.
func (a *App) WaitReady() {
	<-a.ready
}

// SetArgs changes the root command args. Shouldn’t be in general necessary apart for integration tests.
func (a *App) SetArgs(args ...string) {
	a.rootCmd.SetArgs(args)
}
