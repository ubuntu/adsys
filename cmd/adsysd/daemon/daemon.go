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
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/daemon"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
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

	DconfDir     string `mapstructure:"dconf_dir"`
	SudoersDir   string `mapstructure:"sudoers_dir"`
	PolicyKitDir string `mapstructure:"policykit_dir"`
	SSSCacheDir  string `mapstructure:"sss_cache_dir"`

	ServiceTimeout        int    `mapstructure:"service_timeout"`
	ADServer              string `mapstructure:"ad_server"`
	ADDomain              string `mapstructure:"ad_domain"`
	ADDefaultDomainSuffix string `mapstructure:"ad_default_domain_suffix"`
}

// New registers commands and return a new App.
func New() *App {
	a := App{ready: make(chan struct{})}
	a.rootCmd = cobra.Command{
		Use:   fmt.Sprintf("%s COMMAND", CmdName),
		Short: i18n.G("AD integration daemon"),
		Long:  i18n.G(`Active Directory integration bridging toolset daemon.`),
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
			adsys, err := adsysservice.New(context.Background(), a.config.ADServer, a.config.ADDomain,
				adsysservice.WithCacheDir(a.config.CacheDir),
				adsysservice.WithRunDir(a.config.RunDir),
				adsysservice.WithDconfDir(a.config.DconfDir),
				adsysservice.WithSudoersDir(a.config.SudoersDir),
				adsysservice.WithPolicyKitDir(a.config.PolicyKitDir),
				adsysservice.WithSSSCacheDir(a.config.SSSCacheDir),
				adsysservice.WithDefaultDomainSuffix(a.config.ADDefaultDomainSuffix),
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

	a.rootCmd.PersistentFlags().StringP("cache-dir", "", consts.DefaultCacheDir, i18n.G("directory where ADsys caches GPOs downloads and policies."))
	decorate.LogOnError(a.viper.BindPFlag("cache_dir", a.rootCmd.PersistentFlags().Lookup("cache-dir")))
	a.rootCmd.PersistentFlags().StringP("run-dir", "", consts.DefaultRunDir, i18n.G("directory where ADsys stores transient information erased on reboot."))
	decorate.LogOnError(a.viper.BindPFlag("run_dir", a.rootCmd.PersistentFlags().Lookup("run-dir")))

	a.rootCmd.PersistentFlags().IntP("timeout", "t", consts.DefaultServiceTimeout, i18n.G("time in seconds without activity before the service exists. 0 for no timeout."))
	decorate.LogOnError(a.viper.BindPFlag("service_timeout", a.rootCmd.PersistentFlags().Lookup("timeout")))

	a.rootCmd.PersistentFlags().StringP("ad-server", "S", "", i18n.G("URL of the Active Directory server. This overrides parsing sssd.conf."))
	decorate.LogOnError(a.viper.BindPFlag("ad_server", a.rootCmd.PersistentFlags().Lookup("ad-server")))
	a.rootCmd.PersistentFlags().StringP("ad-domain", "D", "", i18n.G("AD domain to use. This overrides parsing sssd.conf"))
	decorate.LogOnError(a.viper.BindPFlag("ad_domain", a.rootCmd.PersistentFlags().Lookup("ad-domain")))
	a.rootCmd.PersistentFlags().StringP("ad-default-domain-suffix", "", "", i18n.G("AD default domain suffix to use. This overrides parsing sssd.conf."))
	decorate.LogOnError(a.viper.BindPFlag("ad_default_domain_suffix", a.rootCmd.PersistentFlags().Lookup("ad-default-domain-suffix")))

	// subcommands
	a.installVersion()
	a.installRunScripts()

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
func (a *App) SetArgs(args []string) {
	a.rootCmd.SetArgs(args)
}
