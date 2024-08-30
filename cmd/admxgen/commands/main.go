// Package commands is the admxgen command handling.
package commands

import (
	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/ad/admxgen"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/decorate"
)

// App encapsulates the commands and configuration of the admxgen application.
type App struct {
	rootCmd cobra.Command
	viper   *viper.Viper
}

// New registers commands and return a new App.
func New() *App {
	a := App{}

	a.viper = viper.New()
	a.rootCmd = cobra.Command{
		Use:   "admxgen COMMAND",
		Short: gotext.Get("Generate Active Directory admx and adml files"),
		Long:  gotext.Get(`Generate ADMX and intermediary working files from a list of policy definition files.`),
		Args:  cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:  cmdhandler.NoCmd,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			// Command parsing has been successful. Returns runtime (or
			// configuration) error now and so, don't print usage.
			a.rootCmd.SilenceUsage = true

			config.SetVerboseMode(a.viper.GetInt("verbose"))
			return nil
		},

		// We display usage error ourselves
		SilenceErrors: true,
	}

	a.rootCmd.PersistentFlags().CountP("verbose", "v", gotext.Get("issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output"))
	err := a.viper.BindPFlag("verbose", a.rootCmd.PersistentFlags().Lookup("verbose"))
	decorate.LogOnError(&err)

	// Install subcommands
	a.installExpand()
	a.installAdmx()
	a.installDoc()

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

func (a *App) installExpand() {
	cmd := &cobra.Command{
		Use:   "expand SOURCE DEST",
		Short: gotext.Get("Generates intermediary policy definition files"),
		Long: gotext.Get(`Generates an intermediary policy definition file into DEST directory from all the policy definition files in SOURCE directory, using the correct decoder.
The generated definition file will be of the form expanded_policies.RELEASE.yaml`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return admxgen.Expand(args[0], args[1], viper.GetString("root"), viper.GetString("current-session"))
		},
	}
	cmd.Flags().StringP("root", "r", "/", gotext.Get("root filesystem path to use. Default to /."))
	err := viper.BindPFlag("root", cmd.Flags().Lookup("root"))
	decorate.LogOnError(&err)

	cmd.Flags().StringP("current-session", "s", "", gotext.Get(`current session to consider for dconf per-session overrides. Default to "".`))
	err = viper.BindPFlag("current-session", cmd.Flags().Lookup("current-session"))
	decorate.LogOnError(&err)

	a.rootCmd.AddCommand(cmd)
}

func (a *App) installAdmx() {
	var autoDetectReleases, allowMissingKeys *bool
	cmd := &cobra.Command{
		Use:   "admx CATEGORIES_DEF.YAML SOURCE DEST",
		Short: gotext.Get("Create finale admx and adml files"),
		Long:  gotext.Get("Collects all intermediary policy definition files in SOURCE directory to create admx and adml templates in DEST, based on CATEGORIES_DEF.yaml."),
		Args:  cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			return admxgen.GenerateAD(args[0], args[1], args[2], *autoDetectReleases, *allowMissingKeys)
		},
	}
	autoDetectReleases = cmd.Flags().BoolP("auto-detect-releases", "a", false, gotext.Get("override supported releases in categories definition file and will takes all yaml files in SOURCE directory and use the basename as their versions."))
	err := a.viper.BindPFlag("auto-detect-releases", cmd.Flags().Lookup("auto-detect-releases"))
	decorate.LogOnError(&err)

	allowMissingKeys = cmd.Flags().BoolP("allow-missing-keys", "k", false, gotext.Get(`avoid fail but display a warning if some keys are not available in a release. This is the case when news keys are added to non-lts releases.`))
	err = a.viper.BindPFlag("allow-missing-keys", cmd.Flags().Lookup("allow-missing-keys"))
	decorate.LogOnError(&err)

	a.rootCmd.AddCommand(cmd)
}

func (a *App) installDoc() {
	cmd := &cobra.Command{
		Use:   "doc CATEGORIES_DEF.YAML SOURCE DEST",
		Short: gotext.Get("Create markdown documentation"),
		Long:  gotext.Get("Collects all intermediary policy definition files in SOURCE directory to create markdown documentation in DEST, based on CATEGORIES_DEF.yaml."),
		Args:  cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			return admxgen.GenerateDoc(args[0], args[1], args[2])
		},
	}

	a.rootCmd.AddCommand(cmd)
}
