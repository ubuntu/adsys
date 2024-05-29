// Package main is the entry point for admxgen command line.
//
// admxgen is a tool used in CI to refresh policy definition files and generates admx/adml.
package main

import (
	"os"

	"github.com/leonelquinteros/gotext"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/ad/admxgen"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/decorate"
)

func main() {
	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		DisableTimestamp:       true,
	})

	viper := viper.New()

	rootCmd := cobra.Command{
		Use:   "admxgen COMMAND",
		Short: gotext.Get("Generate Active Directory admx and adml files"),
		Long:  gotext.Get(`Generate ADMX and intermediary working files from a list of policy definition files.`),
		Args:  cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:  cmdhandler.NoCmd,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			config.SetVerboseMode(viper.GetInt("verbose"))
			return nil
		},
	}

	rootCmd.PersistentFlags().CountP("verbose", "v", gotext.Get("issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output"))
	decorate.LogOnError(viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose")))

	// Install subcommands
	installExpand(&rootCmd, viper)
	installAdmx(&rootCmd, viper)
	installDoc(&rootCmd, viper)

	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func installExpand(rootCmd *cobra.Command, viper *viper.Viper) {
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
	decorate.LogOnError(viper.BindPFlag("root", cmd.Flags().Lookup("root")))

	cmd.Flags().StringP("current-session", "s", "", gotext.Get(`current session to consider for dconf per-session overrides. Default to "".`))
	decorate.LogOnError(viper.BindPFlag("current-session", cmd.Flags().Lookup("current-session")))

	rootCmd.AddCommand(cmd)
}

func installAdmx(rootCmd *cobra.Command, viper *viper.Viper) {
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
	decorate.LogOnError(viper.BindPFlag("auto-detect-releases", cmd.Flags().Lookup("auto-detect-releases")))

	allowMissingKeys = cmd.Flags().BoolP("allow-missing-keys", "k", false, gotext.Get(`avoid fail but display a warning if some keys are not available in a release. This is the case when news keys are added to non-lts releases.`))
	decorate.LogOnError(viper.BindPFlag("allow-missing-keys", cmd.Flags().Lookup("allow-missing-keys")))

	rootCmd.AddCommand(cmd)
}

func installDoc(rootCmd *cobra.Command, _ *viper.Viper) {
	cmd := &cobra.Command{
		Use:   "doc CATEGORIES_DEF.YAML SOURCE DEST",
		Short: gotext.Get("Create markdown documentation"),
		Long:  gotext.Get("Collects all intermediary policy definition files in SOURCE directory to create markdown documentation in DEST, based on CATEGORIES_DEF.yaml."),
		Args:  cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			return admxgen.GenerateDoc(args[0], args[1], args[2])
		},
	}

	rootCmd.AddCommand(cmd)
}
