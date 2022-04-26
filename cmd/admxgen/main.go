package main

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/ad/admxgen"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/i18n"
)

const viperPrefix = "ADMXGEN"

func main() {
	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		DisableTimestamp:       true,
	})

	viper := viper.New()
	viper.SetEnvPrefix(viperPrefix)

	rootCmd := cobra.Command{
		Use:   "admxgen COMMAND",
		Short: i18n.G("Generate Active Directory admx and adml files"),
		Long:  i18n.G(`Generate ADMX and intermediary working files from a list of policy definition files.`),
		Args:  cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:  cmdhandler.NoCmd,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			config.SetVerboseMode(viper.GetInt("verbose"))
			return nil
		},
	}

	rootCmd.PersistentFlags().CountP("verbose", "v", i18n.G("issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output"))
	if err := bindFlags(viper, rootCmd.PersistentFlags()); err != nil {
		log.Errorf(i18n.G("can't install command flag bindings: %v"), err)
		os.Exit(2)
	}

	// Install subcommands
	if err := installExpand(&rootCmd, viper); err != nil {
		log.Error(err)
		os.Exit(2)
	}
	if err := installAdmx(&rootCmd, viper); err != nil {
		log.Error(err)
		os.Exit(2)
	}

	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func installExpand(rootCmd *cobra.Command, viper *viper.Viper) error {
	cmd := &cobra.Command{
		Use:   "expand SOURCE DEST",
		Short: i18n.G("Generates intermediary policy definition files"),
		Long: i18n.G(`Generates an intermediary policy definition file into DEST directory from all the policy definition files in SOURCE directory, using the correct decoder.
The generated definition file will be of the form expanded_policies.RELEASE.yaml`),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return admxgen.Expand(args[0], args[1], viper.GetString("root"), viper.GetString("current-session"))
		},
	}
	cmd.Flags().StringP("root", "r", "/", i18n.G("root filesystem path to use. Default to /."))
	cmd.Flags().StringP("current-session", "s", "", i18n.G(`current session to consider for dconf per-session
	overrides. Default to "".`))
	if err := bindFlags(viper, cmd.Flags()); err != nil {
		return fmt.Errorf(i18n.G("can't install command flag bindings: %v"), err)
	}

	rootCmd.AddCommand(cmd)
	return nil
}

func installAdmx(rootCmd *cobra.Command, viper *viper.Viper) error {
	var autoDetectReleases, allowMissingKeys *bool
	cmd := &cobra.Command{
		Use:   "admx CATEGORIES_DEF.YAML SOURCE DEST",
		Short: i18n.G("Create finale admx and adml files"),
		Long:  i18n.G("Collects all intermediary policy definition files in SOURCE directory to create admx and adml templates in DEST, based on CATEGORIES_DEF.yaml."),
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return admxgen.Generate(args[0], args[1], args[2], *autoDetectReleases, *allowMissingKeys)
		},
	}
	autoDetectReleases = cmd.Flags().BoolP("auto-detect-releases", "a", false, i18n.G("override supported releases in categories definition file and will takes all yaml files in SOURCE directory and use the basename as their versions."))
	allowMissingKeys = cmd.Flags().BoolP("allow-missing-keys", "k", false, i18n.G(`avoid fail but display a warning if some keys are not available in a release. This is the case when news keys are added to non-lts releases.`))
	if err := bindFlags(viper, cmd.Flags()); err != nil {
		return fmt.Errorf(i18n.G("can't install command flag bindings: %v"), err)
	}

	rootCmd.AddCommand(cmd)
	return nil
}

// bindFlags each cobra flag in a flagset to its associated viper env, ignoring config
// Compare to the viper automated binding, it translates - to _.
func bindFlags(viper *viper.Viper, flags *pflag.FlagSet) (errBind error) {
	flags.VisitAll(func(f *pflag.Flag) {
		// This allows to connect flag and default value to viper.
		if err := viper.BindPFlag(f.Name, f); err != nil {
			errBind = err
			return
		}
		// And this is the env with translation from - to _.
		envVar := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if err := viper.BindEnv(f.Name, fmt.Sprintf("%s_%s", viperPrefix, envVar)); err != nil {
			errBind = err
			return
		}
	})
	return errBind
}
