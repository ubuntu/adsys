package cmdhandler

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
)

// NoCmd is a no-op command to just make it valid.
func NoCmd(cmd *cobra.Command, args []string) error {
	return nil
}

// ZeroOrNArgs returns an error if there are not 0 or exactly N arguments for the given command.
func ZeroOrNArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 && len(args) != n {
			return fmt.Errorf("requires either no arguments or exactly %d, only received %d", n, len(args))
		}
		return nil
	}
}

// NoValidArgs prevents any completion, including files.
func NoValidArgs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveNoFileComp
}

// RegisterAlias will register a given alias of a command.
// README and manpage refers to them in each subsection (parents are differents, but only one is kept if we use the same object).
func RegisterAlias(cmd, parent *cobra.Command) {
	alias := *cmd
	t := fmt.Sprintf(i18n.G("Alias of %q"), cmd.CommandPath())
	if alias.Long != "" {
		t = fmt.Sprintf("%s (%s)", alias.Long, t)
	}
	alias.Long = t
	parent.AddCommand(&alias)
}

// InstallVerboseFlag adds the -v and -vv options and returns the reference to it.
func InstallVerboseFlag(cmd *cobra.Command, viper *viper.Viper) *int {
	r := cmd.PersistentFlags().CountP("verbose", "v", i18n.G("issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output"))
	decorate.LogOnError(viper.BindPFlag("verbose", cmd.PersistentFlags().Lookup("verbose")))
	return r
}

// InstallSocketFlag adds the -s and --sockets options and returns the reference to it.
func InstallSocketFlag(cmd *cobra.Command, viper *viper.Viper, defaultPath string) *string {
	s := cmd.PersistentFlags().StringP("socket", "s", defaultPath, i18n.G("socket path to use between daemon and client. Can be overridden by systemd socket activation."))
	decorate.LogOnError(viper.BindPFlag("socket", cmd.PersistentFlags().Lookup("socket")))
	return s
}

// InstallConfigFlag adds the -c and --config option to select a configuration file and returns the reference to it.
func InstallConfigFlag(cmd *cobra.Command, persistent bool) *string {
	target := cmd.Flags()
	if persistent {
		target = cmd.PersistentFlags()
	}
	return target.StringP("config", "c", "", i18n.G("use a specific configuration file"))
}

// CalledCmd returns the actual command called by the user inferred from the arguments.
func CalledCmd(cmd *cobra.Command) (*cobra.Command, error) {
	cmdArgs := strings.Fields(cmd.CommandPath())[1:]
	cmd, _, err := cmd.Find(cmdArgs)
	if err != nil {
		return nil, err
	}

	return cmd, nil
}
