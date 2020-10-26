package cmdhandler

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/i18n"
)

// NoCmd is a no-op command to just make it valid
func NoCmd(cmd *cobra.Command, args []string) {
}

// RegisterAlias allows to decorelate the alias from the main command when alias have different command level (different parents)
// README and manpage refers to them in each subsection (parents are differents, but only one is kept if we use the same object)
func RegisterAlias(cmd, parent *cobra.Command) {
	alias := *cmd
	t := fmt.Sprintf(i18n.G("Alias of %s"), cmd.CommandPath())
	if alias.Long != "" {
		t = fmt.Sprintf("%s (%s)", alias.Long, t)
	}
	alias.Long = t
	parent.AddCommand(&alias)
}

// InstallCompletionCmd adds a subcommand named "completion"
func InstallCompletionCmd(rootCmd *cobra.Command) {
	prog := rootCmd.Name()
	var completionCmd = &cobra.Command{
		Use:   "completion",
		Short: i18n.G("Generates bash completion scripts"),
		Long: fmt.Sprintf(i18n.G(`To load completion run

. <(%s completion)

To configure your bash shell to load completions for each session add to your ~/.bashrc or ~/.profile:

. <(%s completion)
`), prog, prog),
		Run: func(cmd *cobra.Command, args []string) {
			// use upstream completion for now as we don’t have hidden subcommands
			rootCmd.GenBashCompletion(os.Stdout)
		},
	}
	rootCmd.AddCommand(completionCmd)
}

// InstallVerboseFlag adds the -v and -vv options and returns the reference to it.
func InstallVerboseFlag(cmd *cobra.Command) *int {
	r := cmd.PersistentFlags().CountP("verbose", "v", i18n.G("issue INFO (-v) and DEBUG (-vv) output"))
	viper.BindPFlag("verbose", cmd.PersistentFlags().Lookup("verbose"))
	return r
}

// InstallSocketFlag adds the -s and --sockets options and returns the reference to it.
func InstallSocketFlag(cmd *cobra.Command, defaultPath string) *string {
	s := cmd.PersistentFlags().StringP("socket", "s", defaultPath, i18n.G("socket path to use between daemon and client"))
	viper.BindPFlag("socket", cmd.PersistentFlags().Lookup("socket"))
	return s
}
