package client

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installPolicy() {
	mainCmd := &cobra.Command{
		Use:   "policy COMMAND",
		Short: i18n.G("Policy management"),
		Args:  cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:  cmdhandler.NoCmd,
	}
	a.rootCmd.AddCommand(mainCmd)

	var updateMachine *bool
	cmd := &cobra.Command{
		Use:   "update [USER_NAME KERBEROS_TICKET_PATH]",
		Short: i18n.G("Updates/Create a policy for current user or given user with its kerberos ticket"),
		Args:  cmdhandler.ZeroOrNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var user, krb5cc string
			if len(args) > 0 {
				user, krb5cc = args[0], args[1]
			}
			return a.policyUpdate(*updateMachine, user, krb5cc)
		},
	}
	updateMachine = cmd.Flags().BoolP("machine", "m", false, i18n.G("machine updates the policy of the computer."))
	mainCmd.AddCommand(cmd)
}

func (a *App) policyUpdate(isComputer bool, target, krb5cc string) error {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	// override for computer
	if isComputer && target == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		// for malconfigured machines where /proc/sys/kernel/hostname returns the fqdn and not only the machine name, strip it
		if i := strings.Index(hostname, "."); i > 0 {
			target = hostname[:i]
		}
	}

	// Update for current user
	if target == "" {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to retrieve current user: %v", err)
		}
		target = u.Username
		krb5cc = strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:")
	}

	stream, err := client.UpdatePolicy(a.ctx, &adsys.UpdatePolicyRequest{IsComputer: isComputer, User: target, Krb5Cc: krb5cc})
	if err != nil {
		return err
	}

	if _, err := stream.Recv(); err != nil && err != io.EOF {
		return err
	}

	return nil
}
