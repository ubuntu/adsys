package client

import (
	"errors"
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

func (a *App) installUpdate() {
	var updateMachine, updateAll *bool
	cmd := &cobra.Command{
		Use:   "update [USER_NAME KERBEROS_TICKET_PATH]",
		Short: i18n.G("Updates/Create a policy for current user or given user with its kerberos ticket"),
		Args:  cmdhandler.ZeroOrNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var user, krb5cc string
			if len(args) > 0 {
				user, krb5cc = args[0], args[1]
			}
			return a.update(*updateMachine, *updateAll, user, krb5cc)
		},
	}
	updateMachine = cmd.Flags().BoolP("machine", "m", false, i18n.G("machine updates the policy of the computer."))
	updateAll = cmd.Flags().BoolP("all", "a", false, i18n.G("all updates the policy of the computer and all the logged in users. -m or USER_NAME/TICKET cannot be used with this option."))
	a.rootCmd.AddCommand(cmd)
}

func (a *App) update(isComputer, updateAll bool, target, krb5cc string) error {
	// incompatible options
	if updateAll && (isComputer || target != "" || krb5cc != "") {
		return errors.New(i18n.G("machine or user arguments cannot be used with update all"))
	}
	if isComputer && (target != "" || krb5cc != "") {
		return errors.New(i18n.G("user arguments cannot be used with machine update"))
	}

	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	// override for computer
	if (isComputer || updateAll) && target == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		// for malconfigured machines where /proc/sys/kernel/hostname returns the fqdn and not only the machine name, strip it
		if i := strings.Index(hostname, "."); i > 0 {
			hostname = hostname[:i]
		}
		target = hostname
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

	stream, err := client.UpdatePolicy(a.ctx, &adsys.UpdatePolicyRequest{
		IsComputer: isComputer,
		All:        updateAll,
		Target:     target,
		Krb5Cc:     krb5cc})
	if err != nil {
		return err
	}

	if _, err := stream.Recv(); err != nil && err != io.EOF {
		return err
	}

	return nil
}
