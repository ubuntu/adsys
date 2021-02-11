package client

import (
	"fmt"
	"os/user"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installPolicies() {
	var details, all *bool
	cmd := &cobra.Command{
		Use:   "policies [USER_NAME]",
		Short: i18n.G("Print last applied GPOs for current or given user/machine"),
		Args:  cmdhandler.ZeroOrNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var target string
			if len(args) > 0 {
				target = args[0]
			}
			return a.dumpPolicies(target, *details, *all)
		},
	}
	details = cmd.Flags().BoolP("details", "", false, i18n.G("show applied rules in addition to GPOs."))
	all = cmd.Flags().BoolP("all", "a", false, i18n.G("show overridden rules in each GPOs."))
	a.rootCmd.AddCommand(cmd)
}

func (a *App) dumpPolicies(target string, showDetails, showOverridden bool) error {
	// incompatible options
	if showOverridden && !showDetails {
		showDetails = true
	}

	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	// Dump for current user
	if target == "" {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to retrieve current user: %v", err)
		}
		target = u.Username
	}

	stream, err := client.DumpPolicies(a.ctx, &adsys.DumpPoliciesRequest{
		Target:  target,
		Details: showDetails,
		All:     showOverridden,
	})
	if err != nil {
		return err
	}

	policies, err := singleMsg(stream)
	if err != nil {
		return err
	}
	fmt.Println(policies)

	return nil
}
