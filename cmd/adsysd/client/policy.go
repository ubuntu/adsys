package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installPolicy() {
	policyCmd := &cobra.Command{
		Use:   "policy COMMAND",
		Short: i18n.G("Policy management"),
		Args:  cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:  cmdhandler.NoCmd,
	}

	var distro *string
	mainCmd := &cobra.Command{
		Use:   "admx lts-only|all",
		Short: i18n.G("Dump windows policy definitions"),
		Args:  cobra.ExactValidArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return []string{"lts-only", "all"}, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error { return a.getPolicyDefinitions(args[0], *distro) },
	}
	distro = mainCmd.Flags().StringP("distro", "", consts.DistroID, i18n.G("distro for which to retrieve policy definition."))
	policyCmd.AddCommand(mainCmd)

	var details, all, nocolor *bool
	appliedCmd := &cobra.Command{
		Use:   "applied [USER_NAME]",
		Short: i18n.G("Print last applied GPOs for current or given user/machine"),
		Args:  cmdhandler.ZeroOrNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}

			return a.completeWithConnectedUsers()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var target string
			if len(args) > 0 {
				target = args[0]
			}
			return a.dumpPolicies(target, *details, *all, *nocolor)
		},
	}
	details = appliedCmd.Flags().BoolP("details", "", false, i18n.G("show applied rules in addition to GPOs."))
	all = appliedCmd.Flags().BoolP("all", "a", false, i18n.G("show overridden rules in each GPOs."))
	nocolor = appliedCmd.Flags().BoolP("no-color", "", false, i18n.G("don't display colorized version."))
	policyCmd.AddCommand(appliedCmd)
	cmdhandler.RegisterAlias(appliedCmd, &a.rootCmd)

	debugCmd := &cobra.Command{
		Use:    "debug",
		Short:  i18n.G("Debug various policy infos"),
		Hidden: true,
		Args:   cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:   cmdhandler.NoCmd,
	}
	policyCmd.AddCommand(debugCmd)
	gpoListCmd := &cobra.Command{
		Use:               "gpolist-script",
		Short:             i18n.G("Write GPO list python embeeded script in current directory"),
		Args:              cobra.NoArgs,
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(cmd *cobra.Command, args []string) error { return a.dumpGPOListScript() },
	}
	debugCmd.AddCommand(gpoListCmd)

	var updateMachine, updateAll *bool
	updateCmd := &cobra.Command{
		Use:   "update [USER_NAME KERBEROS_TICKET_PATH]",
		Short: i18n.G("Updates/Create a policy for current user or given user with its kerberos ticket"),
		Args:  cmdhandler.ZeroOrNArgs(2),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			// All and machine options don’t take arguments
			if *updateAll || *updateMachine {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			switch len(args) {
			case 0:
				// Get all connected users
				return a.completeWithConnectedUsers()
			case 1:
				// The user has already been process, let then specifying the ticket path
				return nil, cobra.ShellCompDirectiveDefault
			}

			// We already have our 2 args: no more arg completion
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var user, krb5cc string
			if len(args) > 0 {
				user, krb5cc = args[0], args[1]
			}
			return a.update(*updateMachine, *updateAll, user, krb5cc)
		},
	}
	updateMachine = updateCmd.Flags().BoolP("machine", "m", false, i18n.G("machine updates the policy of the computer."))
	updateAll = updateCmd.Flags().BoolP("all", "a", false, i18n.G("all updates the policy of the computer and all the logged in users. -m or USER_NAME/TICKET cannot be used with this option."))
	policyCmd.AddCommand(updateCmd)
	cmdhandler.RegisterAlias(updateCmd, &a.rootCmd)

	a.rootCmd.AddCommand(policyCmd)
}

// getPolicyDefinitions writes policy definitions files returns the current server and client versions.
func (a App) getPolicyDefinitions(format, distroID string) (err error) {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.DumpPoliciesDefinitions(a.ctx, &adsys.DumpPolicyDefinitionsRequest{
		Format:   format,
		DistroID: distroID,
	})
	if err != nil {
		return err
	}

	var admxContent, admlContent string
	for {
		r, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		admxContent, admlContent = r.GetAdmx(), r.GetAdml()
		if admxContent != "" && admlContent != "" {
			break
		}
	}

	admx, adml := fmt.Sprintf("%s.admx", distroID), fmt.Sprintf("%s.adml", distroID)
	log.Infof(context.Background(), "Saving %s and %s", admx, adml)
	if err := os.WriteFile(admx, []byte(admxContent), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(adml, []byte(admlContent), 0600); err != nil {
		return err
	}

	return nil
}

func (a *App) dumpPolicies(target string, showDetails, showOverridden, nocolor bool) error {
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
			return fmt.Errorf("failed to retrieve current user: %w", err)
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

	if nocolor {
		color.NoColor = true
	}
	policies, err = colorizePolicies(policies)
	if err != nil {
		return err
	}
	fmt.Print(policies)

	return nil
}

func (a *App) dumpGPOListScript() error {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.GPOListScript(a.ctx, &adsys.Empty{})
	if err != nil {
		return err
	}

	script, err := singleMsg(stream)
	if err != nil {
		return err
	}

	return os.WriteFile("adsys-gpolist", []byte(script), 0600)
}

func colorizePolicies(policies string) (string, error) {
	first := true
	var out stringsBuilderWithError

	bold := color.New(color.Bold)
	var currentPoliciesType string
	for _, l := range strings.Split(strings.TrimSpace(policies), "\n") {
		//nolint: whitespace
		// We prefer to have one blank line as separator.
		if e := strings.TrimPrefix(l, "***"); e != l {
			// Policy entry
			prefix := strings.TrimSpace(strings.Split(e, " ")[0])

			var overridden, disabledKey bool
			switch prefix {
			case "-":
				overridden = true
				e = e[2:]
			case "+":
				disabledKey = true
				e = e[2:]
			case "-+":
				overridden = true
				disabledKey = true
				e = e[3:]
			default:
				if len(e) > 0 {
					e = e[1:]
				}
			}

			indent := "        - "
			if disabledKey {
				if currentPoliciesType == "dconf" {
					e = fmt.Sprintf(i18n.G("%s: Locked to system default"), e)
				} else {
					e = fmt.Sprintf(i18n.G("%s: Disabled"), e)
				}
			}
			if overridden {
				e = color.HiBlackString("%s%s", indent, e)
			} else {
				e = fmt.Sprintf("%s%s", indent, e)
			}
			out.Println(e)

		} else if e := strings.TrimPrefix(l, "**"); e != l {
			// Type of policy
			e = strings.TrimSpace(e)
			currentPoliciesType = strings.TrimSuffix(e, ":")
			out.Println(fmt.Sprintf("    - %s", bold.Sprint(e)))

		} else if e := strings.TrimPrefix(l, "*"); e != l {
			// GPO
			e = strings.TrimSpace(e)
			i := strings.LastIndex(e, " ")
			gpoName := e[:i]
			gpoID := e[i:]
			out.Println(fmt.Sprintf("- %s%s", color.MagentaString(gpoName), gpoID))

		} else {
			// Machine or user
			if !first {
				out.Println("")
			}
			first = false
			out.Println(bold.Sprint(color.HiBlueString(l)))
		}
	}
	if out.err != nil {
		return "", out.err
	}
	return out.String(), nil
}

type stringsBuilderWithError struct {
	strings.Builder
	err error
}

func (s *stringsBuilderWithError) Println(l string) {
	if s.err != nil {
		return
	}
	l += "\n"
	_, s.err = s.Builder.WriteString(l)
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

	// get target for computer
	if isComputer && target == "" {
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
	if target == "" && !updateAll {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to retrieve current user: %w", err)
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

	if _, err := stream.Recv(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	return nil
}

func (a App) completeWithConnectedUsers() ([]string, cobra.ShellCompDirective) {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	defer client.Close()
	stream, err := client.ListActiveUsers(a.ctx, &adsys.Empty{})
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	list, err := singleMsg(stream)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	return strings.Split(list, " "), cobra.ShellCompDirectiveNoFileComp
}
