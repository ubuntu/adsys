package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/ad"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/decorate"
	"golang.org/x/sys/unix"
)

func (a *App) installPolicy() {
	policyCmd := &cobra.Command{
		Use:   "policy COMMAND",
		Short: gotext.Get("Policy management"),
		Args:  cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:  cmdhandler.NoCmd,
	}

	var distro *string
	mainCmd := &cobra.Command{
		Use:   "admx lts-only|all",
		Short: gotext.Get("Dump windows policy definitions"),
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return []string{"lts-only", "all"}, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error { return a.getPolicyDefinitions(args[0], *distro) },
	}
	distro = mainCmd.Flags().StringP("distro", "", consts.DistroID, gotext.Get("distro for which to retrieve policy definition."))
	policyCmd.AddCommand(mainCmd)

	var details, all, nocolor, isMachine *bool
	appliedCmd := &cobra.Command{
		Use:   "applied [USER_NAME]",
		Short: gotext.Get("Print last applied GPOs for current or given user/machine"),
		Args:  cmdhandler.ZeroOrNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}

			return a.users(true), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var target string
			if len(args) > 0 {
				target = args[0]
			}
			return a.dumpPolicies(target, *details, *all, *nocolor, *isMachine)
		},
	}
	details = appliedCmd.Flags().BoolP("details", "", false, gotext.Get("show applied rules in addition to GPOs."))
	all = appliedCmd.Flags().BoolP("all", "a", false, gotext.Get("show overridden rules in each GPOs."))
	nocolor = appliedCmd.Flags().BoolP("no-color", "", false, gotext.Get("don't display colorized version."))
	isMachine = appliedCmd.Flags().BoolP("machine", "m", false, gotext.Get("show applied rules to the machine."))
	policyCmd.AddCommand(appliedCmd)
	cmdhandler.RegisterAlias(appliedCmd, &a.rootCmd)

	debugCmd := &cobra.Command{
		Use:    "debug",
		Short:  gotext.Get("Debug various policy infos"),
		Hidden: true,
		Args:   cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:   cmdhandler.NoCmd,
	}
	policyCmd.AddCommand(debugCmd)
	gpoListCmd := &cobra.Command{
		Use:               "gpolist-script",
		Short:             gotext.Get("Write GPO list python embedded script in current directory"),
		Args:              cobra.NoArgs,
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(cmd *cobra.Command, args []string) error { return a.dumpGPOListScript() },
	}
	debugCmd.AddCommand(gpoListCmd)
	certEnrollCmd := &cobra.Command{
		Use:               "cert-autoenroll-script",
		Short:             gotext.Get("Write certificate autoenrollment python embedded script in current directory"),
		Args:              cobra.NoArgs,
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(cmd *cobra.Command, args []string) error { return a.dumpCertEnrollScript() },
	}
	debugCmd.AddCommand(certEnrollCmd)
	ticketPathCmd := &cobra.Command{
		Use:   "ticket-path",
		Short: gotext.Get("Print the path of the current (or given) user's Kerberos ticket"),
		Long: gotext.Get(`Infer and print the path of the current user's Kerberos ticket, leveraging the krb5 API.
The command is a no-op if the ticket is not present on disk or the detect_cached_ticket setting is not true.`),
		Args:              cmdhandler.ZeroOrNArgs(1),
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var username string
			if len(args) > 0 {
				username = args[0]
			}
			return a.printTicketPath(username)
		},
	}
	debugCmd.AddCommand(ticketPathCmd)

	var updateMachine, updateAll *bool
	updateCmd := &cobra.Command{
		Use:   "update [USER_NAME KERBEROS_TICKET_PATH]",
		Short: gotext.Get("Updates/Create a policy for current user or given user with its kerberos ticket"),
		Args:  cmdhandler.ZeroOrNArgs(2),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			// All and machine options don’t take arguments
			if *updateAll || *updateMachine {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			switch len(args) {
			case 0:
				// Get all connected users
				return a.users(true), cobra.ShellCompDirectiveNoFileComp
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
	updateMachine = updateCmd.Flags().BoolP("machine", "m", false, gotext.Get("machine updates the policy of the computer."))
	updateAll = updateCmd.Flags().BoolP("all", "a", false, gotext.Get("all updates the policy of the computer and all the logged in users. -m or USER_NAME/TICKET cannot be used with this option."))
	policyCmd.AddCommand(updateCmd)
	cmdhandler.RegisterAlias(updateCmd, &a.rootCmd)

	var purgeMachine, purgeAll *bool
	purgeCmd := &cobra.Command{
		Use:   "purge [USER_NAME]",
		Short: gotext.Get("Purges policies for the current user or a specified one"),
		Args:  cmdhandler.ZeroOrNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			// All and machine options don’t take arguments
			if *purgeAll || *purgeMachine || len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}

			// Get all users with cached policies
			return a.users(false), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var user string
			if len(args) > 0 {
				user = args[0]
			}
			return a.purge(*purgeMachine, *purgeAll, user)
		},
	}
	purgeMachine = purgeCmd.Flags().BoolP("machine", "m", false, gotext.Get("machine purges the policy of the computer."))
	purgeAll = purgeCmd.Flags().BoolP("all", "a", false, gotext.Get("all purges the policy of the computer and all the logged in users. -m or USER_NAME cannot be used with this option."))
	purgeCmd.MarkFlagsMutuallyExclusive("machine", "all")
	policyCmd.AddCommand(purgeCmd)

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

func (a *App) dumpPolicies(target string, showDetails, showOverridden, nocolor, isMachine bool) error {
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
		if isMachine {
			hostname, err := os.Hostname()
			if err != nil {
				return fmt.Errorf("failed to retrieve client hostname: %w", err)
			}
			target = hostname
		} else {
			u, err := user.Current()
			if err != nil {
				return fmt.Errorf("failed to retrieve current user: %w", err)
			}
			target = u.Username
		}
	}

	stream, err := client.DumpPolicies(a.ctx, &adsys.DumpPoliciesRequest{
		Target:     target,
		IsComputer: isMachine,
		Details:    showDetails,
		All:        showOverridden,
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

func (a *App) dumpCertEnrollScript() error {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.CertAutoEnrollScript(a.ctx, &adsys.Empty{})
	if err != nil {
		return err
	}

	script, err := singleMsg(stream)
	if err != nil {
		return err
	}

	return os.WriteFile("cert-autoenroll", []byte(script), 0600)
}

// printTicketPath prints the path to the Kerberos ccache of the given (or current) user to stdout.
// The function is a no-op if the detect_cached_ticket setting is not enabled.
// No error is raised if the inferred ticket is not present on disk.
func (a *App) printTicketPath(username string) (err error) {
	defer decorate.OnError(&err, gotext.Get("error getting ticket path"))

	// Do not print anything if the required setting is not enabled
	if !a.config.DetectCachedTicket {
		log.Debugf(a.ctx, "The detect_cached_ticket setting needs to be enabled to use this command")
		return nil
	}

	// Default to current user
	if username == "" {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to retrieve current user: %w", err)
		}
		username = u.Username
	}

	user, err := user.Lookup(username)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return err
	}

	// This effectively deescalates the current user's privileges with no
	// possibility of turning back. We're doing this on purpose right before the
	// code path that requires this, with the program exiting immediately after.
	if err := unix.Setuid(uid); err != nil {
		return fmt.Errorf(gotext.Get("failed to set privileges to UID %d: %v", uid, err))
	}

	krb5ccPath, err := ad.TicketPath()
	if errors.Is(err, ad.ErrTicketNotPresent) {
		log.Debugf(a.ctx, "No ticket found for user %s: %s", username, err)
		return nil
	}

	if err != nil {
		return err
	}

	fmt.Println(krb5ccPath)

	return nil
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
					e = gotext.Get("%s: Locked to system default", e)
				} else {
					e = gotext.Get("%s: Disabled", e)
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
		return errors.New(gotext.Get("machine or user arguments cannot be used with update all"))
	}
	if isComputer && (target != "" || krb5cc != "") {
		return errors.New(gotext.Get("user arguments cannot be used with machine update"))
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
		target, _, _ = strings.Cut(hostname, ".")
	}

	// Update for current user
	if target == "" && !updateAll {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to retrieve current user: %w", err)
		}
		target = u.Username
		krb5cc = strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:")
		if krb5cc == "" && a.config.DetectCachedTicket {
			krb5cc, err = ad.TicketPath()
			// Don't return an error as we might still have a cached ticket
			// under /run/adsys/krb5cc
			if err != nil {
				log.Warningf(a.ctx, "Failed to get ticket path: %v", err)
			}
		}
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

func (a *App) purge(isComputer, purgeAll bool, target string) error {
	// incompatible options
	if purgeAll && target != "" {
		return errors.New(gotext.Get("machine or user arguments cannot be used with update all"))
	}
	if isComputer && target != "" {
		return errors.New(gotext.Get("user arguments cannot be used with machine update"))
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
		target, _, _ = strings.Cut(hostname, ".")
	}

	// Purge current user
	if target == "" && !purgeAll {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to retrieve current user: %w", err)
		}
		target = u.Username
	}

	stream, err := client.UpdatePolicy(a.ctx, &adsys.UpdatePolicyRequest{
		IsComputer: isComputer,
		All:        purgeAll,
		Target:     target,
		Purge:      true,
	})
	if err != nil {
		return err
	}

	if _, err := stream.Recv(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	return nil
}

// users returns the list of connected users according to their cached policy information.
// If active is true, the list of users is retrieved from the cached Kerberos ticket information.
func (a App) users(active bool) []string {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return nil
	}
	defer client.Close()
	stream, err := client.ListUsers(a.ctx, &adsys.ListUsersRequest{Active: active})
	if err != nil {
		return nil
	}
	list, err := singleMsg(stream)
	if err != nil {
		return nil
	}

	return strings.Split(list, " ")
}
