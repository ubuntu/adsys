package client

import (
	"fmt"
	"os/user"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installPolicies() {
	var details, all, nocolor *bool
	cmd := &cobra.Command{
		Use:   "policies [USER_NAME]",
		Short: i18n.G("Print last applied GPOs for current or given user/machine"),
		Args:  cmdhandler.ZeroOrNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var target string
			if len(args) > 0 {
				target = args[0]
			}
			return a.dumpPolicies(target, *details, *all, *nocolor)
		},
	}
	details = cmd.Flags().BoolP("details", "", false, i18n.G("show applied rules in addition to GPOs."))
	all = cmd.Flags().BoolP("all", "a", false, i18n.G("show overridden rules in each GPOs."))
	nocolor = cmd.Flags().BoolP("no-color", "", false, i18n.G("don't display colorized version."))
	a.rootCmd.AddCommand(cmd)
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

	if nocolor {
		color.NoColor = true
	}
	policies, err = colorPolicies(policies)
	if err != nil {
		return err
	}
	fmt.Print(policies)

	return nil
}

func colorPolicies(policies string) (string, error) {
	first := true
	var out stringsBuilderWithError

	bold := color.New(color.Bold)
	for _, l := range strings.Split(strings.TrimSpace(policies), "\n") {
		if e := strings.TrimPrefix(l, "***"); e != l {
			// Policy entry
			prefix := strings.TrimSpace(strings.Split(e, " ")[0])

			var overridden, systemDefault bool
			switch prefix {
			case "-":
				overridden = true
				e = e[2:]
			case "+":
				systemDefault = true
				e = e[2:]
			case "-+":
				overridden = true
				systemDefault = true
				e = e[3:]
			default:
				if len(e) > 0 {
					e = e[1:]
				}
			}

			indent := "        - "
			if systemDefault {
				e = fmt.Sprintf(i18n.G("%s: Locked to system default"), e)
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
