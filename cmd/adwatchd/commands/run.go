package commands

import (
	"context"
	"errors"
	"strings"

	"github.com/kardianos/service"
	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	watchdconfig "github.com/ubuntu/adsys/internal/config/watchd"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/decorate"
)

func (a *App) installRun() {
	cmd := &cobra.Command{
		Use:   "run",
		Short: gotext.Get("Starts the directory watch loop"),
		Long: gotext.Get(`Can run as a service through the service manager or interactively as a standalone application.

The program will monitor the configured directories for changes and bump the appropriate GPT.ini versions anytime a change is detected.
If a GPT.ini file does not exist for a directory, a warning will be issued and the file will be created. If the GPT.ini file is incompatible or malformed, the program will report an error.
`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(a.config.Dirs) < 1 {
				return errors.New(gotext.Get("run command needs at least one directory to watch either with --dirs or via the configuration file"))
			}

			// Exit early if we are interactive and have a service with the same name running.
			if service.Interactive() {
				if status, _ := a.service.Status(context.Background()); strings.Contains(status, "running") {
					msg := gotext.Get("another instance of the %s service is already running", watchdconfig.CmdName)

					if !a.config.Force {
						return errors.New(gotext.Get("%s, use --force to override", msg))
					}
					log.Warningf(context.Background(), gotext.Get(msg))
				}
			}

			return a.service.Run(context.Background())
		},
	}

	var dirs []string
	cmd.Flags().StringSliceVarP(
		&dirs,
		"dirs",
		"d",
		[]string{},
		gotext.Get("a `directory` to check for changes (can be specified multiple times)"),
	)
	decorate.LogOnError(a.viper.BindPFlag("dirs", cmd.Flags().Lookup("dirs")))

	cmd.Flags().BoolP(
		"force",
		"f",
		false,
		gotext.Get("force the program to run even if another instance is already running"),
	)
	decorate.LogOnError(a.viper.BindPFlag("force", cmd.Flags().Lookup("force")))
	cmdhandler.InstallConfigFlag(cmd, false)

	a.rootCmd.AddCommand(cmd)
}
