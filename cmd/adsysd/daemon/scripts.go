package daemon

import (
	"context"
	"errors"

	systemd "github.com/coreos/go-systemd/v22/daemon"
	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/policies/scripts"
)

func (a *App) installRunScripts() {
	var allowOrderMissing *bool
	cmd := &cobra.Command{
		Use:    "runscripts ORDER_FILE",
		Short:  gotext.Get("Runs scripts in the given subdirectory"),
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE:   func(_ *cobra.Command, args []string) error { return runScripts(args[0], *allowOrderMissing) },
	}
	allowOrderMissing = cmd.Flags().BoolP("allow-order-missing", "", false, gotext.Get("allow ORDER_FILE to be missing once the scripts are ready."))
	a.rootCmd.AddCommand(cmd)
}

func runScripts(orderFile string, allowOrderMissing bool) error {
	if err := scripts.RunScripts(context.Background(), orderFile, allowOrderMissing); err != nil {
		return err
	}

	// TODO: mock this for tests
	if sent, err := systemd.SdNotify(false, "READY=1"); err != nil {
		return errors.New(gotext.Get("couldn't send ready notification to systemd: %v", err))
	} else if sent {
		log.Debug(context.Background(), gotext.Get("Ready state sent to systemd"))
	}

	return nil
}
