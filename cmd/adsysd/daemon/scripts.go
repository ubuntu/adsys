package daemon

import (
	"context"
	"fmt"

	systemd "github.com/coreos/go-systemd/daemon"
	"github.com/spf13/cobra"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/scripts"
)

func (a *App) installRunScripts() {
	var allowOrderMissing *bool
	cmd := &cobra.Command{
		Use:    "runscripts ORDER_FILE",
		Short:  i18n.G("Runs scripts in the given subdirectory"),
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE:   func(cmd *cobra.Command, args []string) error { return runScripts(args[0], *allowOrderMissing) },
	}
	allowOrderMissing = cmd.Flags().BoolP("allow-order-missing", "", false, i18n.G("allow ORDER_FILE to be missing once the scripts are ready."))
	a.rootCmd.AddCommand(cmd)
}

func runScripts(orderFile string, allowOrderMissing bool) error {
	if err := scripts.RunScripts(context.Background(), orderFile, allowOrderMissing); err != nil {
		return err
	}

	// TODO: mock this for tests
	if sent, err := systemd.SdNotify(false, "READY=1"); err != nil {
		return fmt.Errorf(i18n.G("couldn't send ready notification to systemd: %v"), err)
	} else if sent {
		log.Debug(context.Background(), i18n.G("Ready state sent to systemd"))
	}

	return nil
}
