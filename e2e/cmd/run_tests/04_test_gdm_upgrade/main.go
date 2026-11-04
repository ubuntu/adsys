// Package main verifies the released GDM profile regression and its repair by
// upgrading the same disposable Resolute VM.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ubuntu/adsys/e2e/internal/command"
	"github.com/ubuntu/adsys/e2e/internal/inventory"
	"github.com/ubuntu/adsys/e2e/internal/remote"
	"github.com/ubuntu/adsys/e2e/scripts"
)

func main() {
	cmd := command.New(action, command.WithRequiredState(inventory.ADProvisioned))
	cmd.Usage = `go run ./e2e/cmd/run_tests/04_test_gdm_upgrade

Verify the GDM profile regression with released adsys 0.16.4ubuntu1.1,
then upgrade to the candidate staged in /debs and verify its repair.
Provision the client using --baseline-deb before running this scenario.
This tests profile defaults and policy locks, not graphical logins.`
	os.Exit(cmd.Execute(context.Background()))
}

func action(ctx context.Context, cmd *command.Command) (err error) {
	if cmd.Inventory.Codename != "resolute" {
		return errors.New("the GDM upgrade regression requires Resolute")
	}
	key, err := command.ValidateAndExpandPath(cmd.Inventory.SSHKeyPath, command.DefaultSSHKeyPath)
	if err != nil {
		return err
	}
	client, err := remote.NewClient(cmd.Inventory.IP, "root", key)
	if err != nil {
		return err
	}
	defer client.Close()
	//nolint:errcheck // Collecting additional logs is best effort.
	defer client.CollectLogsOnFailure(ctx, &err, cmd.Inventory.Hostname)

	dir, err := scripts.Dir()
	if err != nil {
		return err
	}
	if err := client.Upload(filepath.Join(dir, "gdm_upgrade.py"), "/root/adsys-gdm-upgrade.py"); err != nil {
		return err
	}
	logDir := filepath.Join("logs", cmd.Inventory.Hostname)
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return err
	}
	defer func() {
		if reportErr := client.Download("/root/adsys-gdm-upgrade.json", filepath.Join(logDir, "gdm-upgrade.json")); reportErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to save GDM upgrade evidence: %w", reportErr))
		}
	}()

	_, err = client.Run(ctx, "python3 /root/adsys-gdm-upgrade.py")
	return err
}
