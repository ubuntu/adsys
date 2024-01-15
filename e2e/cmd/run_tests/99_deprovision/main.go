// Package main provides a script that deprovisions previously created resources.
// This currently consists of leaving the realm and deleting the client VM.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/e2e/internal/az"
	"github.com/ubuntu/adsys/e2e/internal/command"
	"github.com/ubuntu/adsys/e2e/internal/inventory"
	"github.com/ubuntu/adsys/e2e/internal/remote"
)

var adPassword string

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action,
		command.WithValidateFunc(validate),
		command.WithStateTransition(inventory.ClientProvisioned, inventory.Deprovisioned),
	)
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Deprovision and destroy previously created resources.

This will leave the realm, delete the computer object from the domain, and
destroy the Azure client VM.`, filepath.Base(os.Args[0]))

	return cmd.Execute(context.Background())
}

func validate(_ context.Context, _ *command.Command) error {
	adPassword = os.Getenv("AD_PASSWORD")
	if adPassword == "" {
		return fmt.Errorf("AD_PASSWORD environment variable must be set")
	}

	return nil
}

func action(ctx context.Context, cmd *command.Command) error {
	ipAddress := cmd.Inventory.IP
	sshKey := cmd.Inventory.SSHKeyPath
	client, err := remote.NewClient(ipAddress, "root", sshKey)
	if err != nil {
		return fmt.Errorf("failed to connect to VM: %w", err)
	}
	defer client.Close()

	// Leave realm and delete computer object
	_, err = client.Run(ctx, fmt.Sprintf("realm leave --remove -U localadmin -v --unattended <<<'%s'", adPassword))
	if err != nil {
		return fmt.Errorf("failed to leave domain: %w", err)
	}

	// Destroy the client VM
	log.Infof("Destroying client VM %q", cmd.Inventory.VMName)
	_, _, err = az.RunCommand(ctx, "vm", "delete",
		"--resource-group", "AD",
		"--name", cmd.Inventory.VMName,
		"--force-deletion", "true",
		"--yes",
	)
	if err != nil {
		return err
	}

	return nil
}
