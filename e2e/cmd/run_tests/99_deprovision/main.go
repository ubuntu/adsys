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
	"github.com/ubuntu/adsys/e2e/scripts"
)

var adPassword string

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action,
		command.WithValidateFunc(validate),
		command.WithStateTransition(inventory.ADProvisioned, inventory.Deprovisioned),
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

	scriptsDir, err := scripts.Dir()
	if err != nil {
		return err
	}

	// Leave realm and delete computer object
	_, err = client.Run(ctx, fmt.Sprintf("realm leave --remove -U localadmin -v --unattended <<<'%s'", adPassword))
	if err != nil {
		return fmt.Errorf("failed to leave domain: %w", err)
	}

	// Connect to the domain controller
	client, err = remote.NewClient(inventory.DomainControllerIP, "localadmin", sshKey)
	if err != nil {
		return err
	}
	defer client.Close()

	// Upload the PowerShell cleanup script to the domain controller
	if err := client.Upload(filepath.Join(scriptsDir, "cleanup-ad.ps1"), filepath.Join("C:", "Temp", cmd.Inventory.Hostname)); err != nil {
		return err
	}
	// Run the PowerShell cleanup script
	if _, err := client.Run(ctx, fmt.Sprintf("powershell.exe -ExecutionPolicy Bypass -File %s -hostname %s", filepath.Join("C:", "Temp", cmd.Inventory.Hostname, "cleanup-ad.ps1"), cmd.Inventory.Hostname)); err != nil {
		return fmt.Errorf("error running the PowerShell script: %w", err)
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
