// Package main provides a script to prepare OU and GPO configuration on the
// domain controller, converting XML GPOs to binary POL format and staging them
// in the SYSVOL share.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/e2e/internal/command"
	"github.com/ubuntu/adsys/e2e/internal/inventory"
	"github.com/ubuntu/adsys/e2e/internal/remote"
	"github.com/ubuntu/adsys/e2e/scripts"
)

var sshKey string

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action,
		command.WithValidateFunc(validate),
		command.WithStateTransition(inventory.ClientProvisioned, inventory.ADProvisioned),
	)
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Prepare OU and GPO configuration on the domain controller.

The AD password must be set in the AD_PASSWORD environment variable.

This script will:
 - convert XML GPOs in the e2e/gpo directory to POL format
 - upload the GPO structure to the domain controller
 - upload & run a PowerShell script to the domain controller responsible for creating the required resources`, filepath.Base(os.Args[0]))

	return cmd.Execute(context.Background())
}

func validate(_ context.Context, cmd *command.Command) error {
	var err error
	sshKey, err = command.ValidateAndExpandPath(cmd.Inventory.SSHKeyPath, command.DefaultSSHKeyPath)
	if err != nil {
		return err
	}

	return nil
}

func action(ctx context.Context, cmd *command.Command) error {
	gpoDir, err := scripts.GPODir()
	if err != nil {
		return err
	}
	scriptsDir, err := scripts.Dir()
	if err != nil {
		return err
	}

	// Convert XML GPOs to POL format
	// #nosec G204: this is only for tests, under controlled args
	out, err := exec.CommandContext(ctx, "python3", filepath.Join(scriptsDir, "xml_to_pol.py"), gpoDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to convert GPOs to POL format: %w\n%s", err, out)
	}
	log.Debugf("xml_to_pol.py output:\n%s", out)

	// Establish remote connection
	client, err := remote.NewClient(inventory.DomainControllerIP, "localadmin", sshKey)
	if err != nil {
		return err
	}
	defer client.Close()

	// Recursively upload the GPO structure to the domain controller
	if err := filepath.Walk(gpoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// We only need to copy files
		if info.IsDir() {
			return nil
		}

		// Get the relative path of the file
		relPath, err := filepath.Rel(gpoDir, path)
		if err != nil {
			return err
		}

		// Upload the file
		remotePath := filepath.Join("C:", "Temp", cmd.Inventory.Hostname, relPath)
		if err := client.Upload(path, remotePath); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to upload GPOs to domain controller: %w", err)
	}

	// Upload the PowerShell script to the domain controller
	if err := client.Upload(filepath.Join(scriptsDir, "prepare-ad.ps1"), filepath.Join("C:", "Temp", cmd.Inventory.Hostname)); err != nil {
		return err
	}

	// Run the PowerShell script
	if _, err := client.Run(ctx, fmt.Sprintf("powershell.exe -ExecutionPolicy Bypass -File %s -hostname %s", filepath.Join("C:", "Temp", cmd.Inventory.Hostname, "prepare-ad.ps1"), cmd.Inventory.Hostname)); err != nil {
		return fmt.Errorf("error running the PowerShell script: %w", err)
	}

	return nil
}
