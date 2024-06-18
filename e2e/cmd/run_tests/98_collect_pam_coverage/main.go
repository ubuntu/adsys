// Package main provides a script to collect PAM module coverage from the remote Ubuntu VM.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

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
		command.WithStateTransition(inventory.ADProvisioned, inventory.ADProvisioned),
	)
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Collect PAM module coverage and save it locally to output/pam-cobertura.xml`, filepath.Base(os.Args[0]))

	return cmd.Execute(context.Background())
}

func validate(_ context.Context, cmd *command.Command) (err error) {
	sshKey, err = command.ValidateAndExpandPath(cmd.Inventory.SSHKeyPath, command.DefaultSSHKeyPath)
	if err != nil {
		return err
	}

	return nil
}

func action(ctx context.Context, cmd *command.Command) error {
	adsysRootDir, err := scripts.RootDir()
	if err != nil {
		return err
	}

	// Establish remote connection
	client, err := remote.NewClient(cmd.Inventory.IP, "root", sshKey)
	if err != nil {
		return fmt.Errorf("failed to connect to VM: %w", err)
	}
	defer client.Close()

	// Collect PAM module coverage if present
	if _, err := client.Run(ctx, fmt.Sprintf("gcovr --cobertura --output=/tmp/pam-cobertura.xml %s", remote.PAMModuleDirectory)); err != nil {
		return fmt.Errorf("failed to collect PAM module coverage: %w", err)
	}

	if err := client.Download("/tmp/pam-cobertura.xml", filepath.Join(adsysRootDir, "output", "pam-cobertura.xml")); err != nil {
		return fmt.Errorf("failed to download PAM module coverage: %w", err)
	}

	return nil
}
