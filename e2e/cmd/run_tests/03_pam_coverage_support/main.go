// Package main provides a script to recompile the adsys PAM module with coverage support.
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

Rebuild PAM module with coverage support with the goal of collecting coverage data at the end of the suite.`, filepath.Base(os.Args[0]))

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

	// Install required dependencies to process coverage data
	if _, err := client.Run(ctx, "DEBIAN_FRONTEND=noninteractive apt-get install -y gcc gcovr libpam0g-dev"); err != nil {
		return fmt.Errorf("failed to install coverage dependencies: %w", err)
	}

	// Upload PAM module source code to a persistent location
	if err := client.Upload(filepath.Join(adsysRootDir, "pam", "pam_adsys.c"), "/root/pam/pam_adsys.c"); err != nil {
		return fmt.Errorf("failed to upload PAM module source code: %w", err)
	}

	// Rebuild PAM module in-place with coverage support
	if _, err := client.Run(ctx, fmt.Sprintf("gcc --coverage -shared -Wl,-soname,libpam_adsys.so -o %s/pam_adsys.so pam/pam_adsys.c -lpam", remote.PAMModuleDirectory)); err != nil {
		return fmt.Errorf("failed to compile PAM module: %w", err)
	}

	return nil
}
