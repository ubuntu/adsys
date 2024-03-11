// Package main provides a script that runs PAM krb5cc-related tests on the
// provisioned Ubuntu client.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/e2e/internal/command"
	"github.com/ubuntu/adsys/e2e/internal/inventory"
	"github.com/ubuntu/adsys/e2e/internal/remote"
)

var sshKey string

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action,
		command.WithValidateFunc(validate),
		command.WithRequiredState(inventory.ADProvisioned),
	)
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Perform PAM krb5cc-related tests on the provisioned Ubuntu client.

The runner must be connected to the ADSys E2E tests VPN.`, filepath.Base(os.Args[0]))

	return cmd.Execute(context.Background())
}

func validate(_ context.Context, cmd *command.Command) (err error) {
	sshKey, err = command.ValidateAndExpandPath(cmd.Inventory.SSHKeyPath, command.DefaultSSHKeyPath)
	if err != nil {
		return err
	}

	return nil
}

func action(ctx context.Context, cmd *command.Command) (err error) {
	rootClient, err := remote.NewClient(cmd.Inventory.IP, "root", sshKey)
	if err != nil {
		return fmt.Errorf("failed to connect to VM: %w", err)
	}

	//nolint:errcheck // This is a best effort to collect logs
	defer rootClient.CollectLogsOnFailure(ctx, &err, cmd.Inventory.Hostname)

	defer func() {
		if _, err := rootClient.Run(ctx, "rm -f /etc/adsys.yaml"); err != nil {
			log.Errorf("Teardown: Failed to remove adsys configuration file: %v", err)
		}
	}()

	// Install krb5-user to be able to interact with kinit
	if _, err := rootClient.Run(ctx, "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y krb5-user"); err != nil {
		return fmt.Errorf("failed to install krb5-user: %w", err)
	}

	/// detect_cached_ticket unset (disabled)
	// Connect with pubkey to bypass pam_sss setting KRB5CCNAME
	client, err := remote.NewClient(cmd.Inventory.IP, fmt.Sprintf("%s-usr@warthogs.biz", cmd.Inventory.Hostname), sshKey)
	if err != nil {
		return fmt.Errorf("failed to connect to VM as user with pubkey: %w", err)
	}
	if err := client.RequireEmpty(ctx, "echo $KRB5CCNAME"); err != nil {
		return fmt.Errorf("KRB5CCNAME not empty: %w", err)
	}

	// Create a ccache
	if _, err := client.Run(ctx, fmt.Sprintf("kinit %s-usr@WARTHOGS.BIZ <<<'%s'", cmd.Inventory.Hostname, remote.DomainUserPassword)); err != nil {
		return fmt.Errorf("failed to create ccache: %w", err)
	}

	// Set detect_cached_ticket to true
	if _, err := rootClient.Run(ctx, "echo 'detect_cached_ticket: true' > /etc/adsys.yaml"); err != nil {
		return fmt.Errorf("failed to set detect_cached_ticket to true: %w", err)
	}

	/// detect_cached_ticket enabled
	// Reconnect as user
	client, err = remote.NewClient(cmd.Inventory.IP, fmt.Sprintf("%s-usr@warthogs.biz", cmd.Inventory.Hostname), sshKey)
	if err != nil {
		return fmt.Errorf("failed to connect to VM as user with pubkey: %w", err)
	}
	if err := client.RequireNotEmpty(ctx, "echo $KRB5CCNAME"); err != nil {
		return fmt.Errorf("KRB5CCNAME empty: %w", err)
	}

	// Remove ticket cache
	if _, err := rootClient.Run(ctx, "rm -f /tmp/krb5cc_*"); err != nil {
		return fmt.Errorf("failed to remove ticket cache: %w", err)
	}

	// Reconnect as user, KRB5CCNAME should be left unset
	client, err = remote.NewClient(cmd.Inventory.IP, fmt.Sprintf("%s-usr@warthogs.biz", cmd.Inventory.Hostname), sshKey)
	if err != nil {
		return fmt.Errorf("failed to connect to VM as user with pubkey: %w", err)
	}
	if err := client.RequireEmpty(ctx, "echo $KRB5CCNAME"); err != nil {
		return fmt.Errorf("KRB5CCNAME not empty: %w", err)
	}

	return nil
}
