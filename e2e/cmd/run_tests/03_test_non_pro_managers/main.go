// Package main provides a script that applies and asserts non-Pro policies on
// the provisioned Ubuntu client.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

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

Apply and assert non-Pro policies on the Ubuntu client.

These policies are configured in the e2e/assets/gpo directory, and described as
part of the ADSys QA Plan document.

https://docs.google.com/document/d/1dIdhqAfNohapcTgWVVeyG7aSDMrGJekeezmoRdd_JSU/

This script will:
 - reboot the client VM to trigger machine policy application
 - assert machine GPO rules were applied
 - assert users and admins GPO rules were applied

The run is considered successful if the script exits with a zero exit code.

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

func action(ctx context.Context, cmd *command.Command) error {
	client, err := remote.NewClient(cmd.Inventory.IP, "root", sshKey)
	if err != nil {
		return fmt.Errorf("failed to connect to VM: %w", err)
	}

	// Reboot machine to apply machine policies
	if err := client.Reboot(); err != nil {
		return err
	}

	//nolint:errcheck // This is a best effort to collect logs
	defer client.CollectLogs(ctx, cmd.Inventory.Hostname)

	// Assert machine policies were applied
	if err := client.RequireEqual(ctx, "DCONF_PROFILE=gdm dconf read /org/gnome/desktop/interface/clock-format", "'12h'"); err != nil {
		return err
	}
	if err := client.RequireEqual(ctx, "DCONF_PROFILE=gdm dconf read /org/gnome/desktop/interface/clock-show-weekday", "false"); err != nil {
		return err
	}
	if err := client.RequireEqual(ctx, "DCONF_PROFILE=gdm dconf read /org/gnome/login-screen/banner-message-enable", "true"); err != nil {
		return err
	}
	if err := client.RequireEqual(ctx, "DCONF_PROFILE=gdm dconf read /org/gnome/login-screen/banner-message-text", "'Sample banner text'"); err != nil {
		return err
	}

	// Pro policies should not be applied yet
	if err := client.RequireEqual(ctx, "gsettings get org.gnome.system.proxy.ftp host", "''"); err != nil {
		return err
	}

	// Assert user GPO policies were applied
	client, err = remote.NewClient(cmd.Inventory.IP, fmt.Sprintf("%s-usr@warthogs.biz", cmd.Inventory.Hostname), remote.DomainUserPassword)
	if err != nil {
		return fmt.Errorf("failed to connect to VM: %w", err)
	}
	if err := client.RequireEqual(ctx, "dconf read /org/gnome/desktop/background/picture-uri", ""); err != nil {
		return err
	}

	expectedPictureURIDark := "'file:///usr/share/backgrounds/warty-final-ubuntu.png'"
	if cmd.Inventory.Codename == "jammy" {
		expectedPictureURIDark = "'file:///usr/share/backgrounds/ubuntu-default-greyscale-wallpaper.png'"
	}
	if err := client.RequireEqual(ctx, "dconf read /org/gnome/desktop/background/picture-uri-dark", expectedPictureURIDark); err != nil {
		return err
	}
	if err := client.RequireEqual(ctx, "dconf read /org/gnome/shell/favorite-apps", "['firefox.desktop', 'thunderbird.desktop', 'org.gnome.Nautilus.desktop']"); err != nil {
		return err
	}

	// Assert admin GPO policies were applied
	client, err = remote.NewClient(cmd.Inventory.IP, fmt.Sprintf("%s-adm@warthogs.biz", cmd.Inventory.Hostname), remote.DomainUserPassword)
	if err != nil {
		return fmt.Errorf("failed to connect to VM: %w", err)
	}
	if err := client.RequireEqual(ctx, "dconf read /org/gnome/shell/favorite-apps", "['rhythmbox.desktop']"); err != nil {
		return err
	}

	return nil
}
