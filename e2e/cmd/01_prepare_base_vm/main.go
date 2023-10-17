// Package main provides a script to create a base VM that can be turned into a
// template for E2E tests.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/e2e/internal/az"
	"github.com/ubuntu/adsys/e2e/internal/command"
	"github.com/ubuntu/adsys/e2e/internal/inventory"
	"github.com/ubuntu/adsys/e2e/internal/remote"
	"github.com/ubuntu/adsys/e2e/scripts"
)

var vmImage, codename, sshKey string
var keep bool

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action,
		command.WithValidateFunc(validate),
		command.WithStateTransition(inventory.Null, inventory.BaseVMCreated),
	)
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Create a base VM that can be turned into a template for E2E tests.

Options:
 --vm-image              Required: name of the Azure VM image to use as a base
                         image (e.g. Ubuntu2204, canonical:0001-com-ubuntu-minimal-focal:20_04-lts-gen2:latest)
 --codename              Required: codename of the Ubuntu release (e.g. focal)
 --ssh-key               SSH private key to use for authentication (default: ~/.ssh/id_rsa)
 -k, --keep              Don't destroy VM if template creation fails (default: false)

This script will:
 - create a VM from the specified Azure VM image
 - upgrade the system and install required packages
 - stage a provisioning script to run on first boot
 - stop and deallocate the VM

The machine must be authenticated to Azure via the Azure CLI.
The machine must be connected to the ADSys E2E tests VPN.`, filepath.Base(os.Args[0]))

	cmd.AddStringFlag(&vmImage, "vm-image", "", "")
	cmd.AddStringFlag(&codename, "codename", "", "")
	cmd.AddStringFlag(&sshKey, "ssh-key", "", "")
	cmd.AddBoolFlag(&keep, "keep", false, "")
	cmd.AddBoolFlag(&keep, "k", false, "")

	return cmd.Execute(context.Background())
}

func validate(_ context.Context, _ *command.Command) error {
	var err error
	sshKey, err = command.ValidateAndExpandPath(sshKey, command.DefaultSSHKeyPath)
	if err != nil {
		return err
	}

	if codename == "" {
		return errors.New("codename must be specified")
	}

	return nil
}

func action(ctx context.Context, cmd *command.Command) error {
	uuid := uuid.NewString()
	cmd.Inventory = inventory.Inventory{
		Codename: codename,
		UUID:     uuid,
	}

	inv := cmd.Inventory
	vmName := fmt.Sprintf("adsys-e2e-template-%s-%s", inv.Codename, inv.UUID)

	log.Infof("Creating VM %q from image %q with codename %q", vmName, vmImage, codename)
	out, _, err := az.RunCommand(ctx, "vm", "create",
		"--resource-group", "AD",
		"--name", vmName,
		"--image", vmImage,
		"--admin-username", "azureuser",
		"--security-type", "TrustedLaunch",
		"--size", "Standard_B2s",
		"--zone", "1",
		"--vnet-name", "adsys-integration-tests",
		"--nsg", "",
		"--subnet", "default",
		"--nic-delete-option", "Delete",
		"--public-ip-address", "",
		"--ssh-key-name", "adsys-e2e",
		"--storage-sku", "StandardSSD_LRS",
		"--os-disk-delete-option", "Delete",
		"--tags", "project=AD", "subproject=adsys-e2e-tests", "lifetime=6h",
	)
	if err != nil {
		return err
	}

	// Destroy VM if template creation fails
	defer func() {
		if err == nil {
			return
		}
		log.Error(err)

		if keep {
			log.Infof("Preserving VM as requested...")
			return
		}

		if err := az.DeleteVM(context.Background(), vmName); err != nil {
			log.Error(err)
		}
	}()

	// Parse create output to determine VM ID and private IP address
	log.Infof("Base VM created. Getting IP address...")
	var vm az.VMInfo
	if err := json.Unmarshal(out, &vm); err != nil {
		return fmt.Errorf("failed to parse az vm create output: %w", err)
	}
	ipAddress := vm.IP
	id := vm.ID

	client, err := remote.NewClient(ipAddress, "azureuser", sshKey)
	if err != nil {
		return fmt.Errorf("failed to connect to VM: %w", err)
	}
	defer client.Close()

	// Install required dependencies
	log.Infof("Installing eatmydata to speed up package installation...")
	if _, err := client.Run(ctx, `echo force-unsafe-io | sudo tee /etc/dpkg/dpkg.cfg.d/force-unsafe-io && \
sudo DEBIAN_FRONTEND=noninteractive apt-get update && \
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y eatmydata`); err != nil {
		return fmt.Errorf("failed to set up eatmydata: %w", err)
	}

	log.Infof("Installing required packages on VM...")
	if _, err := client.Run(ctx, `echo force-unsafe-io | sudo tee /etc/dpkg/dpkg.cfg.d/force-unsafe-io && \
sudo DEBIAN_FRONTEND=noninteractive eatmydata apt-get update && \
sudo DEBIAN_FRONTEND=noninteractive eatmydata apt-get upgrade -y && \
sudo DEBIAN_FRONTEND=noninteractive eatmydata apt-get install -y ubuntu-desktop realmd nfs-common cifs-utils && \
sudo sync && \
sudo rm -f /etc/dpkg/dpkg.cfg.d/force-unsafe-io
`); err != nil {
		return fmt.Errorf("failed to install required packages: %w", err)
	}

	// Upload first run script
	log.Infof("Staging first run script to VM...")
	scriptsDir, err := scripts.Dir()
	if err != nil {
		return fmt.Errorf("failed to get scripts directory: %w", err)
	}
	provisionScriptPath := filepath.Join(scriptsDir, "provision.sh")
	if err := client.Upload(provisionScriptPath, "/home/azureuser/provision.sh"); err != nil {
		return fmt.Errorf("failed to upload provisioning script: %w", err)
	}

	// Prepare script to run on first boot
	log.Infof("Preparing cloud-init script...")
	_, err = client.Run(ctx, "sudo cloud-init clean")
	if err != nil {
		return fmt.Errorf("failed to clean cloud-init: %w", err)
	}
	_, err = client.Run(ctx, "sudo mkdir -p /var/lib/cloud/scripts/per-once")
	if err != nil {
		return fmt.Errorf("failed to create cloud-init script directory: %w", err)
	}
	_, err = client.Run(ctx, "sudo mv /home/azureuser/provision.sh /var/lib/cloud/scripts/per-once/provision.sh")
	if err != nil {
		return fmt.Errorf("failed to copy cloud-init script: %w", err)
	}
	_, err = client.Run(ctx, "sudo chmod +x /var/lib/cloud/scripts/per-once/provision.sh")
	if err != nil {
		return fmt.Errorf("failed to make cloud-init script executable: %w", err)
	}

	// Close SSH connection
	if err := client.Close(); err != nil {
		return fmt.Errorf("failed to close SSH connection: %w", err)
	}

	// Stop and deallocate VM
	log.Infof("Deallocating VM...")
	_, _, err = az.RunCommand(ctx, "vm", "stop",
		"--resource-group", "AD",
		"--name", vmName,
	)
	if err != nil {
		return err
	}
	_, _, err = az.RunCommand(ctx, "vm", "deallocate",
		"--resource-group", "AD",
		"--name", vmName,
	)
	if err != nil {
		return err
	}

	cmd.Inventory.IP = ipAddress
	cmd.Inventory.VMID = id
	cmd.Inventory.BaseVMImage = vmImage
	cmd.Inventory.VMName = vmName
	cmd.Inventory.SSHKeyPath = sshKey

	return nil
}
