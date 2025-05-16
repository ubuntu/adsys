// Package main provides a script to create a disposable Ubuntu VM on Azure,
// join it to the E2E tests domain and install the previously built
// adsys package.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/e2e/internal/az"
	"github.com/ubuntu/adsys/e2e/internal/command"
	"github.com/ubuntu/adsys/e2e/internal/inventory"
	"github.com/ubuntu/adsys/e2e/internal/remote"
	"github.com/ubuntu/adsys/e2e/scripts"
)

var keep bool
var sshKey, adPassword string

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action,
		command.WithValidateFunc(validate),
		command.WithStateTransition(inventory.PackageBuilt, inventory.ClientProvisioned),
	)
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Create a disposable Ubuntu VM on Azure, join it to the E2E tests domain
and install the adsys package.

This requires an inventory file containing the codename of the Ubuntu release
that will be provisioned. The AD password must be set in the AD_PASSWORD
environment variable.

Options:
 --ssh-key           SSH private key to use for authentication (default: ~/.ssh/id_rsa)
 -k, --keep          Don't destroy VM if provisioning fails (default: false)

This script will:
 - create a VM from the specified codename
 - join the VM to the E2E tests domain
 - install the previously built adsys package on the VM`, filepath.Base(os.Args[0]))

	cmd.AddStringFlag(&sshKey, "ssh-key", "", "")
	cmd.AddBoolFlag(&keep, "k", false, "")
	cmd.AddBoolFlag(&keep, "keep", false, "")

	return cmd.Execute(context.Background())
}

func validate(_ context.Context, _ *command.Command) (err error) {
	sshKey, err = command.ValidateAndExpandPath(sshKey, command.DefaultSSHKeyPath)
	if err != nil {
		return err
	}

	adPassword = os.Getenv("AD_PASSWORD")
	if adPassword == "" {
		return fmt.Errorf("AD_PASSWORD environment variable must be set")
	}

	return nil
}

func action(ctx context.Context, cmd *command.Command) error {
	adsysRootDir, err := scripts.RootDir()
	if err != nil {
		return err
	}

	codename := cmd.Inventory.Codename
	debs, err := filepath.Glob(filepath.Join(adsysRootDir, "output", codename, "*.deb"))
	if err != nil {
		return fmt.Errorf("failed to find adsys package: %w", err)
	}

	if len(debs) == 0 {
		return fmt.Errorf("no adsys package found in %q, please run the previous script in the suite", filepath.Join(adsysRootDir, "output"))
	}

	uuid := uuid.NewString()
	vmName := fmt.Sprintf("adsys-e2e-tests-%s-%s", codename, uuid)

	// Get subscription ID
	out, _, err := az.RunCommand(ctx, "account", "show", "--query", "id", "--output", "tsv")
	if err != nil {
		return err
	}
	subscriptionID := strings.TrimSpace(string(out))

	// Provision the VM
	log.Infof("Provisioning VM %q", vmName)
	out, _, err = az.RunCommand(ctx, "vm", "create",
		"--resource-group", "AD",
		"--name", vmName,
		"--image", fmt.Sprintf("/subscriptions/%s/resourceGroups/AD/providers/Microsoft.Compute/galleries/AD/images/%s", subscriptionID, az.ImageDefinitionName(codename)),
		"--specialized",
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

	// Destroy VM if any error occurs from here
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
	log.Infof("VM created. Getting IP address...")
	var vm az.VMInfo
	if err := json.Unmarshal(out, &vm); err != nil {
		return fmt.Errorf("failed to parse az vm create output: %w", err)
	}
	ipAddress := vm.IP
	id := vm.ID

	// Wait for cloud-init to finish before connecting
	_, _, err = az.RunCommand(ctx, "vm", "run-command", "invoke",
		"--ids", id,
		"--command-id", "RunShellScript",
		"--scripts", "cloud-init status --wait",
	)

	client, err := remote.NewClient(ipAddress, "root", sshKey)
	if err != nil {
		return fmt.Errorf("failed to connect to VM: %w", err)
	}
	defer client.Close()

	out, err = client.Run(ctx, "hostname")
	if err != nil {
		return fmt.Errorf("failed to get hostname of VM: %w", err)
	}
	hostname := strings.TrimSpace(string(out))

	_, err = client.Run(ctx, "mkdir -p /debs")
	if err != nil {
		return fmt.Errorf("failed to create /debs directory on VM: %w", err)
	}
	for _, deb := range debs {
		if err := client.Upload(deb, "/debs"); err != nil {
			return fmt.Errorf("failed to copy %q to VM: %w", deb, err)
		}
	}

	log.Infof("Updating and upgrading packages...")
	_, err = client.Run(ctx, "apt-get update")
	if err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}

	_, err = client.Run(ctx, "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y")
	if err != nil {
		return fmt.Errorf("failed to upgrade packages: %w", err)
	}

	log.Infof("Installing adsys package...")
	_, err = client.Run(ctx, "DEBIAN_FRONTEND=noninteractive apt-get install /debs/*.deb -y")
	if err != nil {
		return fmt.Errorf("failed to install adsys package: %w", err)
	}

	// TODO: remove this once the packages installed below are MIRed and installed by default with adsys
	// Allow errors here on account on packages not being available on the tested Ubuntu version
	log.Infof("Installing universe packages required for some policy managers...")
	if _, err := client.Run(ctx, "DEBIAN_FRONTEND=noninteractive apt-get install ubuntu-proxy-manager python3-cepces -y"); err != nil {
		log.Warningf("Some packages failed to install: %v", err)
	}

	log.Infof("Joining VM to domain...")
	_, err = client.Run(ctx, fmt.Sprintf("realm join warthogs.biz -U localadmin -v --unattended <<<'%s'", adPassword))
	if err != nil {
		return fmt.Errorf("failed to join VM to domain: %w", err)
	}

	cmd.Inventory.IP = ipAddress
	cmd.Inventory.VMID = id
	cmd.Inventory.UUID = uuid
	cmd.Inventory.VMName = vmName
	cmd.Inventory.SSHKeyPath = sshKey
	cmd.Inventory.Hostname = hostname

	return nil
}
