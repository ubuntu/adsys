// Package inventory provides functions to interact with the inventory file.
package inventory

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultPath is the default path to the inventory file.
	DefaultPath = "inventory.yaml"

	// DomainControllerIP is the IP address of the domain controller.
	DomainControllerIP = "10.1.0.4"
)

// Inventory represents the contents of an inventory file.
type Inventory struct {
	IP          string
	VMID        string
	UUID        string
	VMName      string
	BaseVMImage string
	Codename    string
	State       State
	SSHKeyPath  string
	Hostname    string
}

// Write writes the inventory file to the given path.
func Write(path string, inventory Inventory) error {
	data, err := yaml.Marshal(&inventory)
	if err != nil {
		return fmt.Errorf("failed to marshal inventory file: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write inventory file: %w", err)
	}

	return nil
}

// Read reads the inventory file at the given path.
func Read(path string) (Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Inventory{}, fmt.Errorf("failed to read inventory file: %w", err)
	}

	var inv Inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return Inventory{}, fmt.Errorf("failed to unmarshal inventory file: %w", err)
	}

	return inv, nil
}
