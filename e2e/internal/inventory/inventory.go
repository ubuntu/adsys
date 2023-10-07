// Package inventory provides functions to interact with the inventory file.
package inventory

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the default path to the inventory file.
const DefaultPath = "inventory.yaml"

// Inventory represents the contents of an inventory file.
type Inventory struct {
	IP          string `yaml:"ip"`
	VMID        string `yaml:"vm_id"`
	UUID        string `yaml:"uuid"`
	VMName      string `yaml:"vm_name"`
	BaseVMImage string `yaml:"base_vm_image"`
	Codename    string `yaml:"codename"`
	State       State  `yaml:"state"`
	SSHKeyPath  string `yaml:"ssh_key_path"`
	Hostname    string `yaml:"hostname"`
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
