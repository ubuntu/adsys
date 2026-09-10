// Package az provides functions to interact with the Azure CLI.
package az

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// VMInfo contains information about a VM returned by az vm create.
type VMInfo struct {
	IP string `json:"privateIpAddress"`
	ID string `json:"id"`
}

// RunCommand runs the Azure CLI with the given arguments.
func RunCommand(ctx context.Context, args ...string) ([]byte, []byte, error) {
	log.Debugf("Running az with args %s", args)

	// #nosec G204,G702: this is only for the e2e tests, under controlled args
	c := exec.CommandContext(ctx, "az", args...)
	var outb, errb bytes.Buffer
	c.Stdout = &outb
	c.Stderr = &errb
	err := c.Run()

	// Report the output at a level that reflects the outcome. The CLI writes
	// advisories to stderr on calls that went perfectly well, so warning about
	// those unconditionally trains readers to disregard warnings, while a call
	// that failed is unreadable without the output explaining why.
	logOutput := log.Debugf
	if err != nil {
		logOutput = log.Warningf
	}
	if outb.Len() > 0 {
		logOutput("\tSTDOUT: %s", outb.String())
	}
	if errb.Len() > 0 {
		logOutput("\tSTDERR: %s", errb.String())
	}

	return outb.Bytes(), errb.Bytes(), err
}

// DeleteVM deletes the VM with the given name from Azure.
func DeleteVM(ctx context.Context, vmName string) error {
	log.Infof("Deleting VM %q", vmName)

	_, _, err := RunCommand(ctx, "vm", "delete",
		"--resource-group", "AD",
		"--name", vmName,
		"--force-deletion", "true",
		"--yes",
	)
	if err != nil {
		return fmt.Errorf("failed to delete VM: %w", err)
	}

	return nil
}
