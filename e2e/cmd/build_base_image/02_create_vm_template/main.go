// Package main provides a script to generalize an Azure VM to be used as a
// template for E2E tests.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/e2e/internal/az"
	"github.com/ubuntu/adsys/e2e/internal/command"
	"github.com/ubuntu/adsys/e2e/internal/inventory"
)

var version string
var keep bool

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action, command.WithStateTransition(inventory.BaseVMCreated, inventory.TemplateCreated))
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Generalize an Azure VM to use as a template for E2E tests.

Options:
 --version          override the template version number (default behavior is to
                    auto-increment the latest version by 0.0.1)
 -k, --keep         don't destroy base VM after creating image version (default: false)

This script will:
 - create an Azure image definition for the Ubuntu version of the VM unless it already exists
 - create an image version using the VM, incrementing the version number
 - destroy the base VM unless otherwise specified

The script requires an inventory file to be present in the current directory,
created by the 00_prepare_base_vm script.

The machine must be authenticated to Azure via the Azure CLI.`, filepath.Base(os.Args[0]))

	cmd.AddStringFlag(&version, "version", "", "")
	cmd.AddBoolFlag(&keep, "k", false, "")
	cmd.AddBoolFlag(&keep, "keep", false, "")

	return cmd.Execute(context.Background())
}

// action creates the image version from the base VM. The error is named so
// that the cleanup deferred below observes what the function actually returns:
// failure paths that bind their own err inside an if statement would otherwise
// leave the error the cleanup inspects untouched.
func action(ctx context.Context, cmd *command.Command) (err error) {
	inv := cmd.Inventory

	imageDefinition := az.ImageDefinitionName(inv.Codename)
	latestImageVersion, err := az.LatestImageVersion(ctx, imageDefinition)
	if err != nil {
		return err
	}

	isDevelopmentVersion := strings.Contains(cmd.Inventory.BaseVMImage, "daily")
	buildNumber := az.ImageBuildNumber(cmd.Inventory.BaseVMImage)
	nextImageVersion := constructNewVersion(latestImageVersion, buildNumber, isDevelopmentVersion)

	// Destroy VM if template creation fails
	var vmDeleted bool
	defer func() {
		if err == nil || vmDeleted {
			return
		}
		log.Error(err)

		if keep {
			log.Infof("Preserving VM as requested...")
			return
		}

		if err := az.DeleteVM(context.Background(), cmd.Inventory.VMName); err != nil {
			log.Error(err)
		}
	}()

	// If the version is empty, we need to create the image definition
	if latestImageVersion == az.NullImageVersion {
		log.Infof("Creating image definition %q", imageDefinition)
		_, _, err := az.RunCommand(ctx, "sig", "image-definition", "create",
			"--resource-group", "AD",
			"--gallery-name", "AD",
			"--gallery-image-definition", imageDefinition,
			"--publisher", "Canonical",
			"--offer", imageDefinition,
			"--sku", inv.Codename,
			"--os-type", "Linux",
			"--os-state", "Specialized",
			"--hyper-v-generation", "V2",
			"--features", "SecurityType=TrustedLaunch",
			"--tags", "project=AD", "subproject=adsys-e2e-tests",
		)
		if err != nil {
			return fmt.Errorf("failed to create image definition: %w", err)
		}
	}

	// User has specified a version, use it instead
	if version != "" {
		nextImageVersion = version
	}

	// Create the image version
	log.Infof("Creating image version %q for image definition %q", nextImageVersion, imageDefinition)
	_, _, err = az.RunCommand(ctx, "sig", "image-version", "create",
		"--resource-group", "AD",
		"--gallery-name", "AD",
		"--gallery-image-definition", imageDefinition,
		"--gallery-image-version", nextImageVersion,
		"--target-regions", "westeurope", "eastus=1=standard_zrs",
		"--replica-count", "2",
		"--virtual-machine", inv.VMID,
		"--tags", "project=AD", "subproject=adsys-e2e-tests",
		fmt.Sprintf("%s=%s", az.SourceBuildTag, buildNumber),
		fmt.Sprintf("%s=%s", az.SourceURNTag, inv.BaseVMImage),
	)
	if err != nil {
		return fmt.Errorf("failed to create image version: %w", err)
	}

	// Destroy base VM unless otherwise specified
	if keep {
		log.Infof("Preserving resource %q as requested", inv.VMID)
		return nil
	}
	if err := az.DeleteVM(ctx, cmd.Inventory.VMName); err != nil {
		return err
	}
	// The cleanup above must retry if the explicit deletion failed.
	vmDeleted = true

	return nil
}

// constructNewVersion builds a new version number for the image definition.
//
// Azure resolves an image definition to its highest version, not to the one
// built most recently, so a template only takes over from the one already
// published if it sorts above it.
//
// The build number of the image we start from usually climbs, but it does not
// have to: it identifies a publication of a specific SKU, so changing which
// SKU we build from can move it backwards. That is what happened when noble
// stopped being built from the Ubuntu Pro SKU, and the correct template that
// replaced it was never used because it sorted below the one it was meant to
// replace. Keep the published minor and increment the patch whenever the build
// number would not move us forward.
func constructNewVersion(prevVersion, buildNumber string, dev bool) string {
	newMajor := "1"
	if dev {
		newMajor = "0"
	}

	parts := strings.Split(prevVersion, ".")
	if len(parts) != 3 {
		return fmt.Sprintf("%s.%s.0", newMajor, buildNumber)
	}
	prevMajor, prevMinor := parts[0], parts[1]
	prevPatch, err := strconv.Atoi(parts[2])
	if err != nil {
		return fmt.Sprintf("%s.%s.0", newMajor, buildNumber)
	}

	// A different major means we are switching between daily and stable
	// images, which starts a series of its own rather than continuing this one.
	if prevMajor != newMajor {
		return fmt.Sprintf("%s.%s.0", newMajor, buildNumber)
	}

	build, errBuild := strconv.Atoi(buildNumber)
	prevBuild, errPrev := strconv.Atoi(prevMinor)
	if errBuild != nil || errPrev != nil || build <= prevBuild {
		return fmt.Sprintf("%s.%s.%d", newMajor, prevMinor, prevPatch+1)
	}

	return fmt.Sprintf("%s.%s.0", newMajor, buildNumber)
}
