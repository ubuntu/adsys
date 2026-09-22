// Package main provides a script to generalize an Azure VM to be used as a
// template for E2E tests.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
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
 --version          override the template version number (by default the new
                    version sorts above every existing version)
 -k, --keep         don't destroy base VM after creating image version (default: false)

This script will:
 - create an Azure image definition for the Ubuntu version of the VM unless it already exists
 - create an image version using the VM, incrementing the version number
 - destroy the base VM unless otherwise specified

The script requires an inventory file to be present in the current directory,
created by the 01_prepare_base_vm script.

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

	source, err := sourceImage(ctx, inv.VMID, inv.BaseVMImage)
	if err != nil {
		return err
	}
	nextImageVersion := version
	if nextImageVersion == "" {
		build := source.Version[strings.LastIndexByte(source.Version, '.')+1:]
		nextImageVersion, err = constructNewVersion(latestImageVersion, build, source.IsDaily())
		if err != nil {
			return err
		}
	}

	// If the version is empty, we need to create the image definition
	if latestImageVersion == "" {
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

	// Create the image version
	log.Infof("Creating image version %q for image definition %q", nextImageVersion, imageDefinition)
	args := []string{"sig", "image-version", "create",
		"--resource-group", "AD",
		"--gallery-name", "AD",
		"--gallery-image-definition", imageDefinition,
		"--gallery-image-version", nextImageVersion,
		"--target-regions", "westeurope", "eastus=1=standard_zrs",
		"--replica-count", "2",
		"--virtual-machine", inv.VMID,
		"--tags", "project=AD", "subproject=adsys-e2e-tests",
	}
	if source.URN != "" {
		args = append(args, az.SourceURNTag+"="+source.URN)
	}
	_, _, err = az.RunCommand(ctx, args...)
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

// Read the VM's image reference when --vm-image was a floating URN or alias.
func sourceImage(ctx context.Context, vmID, requested string) (az.Image, error) {
	image := az.ParseMarketplaceURN(requested)
	if image.Version != "" && !strings.EqualFold(image.Version, "latest") {
		return image, nil
	}

	out, _, err := az.RunCommand(ctx, "vm", "show", "--ids", vmID,
		"--query", "storageProfile.imageReference", "--output", "json")
	if err != nil {
		return az.Image{}, fmt.Errorf("failed to read base VM image reference: %w", err)
	}
	var ref struct {
		az.Image
		ExactVersion string `json:"exactVersion"`
	}
	if err := json.Unmarshal(out, &ref); err != nil {
		return az.Image{}, fmt.Errorf("failed to decode base VM image reference: %w", err)
	}
	if ref.Publisher == "" {
		// A managed image or gallery version has no Marketplace source to tag.
		return az.Image{}, nil
	}
	if ref.ExactVersion != "" {
		ref.Version = ref.ExactVersion
	}
	if ref.Offer == "" || ref.SKU == "" || ref.Version == "" || strings.EqualFold(ref.Version, "latest") {
		return az.Image{}, fmt.Errorf("base VM %q has no exact Marketplace image reference", vmID)
	}
	ref.URN = ref.Publisher + ":" + ref.Offer + ":" + ref.SKU + ":" + ref.Version
	return ref.Image, nil
}

// Automatic versions must move forward even when the new source build is older.
func constructNewVersion(previous, buildNumber string, daily bool) (string, error) {
	var major, build uint64 = 1, 0
	if daily {
		major = 0
	}
	if buildNumber != "" {
		var err error
		build, err = strconv.ParseUint(buildNumber, 10, 31)
		if err != nil {
			return "", fmt.Errorf("invalid Marketplace build number %q: %w", buildNumber, err)
		}
	}
	if previous == "" {
		return fmt.Sprintf("%d.%d.0", major, build), nil
	}

	prevMajor, rest, _ := strings.Cut(previous, ".")
	prevMinor, prevPatch, _ := strings.Cut(rest, ".")
	oldMajor, majorErr := strconv.ParseUint(prevMajor, 10, 31)
	oldMinor, minorErr := strconv.ParseUint(prevMinor, 10, 31)
	oldPatch, patchErr := strconv.ParseUint(prevPatch, 10, 31)
	if majorErr != nil || minorErr != nil || patchErr != nil {
		return "", fmt.Errorf("invalid gallery image version %q", previous)
	}

	switch {
	case major > oldMajor:
		return fmt.Sprintf("%d.%d.0", major, build), nil
	case build > oldMinor:
		return fmt.Sprintf("%d.%d.0", oldMajor, build), nil
	case oldPatch < math.MaxInt32:
		return fmt.Sprintf("%d.%d.%d", oldMajor, oldMinor, oldPatch+1), nil
	case oldMinor < math.MaxInt32:
		return fmt.Sprintf("%d.%d.0", oldMajor, oldMinor+1), nil
	case oldMajor < math.MaxInt32:
		return fmt.Sprintf("%d.0.0", oldMajor+1), nil
	default:
		return "", fmt.Errorf("gallery image version %q cannot be incremented", previous)
	}
}
