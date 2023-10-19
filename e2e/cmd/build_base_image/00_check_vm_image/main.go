// Package main provides a script that checks for an existing Azure image for
// the given Ubuntu codename.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/maruel/natural"
	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/e2e/internal/az"
	"github.com/ubuntu/adsys/e2e/internal/command"
)

var codename string
var force bool

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action, command.WithValidateFunc(validate))
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Checks if the given Ubuntu codename is available as an Azure VM image.
Prioritizes stable image releases as opposed to daily builds, but allows daily
images if no stable image is available.

Prints the Azure URN of the image to use for the given codename. If a custom
image template already exists for the given codename, and the custom image
version is newer than the latest available Marketplace image, the script will
not output anything to stdout and will exit with 0.

If the --force flag is set, the script will return the latest image URN
regardless of custom image availability.

Options:
 --codename              Required: codename of the Ubuntu release (e.g. focal)
 -f, --force             Force the script to return the latest image URN
                         regardless of whether we have a custom image or not
`, filepath.Base(os.Args[0]))
	cmd.AddStringFlag(&codename, "codename", "", "")
	cmd.AddBoolFlag(&force, "force", false, "")
	cmd.AddBoolFlag(&force, "f", false, "")

	return cmd.Execute(context.Background())
}

func validate(_ context.Context, _ *command.Command) error {
	if codename == "" {
		return errors.New("codename must be specified")
	}

	return nil
}

func action(ctx context.Context, _ *command.Command) error {
	var noStable, noDaily bool

	availableImages, err := az.ImageList(ctx, codename)
	if err != nil {
		return err
	}
	latestStable, err := availableImages.LatestStable()
	if err != nil {
		noStable = true
		log.Warning(err)
	}

	latestDaily, err := availableImages.LatestDaily()
	if err != nil {
		noDaily = true
		log.Warning(err)
	}

	if noStable && noDaily {
		log.Errorf("couldn't find any marketplace images for codename %q", codename)
		return nil
	}

	latest := latestStable
	if noStable {
		latest = latestDaily
	}

	customImageDefinition := az.ImageDefinitionName(codename)
	latestCustomImageVersion, err := az.LatestImageVersion(ctx, customImageDefinition)
	if err != nil {
		return fmt.Errorf("failed to get latest image version: %w", err)
	}

	// Marketplace version includes the Ubuntu version as well (e.g.
	// 23.10.202310110).
	// As we store the Ubuntu version in the codename, we only need the patch
	// version to differentiate betweeen custom image builds.
	latestMarketplaceBuild := az.ImageBuildNumber(latest.Version)
	customVersionParts := strings.Split(latestCustomImageVersion, ".")
	latestCustomBuild := customVersionParts[1] // minor version is the build number

	// The release is still in development and we already have a daily image built, nothing to do
	// Version scheme is X.Y.Z where:
	// - X: major version, 0 for development releases, 1 for stable releases
	// - Y: minor version, replicates version of the Marketplace VM, e.g. 202310110
	// - Z: patch version, incremented for consecutive builds of the same minor version, starts at 0

	// Handle case where we have no custom image at all
	if latestCustomImageVersion == "0.0.0" || force {
		fmt.Println(latest.URN)
		return nil
	}

	// Handle cases where we only have custom images for development builds
	if natural.Less(latestCustomImageVersion, "1.0.0") {
		// Allow development -> stable transitions with the same version
		if latestCustomBuild >= latestMarketplaceBuild && noStable {
			log.Warningf("custom image for codename %q (%s) is equal or newer than the latest marketplace image (%s)", codename, latestCustomBuild, latestMarketplaceBuild)
			return nil
		}
		fmt.Println(latest.URN)
		return nil
	}

	// Handle cases where have custom images for stable builds
	if latestCustomBuild >= latestMarketplaceBuild {
		log.Warningf("custom image for codename %q (%s) is equal or newer than the latest marketplace image (%s)", codename, latestCustomBuild, latestMarketplaceBuild)
		return nil
	}

	fmt.Println(latest.URN)

	return nil
}
