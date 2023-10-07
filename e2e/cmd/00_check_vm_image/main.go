// Package main provides a script that checks for an existing Azure image for
// the given Ubuntu codename.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/maruel/natural"
	"github.com/ubuntu/adsys/e2e/internal/az"
	"github.com/ubuntu/adsys/e2e/internal/command"
	"golang.org/x/exp/slices"
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
image template already exists for the given codename, the script will exit with
an error unless the --force flag is set or the image is an upgrade from daily to
stable.

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
	availableImages, err := az.Images(ctx, codename)
	if err != nil {
		return err
	}
	stableIdx := slices.IndexFunc(availableImages, func(i az.Image) bool { return i.Stable() })
	develIdx := slices.IndexFunc(availableImages, func(i az.Image) bool { return i.Daily() })
	if stableIdx == -1 && develIdx == -1 {
		return fmt.Errorf("couldn't find any marketplace images for codename %q", codename)
	}

	var image az.Image
	if develIdx != -1 {
		image = availableImages[develIdx]
	}
	// Stable takes precedence over devel
	if stableIdx != -1 {
		image = availableImages[stableIdx]
	}

	imageDefinition := az.ImageDefinitionName(codename)
	latestImageVersion, err := az.LatestImageVersion(ctx, imageDefinition)
	if err != nil {
		return fmt.Errorf("failed to get latest image version: %w", err)
	}

	// The release is still in development and we already have a daily image built, nothing to do
	if natural.Less(latestImageVersion, "1.0.0") && stableIdx == -1 && !force {
		return fmt.Errorf("no stable image found for codename %q and development image already exists", codename)
	}

	// The release is stable and we already have a stable image built, nothing to do
	if !natural.Less(latestImageVersion, "1.0.0") && stableIdx != -1 && !force {
		return fmt.Errorf("stable image for codename %q already exists", codename)
	}

	// Otherwise, print the URN of the image to use
	urn := fmt.Sprintf("%s:%s:%s:latest", image.Publisher, image.Offer, image.SKU)
	fmt.Println(urn)

	return nil
}
