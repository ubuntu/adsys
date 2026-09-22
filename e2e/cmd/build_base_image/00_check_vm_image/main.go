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

var codename, version string
var force, checkTemplate bool

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action, command.WithValidateFunc(validate))
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Prints the Marketplace image URN when a new Azure template is needed.
Prefers stable images and keeps an existing stable template if only a daily
image is available. Within the same offer and SKU, an older build does not
replace a template with a known source.

If the --force flag is set, the script will return the latest image URN
regardless of custom image availability.

If the --check-template flag is set, the script ignores the Marketplace
entirely and prints the latest deployable custom template version for the
given codename, or nothing if none is available.

Options:
 --codename              Required: codename of the Ubuntu release (e.g. noble)
 --version               Required: version of the Ubuntu release (e.g. 24.04),
                         except with --check-template
 -f, --force             Force the script to return the latest image URN
                         regardless of whether we have a custom image or not
 --check-template        Print the version of the existing custom image
                         template, if any, and exit
`, filepath.Base(os.Args[0]))
	cmd.AddStringFlag(&codename, "codename", "", "")
	cmd.AddStringFlag(&version, "version", "", "")
	cmd.AddBoolFlag(&force, "force", false, "")
	cmd.AddBoolFlag(&force, "f", false, "")
	cmd.AddBoolFlag(&checkTemplate, "check-template", false, "")

	return cmd.Execute(context.Background())
}

func validate(_ context.Context, _ *command.Command) error {
	if codename == "" {
		return errors.New("codename must be specified")
	}

	if checkTemplate {
		if force {
			return errors.New("--check-template and --force are mutually exclusive")
		}
		return nil
	}

	if version == "" {
		return errors.New("version must be specified")
	}

	return nil
}

func action(ctx context.Context, _ *command.Command) error {
	imageDefinition := az.ImageDefinitionName(codename)
	if checkTemplate {
		custom, err := az.LatestDeployableImage(ctx, imageDefinition)
		if err != nil {
			return fmt.Errorf("failed to get latest deployable image: %w", err)
		}
		if custom.Version == "" {
			log.Warningf("no deployable image template found for codename %q", codename)
			return nil
		}
		fmt.Println(custom.Version)
		return nil
	}

	availableImages, err := az.ImageList(ctx, codename, version)
	if err != nil {
		return err
	}
	latest, err := availableImages.LatestStable()
	if err != nil {
		latest, err = availableImages.LatestDaily()
		if err != nil {
			log.Errorf("couldn't find any marketplace images for codename %q", codename)
			return nil
		}
	}

	if force {
		fmt.Println(latest.URN)
		return nil
	}
	custom, err := az.LatestDeployableImage(ctx, imageDefinition)
	if err != nil {
		return fmt.Errorf("failed to get latest deployable image: %w", err)
	}
	if shouldRebuild(custom, latest) {
		fmt.Println(latest.URN)
	} else {
		log.Infof("keeping custom image %q for %q (Marketplace candidate: %q)", custom.Version, codename, latest.URN)
	}
	return nil
}

func shouldRebuild(custom az.ImageVersion, latest az.Image) bool {
	if custom.Version == "" {
		return true
	}
	source := az.ParseMarketplaceURN(custom.Tags[az.SourceURNTag])
	if latest.IsDaily() {
		// For untagged templates, major 0 was reserved for daily builds.
		if source.Offer != "" && !source.IsDaily() ||
			source.Offer == "" && !natural.Less(custom.Version, "1.0.0") {
			return false
		}
	}
	// A source from another SKU can be the right replacement even if it is older.
	return source.Version == "" ||
		!strings.EqualFold(source.Publisher, latest.Publisher) ||
		!strings.EqualFold(source.Offer, latest.Offer) ||
		!strings.EqualFold(source.SKU, latest.SKU) ||
		strings.EqualFold(source.Version, "latest") ||
		natural.Less(source.Version, latest.Version)
}
