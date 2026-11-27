// Package main provides a script to destroy previous versions of an Azure VM
// image in order to optimize storage costs.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/maruel/natural"
	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/e2e/internal/az"
	"github.com/ubuntu/adsys/e2e/internal/command"
)

var codename string
var versionsToKeep int

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action, command.WithValidateFunc(validate))
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Delete old Azure VM template versions for an Ubuntu release.

Options:
 --codename          codename for which to delete image versions
 --versions-to-keep  number of versions to keep in storage (default: 2)

This script will:
 - query all image versions for the specified codename
 - keep the highest N versions and the highest version eligible for deployment

The machine must be authenticated to Azure via the Azure CLI.`, filepath.Base(os.Args[0]))

	cmd.AddStringFlag(&codename, "codename", "", "")
	cmd.AddIntFlag(&versionsToKeep, "versions-to-keep", 2, "")

	return cmd.Execute(context.Background())
}

func action(ctx context.Context, _ *command.Command) error {
	log.Infof("Getting image versions for %q", codename)

	imageDefinition := az.ImageDefinitionName(codename)
	versions, err := az.ListImageVersions(ctx, imageDefinition)
	if err != nil {
		return err
	}

	if len(versions) <= versionsToKeep {
		log.Infof("No versions to delete for %q", codename)
		return nil
	}

	slices.SortFunc(versions, func(a, b az.ImageVersion) int {
		return natural.Compare(b.Version, a.Version)
	})
	latestDeployable := slices.IndexFunc(versions, func(v az.ImageVersion) bool {
		return !v.PublishingProfile.ExcludeFromLatest
	})
	log.Infof("Deleting older image versions for %q", codename)

	for i := versionsToKeep; i < len(versions); i++ {
		if i == latestDeployable {
			continue
		}
		version := versions[i].Version
		log.Infof("Deleting image version %q", version)
		_, _, err := az.RunCommand(ctx, "sig", "image-version", "delete",
			"--resource-group", "AD",
			"--gallery-name", "AD",
			"--gallery-image-definition", imageDefinition,
			"--gallery-image-version", version,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func validate(_ context.Context, _ *command.Command) (err error) {
	if codename == "" {
		return errors.New("codename must be specified")
	}
	if versionsToKeep < 1 {
		return errors.New("versions-to-keep must be a positive number")
	}

	return nil
}
