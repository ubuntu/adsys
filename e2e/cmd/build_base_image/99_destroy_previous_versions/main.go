// Package main provides a script to destroy previous versions of an Azure VM
// image in order to optimize storage costs.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

Generalize an Azure VM to use as a template for E2E tests.

Options:
 --codename          codename for which to delete image versions
 --versions-to-keep  number of versions to keep in storage (default: 2)

This script will:
 - query all image versions for the specified codename
 - delete all but the latest N versions, as specified by --versions-to-keep

The machine must be authenticated to Azure via the Azure CLI.`, filepath.Base(os.Args[0]))

	cmd.AddStringFlag(&codename, "codename", "", "")
	cmd.AddIntFlag(&versionsToKeep, "versions-to-keep", 2, "")

	return cmd.Execute(context.Background())
}

func action(ctx context.Context, _ *command.Command) error {
	log.Infof("Getting image versions for %q", codename)

	out, _, err := az.RunCommand(ctx, "sig", "image-version", "list",
		"--resource-group", "AD",
		"--gallery-name", "AD",
		"--gallery-image-definition", az.ImageDefinitionName(codename),
		"--output", "tsv",
		"--query", "[].name",
	)
	if err != nil {
		return err
	}

	versions := strings.Split(string(out), "\n")
	if len(versions) <= versionsToKeep {
		log.Infof("No versions to delete for %q", codename)
		return nil
	}

	versionsToDelete := versions[:len(versions)-versionsToKeep-1]
	log.Infof("Deleting %d versions for %q: %v", len(versionsToDelete), codename, versionsToDelete)

	for _, version := range versionsToDelete {
		_, _, err := az.RunCommand(ctx, "sig", "image-version", "delete",
			"--resource-group", "AD",
			"--gallery-name", "AD",
			"--gallery-image-definition", az.ImageDefinitionName(codename),
			"--gallery-image-version", version,
		)
		if err != nil {
			return err
		}
	}

	log.Infof("Successfully deleted %d image versions", len(versionsToDelete))

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
