// Package main provides a script to build adsys as a deb package for the given
// codename using a Docker container.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/e2e/internal/command"
	"github.com/ubuntu/adsys/e2e/internal/inventory"
	"github.com/ubuntu/adsys/e2e/scripts"
)

var codename string
var keep bool

func main() {
	os.Exit(run())
}

func run() int {
	cmd := command.New(action,
		command.WithValidateFunc(validate),
		command.WithStateTransition(inventory.Null, inventory.PackageBuilt),
	)
	cmd.Usage = fmt.Sprintf(`go run ./%s [options]

Build adsys as a deb package for the given Ubuntu release. Artifacts will be
placed in the output/ directory relative to the root of the repository.

Options:
 --codename       Required: codename of the Ubuntu release to build for (e.g. focal)
 -k, --keep       Don't remove the build container after finishing (default: false)

This script will:
 - build the adsys package in a Docker container from the current source tree for the given codename

`, filepath.Base(os.Args[0]))

	cmd.AddStringFlag(&codename, "codename", "", "")
	cmd.AddBoolFlag(&keep, "k", false, "")
	cmd.AddBoolFlag(&keep, "keep", false, "")

	return cmd.Execute(context.Background())
}

func validate(_ context.Context, _ *command.Command) error {
	if codename == "" {
		return errors.New("codename is required")
	}
	return nil
}

func action(ctx context.Context, cmd *command.Command) error {
	dockerTag := fmt.Sprintf("adsys-build-%s:latest", codename)

	scriptsDir, err := scripts.Dir()
	if err != nil {
		return err
	}

	log.Infof("Preparing build container %q", dockerTag)
	// #nosec G204: this is only for tests, under controlled args
	out, err := exec.CommandContext(ctx,
		"docker", "build", "-t", dockerTag,
		"--build-arg", fmt.Sprintf("CODENAME=%s", codename),
		"--file", filepath.Join(scriptsDir, "Dockerfile.build"), ".",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build container: %w: %s", err, string(out))
	}
	log.Debugf("docker build output: %s", string(out))

	// Run the container
	dockerArgs := []string{"run"}
	if !keep {
		dockerArgs = append(dockerArgs, "--rm")
	}

	adsysRootDir, err := scripts.RootDir()
	if err != nil {
		return err
	}
	dockerArgs = append(dockerArgs,
		"-v", fmt.Sprintf("%s:/source-ro:ro", adsysRootDir),
		"-v", fmt.Sprintf("%s/output:/output", adsysRootDir),
		"-v", fmt.Sprintf("%s/build-deb.sh:/build-deb.sh:ro", scriptsDir),
		"-v", fmt.Sprintf("%s/patches:/patches:ro", scriptsDir),
		// This is to set correct permissions on the output directory
		"-e", fmt.Sprintf("USER=%d", os.Getuid()),
		"-e", fmt.Sprintf("GROUP=%d", os.Getgid()),
		"--tmpfs", "/tmp:exec",
		"--ulimit", "nofile=1024:524288", // workaround an issue with fakeroot closing invalid file descriptors
		dockerTag,
		"/build-deb.sh",
	)

	log.Info("Building adsys package")
	log.Debugf("Running docker with args: %v", dockerArgs)
	out, err = exec.CommandContext(ctx, "docker", dockerArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run container: %w: %s", err, string(out))
	}
	log.Debugf("docker run output: %s", string(out))

	cmd.Inventory.Codename = codename

	return nil
}
