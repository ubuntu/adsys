package az

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/maruel/natural"
	log "github.com/sirupsen/logrus"
)

// Image contains information about an Azure image.
type Image struct {
	Architecture string `json:"architecture"`
	Offer        string `json:"offer"`
	Publisher    string `json:"publisher"`
	SKU          string `json:"sku"`
	URN          string `json:"urn"`
	Version      string `json:"version"`
}

type imageVersion struct {
	Version string `json:"name"`
}

// ImageDefinitionName returns the name of the image definition for the given
// codename.
func ImageDefinitionName(codename string) string {
	return fmt.Sprintf("ubuntu-desktop-%s", codename)
}

// Images returns a list of Azure images for the given codename.
func Images(ctx context.Context, codename string) ([]Image, error) {
	out, _, err := RunCommand(ctx, "vm", "image", "list",
		"--publisher", "Canonical",
		"--offer", fmt.Sprintf("0001-com-ubuntu-server-%s", codename),
		"--all",
	)
	if err != nil {
		return nil, err
	}

	var images []Image
	if err := json.Unmarshal(out, &images); err != nil {
		return nil, fmt.Errorf("failed to get image list: %w", err)
	}

	return images, nil
}

// Daily returns true if the given image is a daily image.
func (i Image) Daily() bool {
	return i.Architecture == "x64" && i.isGen2Image() && i.isDailyImage()
}

// Stable returns true if the given image is a stable image.
func (i Image) Stable() bool {
	return i.Architecture == "x64" && i.isGen2Image() && !i.isDailyImage()
}

func (i Image) isDailyImage() bool {
	return strings.Contains(i.Offer, "daily")
}

func (i Image) isGen2Image() bool {
	return strings.Contains(i.SKU, "gen2")
}

// LatestImageVersion returns the latest image version for the given image definition.
func LatestImageVersion(ctx context.Context, imageDefinition string) (string, error) {
	out, _, err := RunCommand(ctx, "sig", "image-version", "list",
		"--resource-group", "AD",
		"--gallery-name", "AD",
		"--gallery-image-definition", imageDefinition,
	)
	if err != nil {
		return "", err
	}

	var versions []imageVersion
	if err := json.Unmarshal(out, &versions); err != nil {
		return "", err
	}
	if len(versions) == 0 {
		return "", nil
	}

	log.Debugf("Found %d image versions: %s", len(versions), versions)

	latestVersion := "0.0.0"
	for _, v := range versions {
		if natural.Less(latestVersion, v.Version) {
			latestVersion = v.Version
		}
	}

	return latestVersion, nil
}
