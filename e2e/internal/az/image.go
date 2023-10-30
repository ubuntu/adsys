package az

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/maruel/natural"
	log "github.com/sirupsen/logrus"
)

// NullImageVersion is the version returned when no image version is found.
const NullImageVersion = "0.0.0"

// Image contains information about an Azure image.
type Image struct {
	Architecture string `json:"architecture"`
	Offer        string `json:"offer"`
	Publisher    string `json:"publisher"`
	SKU          string `json:"sku"`
	URN          string `json:"urn"`
	Version      string `json:"version"`
}

// Images represents a list of Azure images.
type Images []Image

type imageVersion struct {
	Version string `json:"name"`
}

// ImageDefinitionName returns the name of the image definition for the given
// codename.
func ImageDefinitionName(codename string) string {
	return fmt.Sprintf("ubuntu-desktop-%s", codename)
}

// ImageList returns a list of Azure images for the given codename.
func ImageList(ctx context.Context, codename string) (Images, error) {
	out, _, err := RunCommand(ctx, "vm", "image", "list",
		"--publisher", "Canonical",
		"--offer", fmt.Sprintf("0001-com-ubuntu-minimal-%s", codename),
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

// LatestDaily returns the latest daily image for the given codename.
func (images Images) LatestDaily() (Image, error) {
	// Prepare list of eligible images
	dailyImages := []Image{}
	for _, image := range images {
		if image.Architecture == "x64" && image.isGen2Image() && image.isDailyImage() {
			dailyImages = append(dailyImages, image)
		}
	}

	if len(dailyImages) == 0 {
		return Image{}, fmt.Errorf("no daily image found")
	}

	// Reverse sort images by version
	slices.SortFunc(dailyImages, func(i, j Image) int {
		// Version format is: 23.04.20231029
		return cmp.Compare(j.Version, i.Version)
	})

	return dailyImages[0], nil
}

// LatestStable returns the latest stable image for the given codename.
func (images Images) LatestStable() (Image, error) {
	// Prepare list of eligible images
	stableImages := []Image{}
	for _, image := range images {
		if image.Architecture == "x64" && image.isGen2Image() && !image.isDailyImage() {
			stableImages = append(stableImages, image)
		}
	}

	if len(stableImages) == 0 {
		return Image{}, fmt.Errorf("no stable image found")
	}

	// Reverse sort images by version
	slices.SortFunc(stableImages, func(i, j Image) int {
		// Version format is: 23.04.20231029
		return cmp.Compare(j.Version, i.Version)
	})

	return stableImages[0], nil
}

func (i Image) isDailyImage() bool {
	return strings.Contains(i.Offer, "daily")
}

func (i Image) isGen2Image() bool {
	return strings.Contains(i.SKU, "gen2")
}

// LatestImageVersion returns the latest image version for the given image definition.
// If no version exists, "0.0.0" is returned.
func LatestImageVersion(ctx context.Context, imageDefinition string) (string, error) {
	latestVersion := NullImageVersion

	out, _, err := RunCommand(ctx, "sig", "image-version", "list",
		"--resource-group", "AD",
		"--gallery-name", "AD",
		"--gallery-image-definition", imageDefinition,
	)
	if err != nil {
		return latestVersion, err
	}

	var versions []imageVersion
	if err := json.Unmarshal(out, &versions); err != nil {
		return latestVersion, err
	}
	if len(versions) == 0 {
		return latestVersion, nil
	}

	log.Debugf("Found %d image versions: %s", len(versions), versions)

	for _, v := range versions {
		if natural.Less(latestVersion, v.Version) {
			latestVersion = v.Version
		}
	}

	return latestVersion, nil
}

// ImageBuildNumber returns the build number of the image given a version in the following format
// Canonical:0001-com-ubuntu-minimal-mantic:minimal-23_10-gen2:23.10.202310110 (202310110).
func ImageBuildNumber(baseVMImage string) string {
	urnParts := strings.Split(baseVMImage, ":")
	version := urnParts[len(urnParts)-1]
	versionParts := strings.Split(version, ".")
	buildNumber := versionParts[len(versionParts)-1]

	return buildNumber
}
