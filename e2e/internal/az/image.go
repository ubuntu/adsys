package az

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/maruel/natural"
)

// oldImageVersionCodenames is a list of Ubuntu codenames for which Azure images
// are built using the previous image versioning format.
var oldImageVersionCodenames = []string{"focal", "jammy", "mantic"}

// Image contains information about an Azure image.
type Image struct {
	Architecture string `json:"architecture"`
	Offer        string `json:"offer"`
	Publisher    string `json:"publisher"`
	SKU          string `json:"sku"`
	URN          string `json:"urn"`
	Version      string `json:"version"`
}

// ParseMarketplaceURN splits a publisher:offer:sku:version reference.
// A Marketplace alias or gallery image ID returns an empty Image.
func ParseMarketplaceURN(urn string) Image {
	publisher, rest, _ := strings.Cut(urn, ":")
	offer, rest, _ := strings.Cut(rest, ":")
	sku, version, _ := strings.Cut(rest, ":")
	if publisher == "" || offer == "" || sku == "" || version == "" || strings.Contains(version, ":") {
		return Image{}
	}
	return Image{Publisher: publisher, Offer: offer, SKU: sku, Version: version, URN: urn}
}

// Images represents a list of Azure images.
type Images []Image

// SourceURNTag is the image version tag recording the full Marketplace image
// identity a template was created from.
const SourceURNTag = "sourceURN"

// ImageVersion is a version of one of our own image definitions.
type ImageVersion struct {
	Version           string            `json:"name"`
	Tags              map[string]string `json:"tags"`
	PublishingProfile struct {
		ExcludeFromLatest bool `json:"excludeFromLatest"`
	} `json:"publishingProfile"`
}

// ImageDefinitionName returns the name of the image definition for the given
// codename.
func ImageDefinitionName(codename string) string {
	return fmt.Sprintf("ubuntu-desktop-%s", codename)
}

// ImageList returns a list of Azure images for the given codename.
func ImageList(ctx context.Context, codename, version string) (Images, error) {
	versionParts := strings.Split(version, ".")
	if len(versionParts) != 2 {
		return nil, fmt.Errorf("invalid version format: %s", version)
	}

	// Determine if this is an LTS release
	year, err := strconv.Atoi(versionParts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse version year as a number: %w", err)
	}
	isLTS := year%2 == 0 && versionParts[1] == "04"

	version = fmt.Sprintf("ubuntu-%s", strings.Join(versionParts, "_"))
	if isLTS {
		version += "-lts"
	}

	var filterArgs []string
	filterArgs = []string{"--offer", version, "--sku", "minimal"}
	if slices.Contains(oldImageVersionCodenames, codename) {
		filterArgs = []string{"--offer", fmt.Sprintf("0001-com-ubuntu-minimal-%s", codename)}
	}

	args := []string{"vm", "image", "list", "--publisher", "Canonical", "--all"}
	args = append(args, filterArgs...)

	out, _, err := RunCommand(ctx, args...)
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
	return images.latest(true)
}

// LatestStable returns the latest stable image for the given codename.
func (images Images) LatestStable() (Image, error) {
	return images.latest(false)
}

func (images Images) latest(daily bool) (Image, error) {
	var latest Image
	for _, image := range images {
		if image.Architecture == "x64" && image.IsDaily() == daily && image.isGen2Image() &&
			!image.isProImage() && natural.Less(latest.Version, image.Version) {
			latest = image
		}
	}
	if latest.Version == "" {
		if daily {
			return Image{}, fmt.Errorf("no daily image found")
		}
		return Image{}, fmt.Errorf("no stable image found")
	}
	return latest, nil
}

// IsDaily reports whether the Marketplace offer is a daily build.
func (i Image) IsDaily() bool {
	return strings.Contains(strings.ToLower(i.Offer), "daily")
}

// Azure's "minimal" filter also matches Pro variants. Older offers put "pro"
// at the start of the SKU; newer SKUs include it after "ubuntu-".
func (i Image) isProImage() bool {
	for _, name := range [2]string{i.SKU, i.Offer} {
		for part := range strings.SplitSeq(name, "-") {
			if part == "pro" {
				return true
			}
		}
	}
	return false
}

func (i Image) isGen2Image() bool {
	// gen2 images are explicitly defined in the old versioning scheme.
	if strings.Contains(i.Offer, "0001-com-ubuntu") {
		return strings.Contains(i.SKU, "gen2")
	}

	return !strings.Contains(i.SKU, "gen1")
}

// LatestImageVersion returns the highest gallery version, including versions
// excluded from deployment as latest. An empty result means no version exists.
func LatestImageVersion(ctx context.Context, imageDefinition string) (string, error) {
	latest, err := latestImage(ctx, imageDefinition, false)
	return latest.Version, err
}

// LatestDeployableImage returns the highest gallery version not excluded from
// latest. An empty result means no such version exists.
func LatestDeployableImage(ctx context.Context, imageDefinition string) (ImageVersion, error) {
	return latestImage(ctx, imageDefinition, true)
}

func latestImage(ctx context.Context, imageDefinition string, deployableOnly bool) (ImageVersion, error) {
	versions, err := ListImageVersions(ctx, imageDefinition)
	if err != nil {
		return ImageVersion{}, err
	}

	var latest ImageVersion
	for _, version := range versions {
		if deployableOnly && version.PublishingProfile.ExcludeFromLatest {
			continue
		}
		if natural.Less(latest.Version, version.Version) {
			latest = version
		}
	}
	return latest, nil
}

// ListImageVersions returns the gallery versions and their publishing profiles.
// A missing image definition has no versions.
func ListImageVersions(ctx context.Context, imageDefinition string) ([]ImageVersion, error) {
	out, stderr, err := RunCommand(ctx, "sig", "image-version", "list",
		"--resource-group", "AD",
		"--gallery-name", "AD",
		"--gallery-image-definition", imageDefinition,
		"--output", "json",
	)
	if err != nil {
		if bytes.Contains(stderr, []byte("ResourceNotFound")) {
			return nil, nil
		}
		return nil, err
	}

	var versions []ImageVersion
	if err := json.Unmarshal(out, &versions); err != nil {
		return nil, fmt.Errorf("failed to read gallery versions: %w", err)
	}

	return versions, nil
}
