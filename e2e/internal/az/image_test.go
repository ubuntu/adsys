package az_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/e2e/internal/az"
)

func TestLatestStable(t *testing.T) {
	tests := map[string]struct {
		images az.Images

		wantVersion string
		wantErr     bool
	}{
		"Picks the newest image": {
			images: az.Images{
				minimal("ubuntu-26_04-lts", "minimal", "26.04.202607120"),
				minimal("ubuntu-26_04-lts", "minimal", "26.04.202607150"),
			},
			wantVersion: "26.04.202607150",
		},

		// The SKU filter is applied by the CLI as a substring, so a request
		// for "minimal" also returns the Ubuntu Pro variants. Those images are
		// not interchangeable with the plain ones here: the scenarios decide
		// for themselves whether the machine is subscribed. Reproduce the case
		// that made this visible, where the Pro image was the newer build.
		"Ignores Ubuntu Pro images even when they are newer": {
			images: az.Images{
				minimal("ubuntu-26_04-lts", "minimal", "26.04.202607150"),
				minimal("ubuntu-26_04-lts", "ubuntu-pro-minimal", "26.04.202607220"),
			},
			wantVersion: "26.04.202607150",
		},
		"Ignores gen1 Ubuntu Pro images": {
			images: az.Images{
				minimal("ubuntu-26_04-lts", "minimal", "26.04.202607150"),
				minimal("ubuntu-26_04-lts", "ubuntu-pro-minimal-gen1", "26.04.202607220"),
			},
			wantVersion: "26.04.202607150",
		},
		"Ignores Ubuntu Pro images in the old versioning scheme": {
			images: az.Images{
				minimal("0001-com-ubuntu-minimal-jammy", "minimal-22_04-lts-gen2", "22.04.202607150"),
				minimal("0001-com-ubuntu-pro-minimal-jammy", "pro-minimal-22_04-lts-gen2", "22.04.202607220"),
			},
			wantVersion: "22.04.202607150",
		},
		"Ignores gen1 images":  {images: az.Images{minimal("ubuntu-26_04-lts", "minimal-gen1", "26.04.202608060"), minimal("ubuntu-26_04-lts", "minimal", "26.04.202607150")}, wantVersion: "26.04.202607150"},
		"Ignores daily images": {images: az.Images{minimal("ubuntu-26_04-lts-daily", "minimal", "26.04.202608060"), minimal("ubuntu-26_04-lts", "minimal", "26.04.202607150")}, wantVersion: "26.04.202607150"},
		"Ignores other architectures": {images: az.Images{
			{Architecture: "arm64", Offer: "ubuntu-26_04-lts", SKU: "minimal", Version: "26.04.202608060"},
			minimal("ubuntu-26_04-lts", "minimal", "26.04.202607150"),
		}, wantVersion: "26.04.202607150"},

		"Error when only Ubuntu Pro images are available": {images: az.Images{minimal("ubuntu-26_04-lts", "ubuntu-pro-minimal", "26.04.202607220")}, wantErr: true},
		"Error when no image is available":                {images: az.Images{}, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := tc.images.LatestStable()
			if tc.wantErr {
				require.Error(t, err, "LatestStable should have returned an error but it didn't")
				return
			}
			require.NoError(t, err, "LatestStable should not have returned an error")
			require.Equal(t, tc.wantVersion, got.Version, "Unexpected image selected")
		})
	}
}

func TestLatestDaily(t *testing.T) {
	tests := map[string]struct {
		images az.Images

		wantVersion string
		wantErr     bool
	}{
		"Picks the newest daily image": {
			images: az.Images{
				minimal("ubuntu-26_10-daily", "minimal", "26.10.202607270"),
				minimal("ubuntu-26_10-daily", "minimal", "26.10.202607260"),
			},
			wantVersion: "26.10.202607270",
		},
		"Ignores Ubuntu Pro images even when they are newer": {
			images: az.Images{
				minimal("ubuntu-26_10-daily", "minimal", "26.10.202607260"),
				minimal("ubuntu-26_10-daily", "ubuntu-pro-minimal", "26.10.202607270"),
			},
			wantVersion: "26.10.202607260",
		},
		"Ignores stable images": {images: az.Images{minimal("ubuntu-26_10", "minimal", "26.10.202608060"), minimal("ubuntu-26_10-daily", "minimal", "26.10.202607260")}, wantVersion: "26.10.202607260"},

		"Error when no daily image is available": {images: az.Images{minimal("ubuntu-26_10", "minimal", "26.10.202608060")}, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := tc.images.LatestDaily()
			if tc.wantErr {
				require.Error(t, err, "LatestDaily should have returned an error but it didn't")
				return
			}
			require.NoError(t, err, "LatestDaily should not have returned an error")
			require.Equal(t, tc.wantVersion, got.Version, "Unexpected image selected")
		})
	}
}

// minimal returns an x64 image, the only architecture the tests provision.
func minimal(offer, sku, version string) az.Image {
	return az.Image{Architecture: "x64", Offer: offer, SKU: sku, Version: version}
}

func TestImageVersionSourceBuild(t *testing.T) {
	tests := map[string]struct {
		version string
		tags    map[string]string

		want string
	}{
		"Reads the build the template was created from": {
			version: "1.202609110.0",
			tags:    map[string]string{az.SourceBuildTag: "202609110"},
			want:    "202609110",
		},

		// The tag is what the version number stopped being able to convey:
		// the version has to keep increasing for Azure to serve a new
		// template, so it stays put when a change of SKU moves the build
		// backwards. Reading the minor instead would report a build this
		// template was never created from, and suppress the rebuilds for
		// everything published in between.
		"Prefers the tag over the minor when they disagree": {
			version: "1.202609110.1",
			tags:    map[string]string{az.SourceBuildTag: "202609100"},
			want:    "202609100",
		},

		// Versions published before the tag existed only have the minor,
		// which is what it used to mean.
		"Falls back to the minor when the tag is absent": {
			version: "1.202609110.0",
			want:    "202609110",
		},
		"Falls back to the minor when the tag is empty": {
			version: "1.202609110.0",
			tags:    map[string]string{az.SourceBuildTag: ""},
			want:    "202609110",
		},
		"Reports nothing for a version it cannot read": {
			version: "0.0",
			want:    "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			v := az.ImageVersion{Version: tc.version, Tags: tc.tags}
			require.Equal(t, tc.want, v.SourceBuild(), "Unexpected source build reported")
		})
	}
}

func TestImageVersionSourceURN(t *testing.T) {
	tests := map[string]struct {
		tags map[string]string

		want string
	}{
		"Reads the source URN tag": {
			tags: map[string]string{az.SourceURNTag: "Canonical:ubuntu-24_04-lts:minimal:24.04.202609100"},
			want: "Canonical:ubuntu-24_04-lts:minimal:24.04.202609100",
		},
		"Reports nothing when the tag is absent": {},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			v := az.ImageVersion{Tags: tc.tags}
			require.Equal(t, tc.want, v.SourceURN(), "Unexpected source URN reported")
		})
	}
}

// TestImageVersionUnmarshal pins the fields we read out of
// "az sig image-version list", which is the only place they come from.
func TestImageVersionUnmarshal(t *testing.T) {
	// Trimmed to the fields that matter, keeping the shape of a real reply.
	payload := `[
      {
        "location": "westeurope",
        "name": "1.202609110.1",
        "provisioningState": "Succeeded",
        "publishingProfile": {"replicaCount": 2},
        "resourceGroup": "AD",
        "tags": {
          "project": "AD",
          "sourceBuild": "202609100",
          "sourceURN": "Canonical:ubuntu-24_04-lts:minimal:24.04.202609100",
          "subproject": "adsys-e2e-tests"
        },
        "type": "Microsoft.Compute/galleries/images/versions"
      }
    ]`

	var versions []az.ImageVersion
	require.NoError(t, json.Unmarshal([]byte(payload), &versions), "Setup: could not unmarshal image version listing")

	require.Len(t, versions, 1, "Unexpected number of versions parsed")
	require.Equal(t, "1.202609110.1", versions[0].Version, "Unexpected version parsed")
	require.Equal(t, "202609100", versions[0].SourceBuild(), "Unexpected source build parsed")
	require.Equal(t, "Canonical:ubuntu-24_04-lts:minimal:24.04.202609100", versions[0].SourceURN(), "Unexpected source URN parsed")
}
