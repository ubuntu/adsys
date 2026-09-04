package az_test

import (
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
		// for "minimal" also returns "pro-minimal". Ubuntu Pro images are not
		// interchangeable with the plain ones here: the scenarios decide for
		// themselves whether the machine is subscribed. Reproduce the case
		// that made this visible, where the Pro image was the newer build.
		"Ignores Ubuntu Pro images even when they are newer": {
			images: az.Images{
				minimal("ubuntu-26_04-lts", "minimal", "26.04.202607150"),
				minimal("ubuntu-26_04-lts", "pro-minimal", "26.04.202607220"),
			},
			wantVersion: "26.04.202607150",
		},
		"Ignores gen1 images":  {images: az.Images{minimal("ubuntu-26_04-lts", "minimal-gen1", "26.04.202608060"), minimal("ubuntu-26_04-lts", "minimal", "26.04.202607150")}, wantVersion: "26.04.202607150"},
		"Ignores daily images": {images: az.Images{minimal("ubuntu-26_04-lts-daily", "minimal", "26.04.202608060"), minimal("ubuntu-26_04-lts", "minimal", "26.04.202607150")}, wantVersion: "26.04.202607150"},
		"Ignores other architectures": {images: az.Images{
			{Architecture: "arm64", Offer: "ubuntu-26_04-lts", SKU: "minimal", Version: "26.04.202608060"},
			minimal("ubuntu-26_04-lts", "minimal", "26.04.202607150"),
		}, wantVersion: "26.04.202607150"},

		"Error when only Ubuntu Pro images are available": {images: az.Images{minimal("ubuntu-26_04-lts", "pro-minimal", "26.04.202607220")}, wantErr: true},
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
				minimal("ubuntu-26_10-daily", "pro-minimal", "26.10.202607270"),
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
