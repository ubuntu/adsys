package az_test

import (
	"os"
	"path/filepath"
	"runtime"
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
		"Picks the newest numeric build across different lengths": {
			images: az.Images{
				minimal("ubuntu-26_04-lts", "minimal", "26.04.20260715"),
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

		"Error when no daily image is available": {images: az.Images{minimal("ubuntu-26_10", "minimal", "26.10.202607260")}, wantErr: true},
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

func TestGalleryImageVersionSelection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell")
	}
	bin := t.TempDir()
	// #nosec G306 -- The private CLI fixture must be executable.
	require.NoError(t, os.WriteFile(filepath.Join(bin, "az"), []byte(`#!/bin/sh
[ "$1 $2 $3" = "sig image-version list" ] || exit 1
printf '%s\n' "$ADSYS_TEST_GALLERY"
`), 0700))
	t.Setenv("PATH", bin)
	const excluded = `{"name":"1.202609110.11","publishingProfile":{"excludeFromLatest":true}}`
	t.Setenv("ADSYS_TEST_GALLERY", `[
		{"name":"1.202609110.10","tags":{"sourceURN":"Canonical:ubuntu-24_04-lts:minimal:24.04.202609100"}},
		`+excluded+`,
		{"name":"1.202609110.2"}
	]`)

	deployable, err := az.LatestDeployableImage(t.Context(), "ubuntu-desktop-noble")
	require.NoError(t, err)
	require.Equal(t, "1.202609110.10", deployable.Version)
	require.Equal(t, "Canonical:ubuntu-24_04-lts:minimal:24.04.202609100", deployable.Tags[az.SourceURNTag])

	highest, err := az.LatestImageVersion(t.Context(), "ubuntu-desktop-noble")
	require.NoError(t, err)
	require.Equal(t, "1.202609110.11", highest)

	t.Setenv("ADSYS_TEST_GALLERY", "["+excluded+"]")
	deployable, err = az.LatestDeployableImage(t.Context(), "ubuntu-desktop-noble")
	require.NoError(t, err)
	require.Empty(t, deployable.Version, "a gallery with only excluded versions cannot provision clients")
}
