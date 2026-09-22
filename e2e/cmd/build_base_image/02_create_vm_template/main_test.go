package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/e2e/internal/az"
)

func TestConstructNewVersion(t *testing.T) {
	tests := map[string]struct {
		prevVersion string
		buildNumber string
		daily       bool

		want    string
		wantErr string
	}{
		"First stable version starts the series": {
			buildNumber: "202609110", want: "1.202609110.0",
		},
		"First development version starts the series": {
			buildNumber: "202609110", daily: true, want: "0.202609110.0",
		},
		"Newer build number resets the patch": {
			prevVersion: "1.202609100.3", buildNumber: "202609110", want: "1.202609110.0",
		},
		"Same build number increments the patch": {
			prevVersion: "1.202609110.0", buildNumber: "202609110", want: "1.202609110.1",
		},
		"Switching to a stable image starts a new series": {
			prevVersion: "0.202609110.4", buildNumber: "202609100", want: "1.202609100.0",
		},
		"Older non-Pro build sorts above the old version": {
			prevVersion: "1.202609110.0", buildNumber: "202609100", want: "1.202609110.1",
		},
		"Stable builds preserve a higher manual major": {
			prevVersion: "2.202609110.7", buildNumber: "202609100", want: "2.202609110.8",
		},
		"A forced daily build can replace the current version": {
			prevVersion: "1.202609110.7", buildNumber: "202609100", daily: true, want: "1.202609110.8",
		},
		"Patch rollover increments the minor": {
			prevVersion: "1.202609110.2147483647", buildNumber: "202609100", want: "1.202609111.0",
		},
		"Minor rollover increments the major": {
			prevVersion: "1.2147483647.2147483647", buildNumber: "202609100", want: "2.0.0",
		},
		"Cannot increment the maximum version": {
			prevVersion: "2147483647.2147483647.2147483647", buildNumber: "202609110",
			wantErr: "cannot be incremented",
		},
		"Rejects a truncated gallery version": {
			prevVersion: "1.202609110", buildNumber: "202609110", wantErr: "invalid gallery image version",
		},
		"Rejects a build number outside Azure's range": {
			buildNumber: "2147483648", wantErr: "invalid Marketplace build number",
		},
		"A managed image without a Marketplace version can still be published": {
			prevVersion: "0.0.0", want: "1.0.0",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := constructNewVersion(tc.prevVersion, tc.buildNumber, tc.daily)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestSourceImage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell")
	}
	bin := t.TempDir()
	// #nosec G306 -- The private CLI fixture must be executable.
	require.NoError(t, os.WriteFile(filepath.Join(bin, "az"), []byte(`#!/bin/sh
[ "$1 $2" = "vm show" ] || exit 1
printf '%s\n' "$ADSYS_TEST_IMAGE_REFERENCE"
`), 0700))
	t.Setenv("PATH", bin)

	const (
		prefix = "Canonical:ubuntu-24_04-lts:minimal:"
		exact  = prefix + "24.04.202609100"
	)
	t.Setenv("ADSYS_TEST_IMAGE_REFERENCE", `{
		"publisher":"Canonical","offer":"ubuntu-24_04-lts","sku":"minimal",
		"version":"latest","exactVersion":"24.04.202609100"
	}`)
	for _, requested := range []string{prefix + "latest", "Ubuntu2404"} {
		image, err := sourceImage(t.Context(), "vm-id", requested)
		require.NoError(t, err)
		require.Equal(t, az.ParseMarketplaceURN(exact), image)
	}

	image, err := sourceImage(t.Context(), "vm-id", prefix+"24.04.202609090")
	require.NoError(t, err)
	require.Equal(t, prefix+"24.04.202609090", image.URN)

	t.Setenv("ADSYS_TEST_IMAGE_REFERENCE", `{"id":"/gallery/images/ubuntu/versions/1.0.0"}`)
	image, err = sourceImage(t.Context(), "vm-id", "/gallery/images/ubuntu/versions/1.0.0")
	require.NoError(t, err)
	require.Empty(t, image.URN)
}
