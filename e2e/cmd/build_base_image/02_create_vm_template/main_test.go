package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/e2e/internal/az"
)

func TestConstructNewVersion(t *testing.T) {
	tests := map[string]struct {
		prevVersion string
		buildNumber string
		dev         bool

		want string
	}{
		"First stable version starts the series": {
			prevVersion: az.NullImageVersion, buildNumber: "202609110",
			want: "1.202609110.0",
		},
		"First development version starts the series": {
			prevVersion: az.NullImageVersion, buildNumber: "202609110", dev: true,
			want: "0.202609110.0",
		},
		"Newer build number resets the patch": {
			prevVersion: "1.202609100.3", buildNumber: "202609110",
			want: "1.202609110.0",
		},
		"Same build number increments the patch": {
			prevVersion: "1.202609110.0", buildNumber: "202609110",
			want: "1.202609110.1",
		},
		"Switching to a stable image starts a new series": {
			prevVersion: "0.202609110.4", buildNumber: "202609100",
			want: "1.202609100.0",
		},

		// Azure serves the highest version of an image definition rather than
		// the one built most recently, so a rebuild that sorts below what is
		// already published is never used. This is what kept noble on the
		// Ubuntu Pro template after it stopped being built from that SKU.
		"Older build number keeps the published minor and increments the patch": {
			prevVersion: "1.202609110.0", buildNumber: "202609100",
			want: "1.202609110.1",
		},
		"Older build number keeps incrementing an already bumped patch": {
			prevVersion: "1.202609110.7", buildNumber: "202609100",
			want: "1.202609110.8",
		},

		// Nothing can be inferred from a version we cannot read, so fall back
		// to the build number rather than guessing at a predecessor.
		"Malformed previous version falls back to the build number": {
			prevVersion: "not.a.version", buildNumber: "202609110",
			want: "1.202609110.0",
		},
		"Truncated previous version falls back to the build number": {
			prevVersion: "1.202609110", buildNumber: "202609110",
			want: "1.202609110.0",
		},
		"Non-numeric build number does not lower the published version": {
			prevVersion: "1.202609110.2", buildNumber: "daily",
			want: "1.202609110.3",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := constructNewVersion(tc.prevVersion, tc.buildNumber, tc.dev)
			require.Equal(t, tc.want, got, "constructNewVersion returned an unexpected version")
		})
	}
}
