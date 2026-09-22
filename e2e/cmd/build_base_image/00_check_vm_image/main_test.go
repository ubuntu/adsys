package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/e2e/internal/az"
)

func TestShouldRebuild(t *testing.T) {
	const (
		stable = "Canonical:ubuntu-24_04-lts:minimal:24.04.202609110"
		older  = "Canonical:ubuntu-24_04-lts:minimal:24.04.202609100"
		daily  = "Canonical:ubuntu-24_04-lts-daily:minimal:24.04.202609120"
	)
	tests := map[string]struct {
		customVersion string
		source        string
		candidate     string
		want          bool
	}{
		"Same source does not rebuild": {
			customVersion: "1.202609110.0", source: stable, candidate: stable,
		},
		"An older build of the same SKU does not replace a newer build": {
			customVersion: "1.202609110.0", source: stable, candidate: older,
		},
		"A newer source updates a version with a higher minor number": {
			customVersion: "1.202609120.1", source: older, candidate: stable, want: true,
		},
		"An older non-Pro build can replace a Pro source": {
			customVersion: "1.202609110.0",
			source:        "Canonical:ubuntu-24_04-lts:ubuntu-pro-minimal:24.04.202609110",
			candidate:     older, want: true,
		},
		"An existing stable template beats a newer daily build": {
			customVersion: "2.202609110.0", source: stable, candidate: daily,
		},
		"An untagged stable template also beats a daily build": {
			customVersion: "1.202609110.0", candidate: daily,
		},
		"A stable release replaces a daily source even after a forced rebuild": {
			customVersion: "1.202609120.1", source: daily, candidate: stable, want: true,
		},
		"An untagged template is rebuilt once a stable source is available": {
			customVersion: "1.202609110.0", candidate: stable, want: true,
		},
		"A floating source tag is treated as unknown": {
			customVersion: "1.202609110.0",
			source:        "Canonical:ubuntu-24_04-lts:minimal:latest",
			candidate:     stable, want: true,
		},
		"Daily builds can start a new series": {
			candidate: daily, want: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			custom := az.ImageVersion{Version: tc.customVersion}
			if tc.source != "" {
				custom.Tags = map[string]string{az.SourceURNTag: tc.source}
			}
			require.Equal(t, tc.want, shouldRebuild(custom, az.ParseMarketplaceURN(tc.candidate)))
		})
	}
}
