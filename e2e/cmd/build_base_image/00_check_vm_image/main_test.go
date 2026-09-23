package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/e2e/internal/az"
)

func TestSourceIdentityChanged(t *testing.T) {
	tests := map[string]struct {
		custom az.ImageVersion
		latest az.Image

		want bool
	}{
		"Matches the recorded source image": {
			custom: az.ImageVersion{Tags: map[string]string{az.SourceURNTag: "Canonical:ubuntu-24_04-lts:minimal:24.04.202609100"}},
			latest: az.Image{URN: "Canonical:ubuntu-24_04-lts:minimal:24.04.202609100"},
		},
		"Detects a change of source image": {
			custom: az.ImageVersion{Tags: map[string]string{az.SourceURNTag: "Canonical:ubuntu-24_04-lts:ubuntu-pro-minimal:24.04.202609110"}},
			latest: az.Image{URN: "Canonical:ubuntu-24_04-lts:minimal:24.04.202609100"},
			want:   true,
		},
		"Rebuilds versions without recorded source identity": {
			custom: az.ImageVersion{},
			latest: az.Image{URN: "Canonical:ubuntu-24_04-lts:minimal:24.04.202609100"},
			want:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, sourceIdentityChanged(tc.custom, tc.latest), "Unexpected source identity comparison result")
		})
	}
}
