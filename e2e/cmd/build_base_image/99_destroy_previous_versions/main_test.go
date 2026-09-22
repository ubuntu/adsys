package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanupKeepsLatestDeployableVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell")
	}
	bin := t.TempDir()
	deleted := filepath.Join(bin, "deleted")
	// #nosec G306 -- The private CLI fixture must be executable.
	require.NoError(t, os.WriteFile(filepath.Join(bin, "az"), []byte(`#!/bin/sh
case "$1 $2 $3" in
  'sig image-version list')
    printf '%s\n' '[
      {"name":"1.0.10","publishingProfile":{"excludeFromLatest":true}},
      {"name":"1.0.0"},
      {"name":"1.0.9","publishingProfile":{"excludeFromLatest":true}},
      {"name":"1.0.2"},
      {"name":"1.0.11","publishingProfile":{"excludeFromLatest":true}}
    ]'
    ;;
  'sig image-version delete')
    while [ "$#" -gt 1 ] && [ "$1" != --gallery-image-version ]; do shift; done
    [ "$1" = --gallery-image-version ] || exit 1
    printf '%s\n' "$2" >> "$ADSYS_TEST_DELETED"
    ;;
  *) exit 1 ;;
esac
`), 0700))
	t.Setenv("PATH", bin)
	t.Setenv("ADSYS_TEST_DELETED", deleted)
	codename, versionsToKeep = "noble", 2

	require.NoError(t, action(t.Context(), nil))
	got, err := os.ReadFile(deleted)
	require.NoError(t, err)
	require.Equal(t, "1.0.9\n1.0.0\n", string(got))
}
