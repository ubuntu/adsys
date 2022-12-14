// Package adsysmount_test runs rust tests from a go test global command
package adsysmount_test

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestRust(t *testing.T) {
	if os.Getenv("ADSYS_SKIP_RUST_TESTS_IN_GOLANG") != "" {
		fmt.Println("Rust tests skipped as requested")
		return
	}
	t.Parallel()

	d, err := os.Getwd()
	require.NoError(t, err, "Setup: Failed when fetching current dir.")

	// properly inform Go about which files to use for cache by reading input files.
	testutils.MarkRustFilesForTestCache(t, d)
	env, target := testutils.TrackRustCoverage(t, ".")

	// nolint:gosec // G204 we define our target ourself
	cmd := exec.Command("cargo", "test", "--target-dir", target)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fail()
	}
}

func TestMain(m *testing.M) {
	if err := testutils.CanRunRustTests(testutils.WantCoverage()); err != nil {
		fmt.Fprintf(os.Stderr, "Can't run Rust tests: %v\n", err)
		os.Exit(1)
	}

	m.Run()
	testutils.MergeCoverages()
}
