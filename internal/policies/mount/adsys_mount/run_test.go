// Package adsysmount_test runs rust tests from a go test global command
package adsysmount_test

import (
	"os"
	"os/exec"
	"testing"

	"github.com/ubuntu/adsys/internal/testutils"
)

func TestRust(t *testing.T) {
	t.Parallel()

	// properly inform Go about which files to use for cache by reading input files.
	testutils.MarkRustFilesForTestCache(t)

	cmd := exec.Command("cargo", "test")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fail()
	}
}

func TestMain(m *testing.M) {
	canRun, withCoverage := testutils.CanRunRustTests()
	if !canRun {
		os.Exit(1)
	}

	_ = withCoverage

	m.Run()
}
