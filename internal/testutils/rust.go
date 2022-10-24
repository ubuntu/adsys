package testutils

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// MarkRustFilesForTestCache marks all rust files and related content to be in the Go test caching infra.
func MarkRustFilesForTestCache(t *testing.T) {
	t.Helper()

	markForTestCache(t, []string{"src", "testdata", "Cargo.toml", "Cargo.lock"})
}

// CanRunRustTests returns if we can run rust tests via cargo on this machine.
// It returns if code coverage is supported.
func CanRunRustTests() (canRun, withCoverage bool) {
	d, err := exec.Command("cargo", "--version").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't run Rust tests, cargo can't be executed: %v\n", err)
		return false, false
	}

	// TODO: detect nightly for code coverage
	fmt.Println(string(d))

	return true, false
}
