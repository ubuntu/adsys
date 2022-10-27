package testutils

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	goMainCoverProfile     string
	goMainCoverProfileOnce sync.Once

	coveragesToMerge   []string
	coveragesToMergeMu sync.Mutex
)

// TrackTestCoverage starts tracking coverage in a dedicated file based on current test name.
// This file will be merged to the current coverage main file.
// It’s up to the test use the returned path to file golang-compatible cover format content.
// To collect all coverages, then MergeCoverages() should be called after m.Run().
// If coverage is not enabled, nothing is done.
func TrackTestCoverage(t *testing.T) (testCoverFile string) {
	t.Helper()

	goMainCoverProfileOnce.Do(func() {
		for _, arg := range os.Args {
			if !strings.HasPrefix(arg, "-test.coverprofile=") {
				continue
			}
			goMainCoverProfile = strings.TrimPrefix(arg, "-test.coverprofile=")
		}
	})

	if goMainCoverProfile == "" {
		return ""
	}

	coverAbsPath, err := filepath.Abs(goMainCoverProfile)
	require.NoError(t, err, "Setup: can't transform go cover profile to absolute path")

	testCoverFile = fmt.Sprintf("%s.%s", coverAbsPath, strings.ReplaceAll(t.Name(), "/", "_"))
	coveragesToMergeMu.Lock()
	defer coveragesToMergeMu.Unlock()
	coveragesToMerge = append(coveragesToMerge, testCoverFile)

	return testCoverFile
}

// MergeCoverages append all coverage files marked for merging to main Go Cover Profile.
// This has to be called after m.Run() in TestMain so that the main go cover profile is created.
// This has no action if profiling is not enabled.
func MergeCoverages() {
	coveragesToMergeMu.Lock()
	defer coveragesToMergeMu.Unlock()
	for _, cov := range coveragesToMerge {
		if err := appendToFile(cov, goMainCoverProfile); err != nil {
			log.Fatalf("Teardown: can’t inject coverage into the golang one: %v", err)
		}
	}
	coveragesToMerge = nil
}

// WantCoverage returns true if coverage was requested in test.
func WantCoverage() bool {
	for _, arg := range os.Args {
		if !strings.HasPrefix(arg, "-test.coverprofile=") {
			continue
		}
		return true
	}
	return false
}

// appendToFile appends src to the dst coverprofile file at the end.
func appendToFile(src, dst string) error {
	f, err := os.Open(filepath.Clean(src))
	if err != nil {
		return fmt.Errorf("can't open coverage file named: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("can't close %v", err)
		}
	}()

	d, err := os.OpenFile(dst, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("can't open golang cover profile file: %w", err)
	}
	defer func() {
		if err := d.Close(); err != nil {
			log.Fatalf("can't close %v", err)
		}
	}()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "mode: ") {
			continue
		}
		if _, err := d.Write([]byte(scanner.Text() + "\n")); err != nil {
			return fmt.Errorf("can't write to golang cover profile file: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error while scanning golang cover profile file: %w", err)
	}
	return nil
}

// fqdnToPath allows to return the fqdn path for this file relative to go.mod.
func fqdnToPath(t *testing.T, path string) string {
	t.Helper()

	srcPath, err := filepath.Abs(path)
	require.NoError(t, err, "Setup: can't calculate absolute path")

	d := srcPath
	for d != "/" {
		f, err := os.Open(filepath.Clean(filepath.Join(d, "go.mod")))
		if err != nil {
			d = filepath.Dir(d)
			continue
		}
		defer func() { assert.NoError(t, f.Close(), "Setup: can’t close go.mod") }()

		r := bufio.NewReader(f)
		l, err := r.ReadString('\n')
		require.NoError(t, err, "can't read go.mod first line")
		if !strings.HasPrefix(l, "module ") {
			t.Fatal(`Setup: failed to find "module" line in go.mod`)
		}

		prefix := strings.TrimSpace(strings.TrimPrefix(l, "module "))
		relpath := strings.TrimPrefix(srcPath, d)
		return filepath.Join(prefix, relpath)
	}

	t.Fatal("failed to find go.mod")
	return ""
}

// writeGoCoverageLine writes given line in go coverage format to w.
func writeGoCoverageLine(t *testing.T, w io.Writer, file string, lineNum, lineLength int, covered string) {
	t.Helper()

	_, err := w.Write([]byte(fmt.Sprintf("%s:%d.1,%d.%d 1 %s\n", file, lineNum, lineNum, lineLength, covered)))
	require.NoErrorf(t, err, "Teardown: can't write a write to golang compatible cover file : %v", err)
}
