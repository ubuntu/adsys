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
	goCoverProfile   string
	coveragesToMerge []string
	onceCovFile      sync.Once
)

// AddCoverageFile append cov to the list of file to merge when calling MergeCoverages.
func AddCoverageFile(cov string) {
	onceCovFile.Do(func() {
		goCoverProfile = testCoverageFile()
	})
	coveragesToMerge = append(coveragesToMerge, cov)
}

// MergeCoverages append all coverage files marked for merging to main Go Cover Profile.
func MergeCoverages() {
	for _, cov := range coveragesToMerge {
		if err := appendToFile(cov, goCoverProfile); err != nil {
			log.Fatalf("can’t inject coverage to golang one: %v", err)
		}
	}
}

// testCoverageFile returns the coverprofile file relative path.
// It returns nothing if coverage is not enabled.
func testCoverageFile() string {
	for _, arg := range os.Args {
		if !strings.HasPrefix(arg, "-test.coverprofile=") {
			continue
		}
		return strings.TrimPrefix(arg, "-test.coverprofile=")
	}
	return ""
}

// appendToFile appends src to the dst coverprofile file at the end.
func appendToFile(src, dst string) error {
	f, err := os.Open(filepath.Clean(src))
	if err != nil {
		return fmt.Errorf("can't open python coverage file named: %w", err)
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
