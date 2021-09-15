package testutils

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
