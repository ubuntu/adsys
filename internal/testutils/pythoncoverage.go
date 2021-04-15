package testutils

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const coverageCmd = "python3-coverage"

var (
	goCoverProfile string
	tempdir        string
	once           sync.Once
	mergeCoverage  []func() error
)

// CoverageToGoFormat allow tracking include file to the global go coverage profile
func CoverageToGoFormat(t *testing.T, include string) (coverageOn bool) {
	t.Helper()

	for _, arg := range os.Args {
		if !strings.HasPrefix(arg, "-test.coverprofile=") {
			continue
		}
		goCoverProfile = strings.TrimPrefix(arg, "-test.coverprofile=")
	}
	if goCoverProfile == "" {
		return false
	}

	// Check we have an executable "python3-coverage" in PATH for coverage request
	_, err := exec.LookPath(coverageCmd)
	require.NoErrorf(t, err, "Setup: coverage requested and no %s executable found in $PATH for python code", coverageCmd)

	coverDir := filepath.Dir(goCoverProfile)
	err = os.Setenv("COVERAGE_FILE", filepath.Join(coverDir, "pythoncode.coverage"))
	require.NoError(t, err, "Setup: can’t set python coverage")

	// Create temporary directory and set PATH
	var origPath string
	once.Do(func() {
		var err error
		tempdir, err = os.MkdirTemp("", "cover-python-mocks")
		require.NoError(t, err, "Setup: create temporary directory for covered python mocks")
		origPath = os.Getenv("PATH")
		err = os.Setenv("PATH", fmt.Sprintf("%s:%s", tempdir, origPath))
		require.NoError(t, err, "Setup: can’t prefix covered python mocks to PATH")
	})

	// Create shell starting python module with python3-coverage
	realBinaryPath, err := filepath.Abs(include)
	require.NoError(t, err, "Setup: can’t resolve real binary path")
	n := filepath.Base(include)
	d := []byte(fmt.Sprintf(`#!/bin/sh
python3-coverage run -a %s $@
`, realBinaryPath))
	err = os.WriteFile(filepath.Join(tempdir, n), d, 0700)
	require.NoError(t, err, "Setup: can’t create prefixed covered python mock")

	t.Cleanup(func() {
		_, err = os.Stat(filepath.Join(tempdir, n))
		// Restore mocks and env variables
		err = os.RemoveAll(tempdir)
		require.NoError(t, err, "Teardown: can’t remove temporary directory for covered python mocks")
		err = os.Setenv("PATH", origPath)
		require.NoError(t, err, "Teardown: can’t restore original PATH")

		// Convert to text format
		// #nosec G204 - we have a const for coverageCmd
		out, err := exec.Command(coverageCmd, "annotate", "-d", coverDir, "--include", include).CombinedOutput()
		require.NoErrorf(t, err, "Teardown: can’t combine python coverage: %v", string(out))

		err = os.Unsetenv("COVERAGE_FILE")
		require.NoError(t, err, "Teardown: can’t restore coverage file env variable")

		// Convert to golang compatible cover format
		// search for go.mod to file fqdnFile
		fqdnFile := fqdnToPath(t, include)

		coverDir := filepath.Dir(goCoverProfile)

		// transform include to golang compatible format
		//in := filepath.Join(coverDir, include+",cover")
		inF, err := os.Open(filepath.Clean(filepath.Join(coverDir, include+",cover")))
		require.NoErrorf(t, err, "Teardown: failed opening python cover file: %s", err)
		defer func() { assert.NoError(t, inF.Close(), "Teardown: can’t close python cover file") }()

		golangInclude := filepath.Join(coverDir, include+".gocover")
		outF, err := os.Create(golangInclude)
		require.NoErrorf(t, err, "Teardown: failed opening output golang compatible cover file: %s", err)
		defer func() { assert.NoError(t, outF.Close(), "Teardown: can’t close golang compatible cover file") }()

		var line int
		scanner := bufio.NewScanner(inF)
		for scanner.Scan() {
			line++
			txt := scanner.Text()
			if txt == "" {
				continue
			}
			var covered string
			switch txt[0] {
			case '>':
				covered = "1"
			case '!':
				covered = "0"
			default:
				continue
			}

			_, err := outF.Write([]byte(fmt.Sprintf("%s:%d.1,%d.%d 1 %s\n", fqdnFile, line, line, len(txt), covered)))
			require.NoErrorf(t, err, "Teardown: can't write to golang compatible cover file : %s", err)
		}

		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}

		// append to merge that file when tests are done
		mergeCoverage = append(mergeCoverage, func() error { return appendToFile(goCoverProfile, golangInclude) })
	})

	return true
}

func MergePythonCoverage() {
	for _, m := range mergeCoverage {
		if err := m(); err != nil {
			log.Fatalf("can’t inject python coverage to golang one: %v", err)
		}
	}
}

// appendToFile appends toInclude to the coverprofile file at the end
func appendToFile(main, add string) error {
	d, err := os.ReadFile(add)
	if err != nil {
		return fmt.Errorf("can't open python coverage file named: %v", err)
	}

	f, err := os.OpenFile(main, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("can't open golang cover profile file: %v", err)
	}
	if _, err := f.Write(d); err != nil {
		return fmt.Errorf("can't write to golang cover profile file: %v", err)
	}
	return nil
}

// fqdnToPath allows to return the fqdn path for this file relative to go.mod
func fqdnToPath(t *testing.T, path string) string {
	t.Helper()

	srcPath, err := filepath.Abs(path)
	require.NoError(t, err, "can't calculate absolute path")

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
