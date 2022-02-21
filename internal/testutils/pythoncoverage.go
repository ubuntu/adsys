package testutils

import (
	"bufio"
	// blank embed import for python3-mock.in.
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const coverageCmd = "python3-coverage"

//go:embed python3-mock.in
var python3Mock string

// PythonCoverageToGoFormat allow tracking python include file and convert them to the global go coverage profile
// commandOnStdin replace python3 binary to include with -c.
func PythonCoverageToGoFormat(t *testing.T, include string, commandOnStdin bool) (coverageOn bool) {
	t.Helper()

	goCoverProfile := testCoverageFile()
	if goCoverProfile == "" {
		return false
	}

	// Check we have an executable "python3-coverage" in PATH for coverage request
	_, err := exec.LookPath(coverageCmd)
	require.NoErrorf(t, err, "Setup: coverage requested and no %s executable found in $PATH for python code", coverageCmd)

	coverDir := filepath.Dir(goCoverProfile)
	pythonCoverageFile := filepath.Join(coverDir, "pythoncode.coverage")
	err = os.Setenv("COVERAGE_FILE", pythonCoverageFile)
	require.NoError(t, err, "Setup: can’t set python coverage")

	// Create temporary directory and set PATH
	var origPath string
	tempdir, err := os.MkdirTemp("", "cover-python-mocks")
	require.NoError(t, err, "Setup: create temporary directory for covered python mocks")
	origPath = os.Getenv("PATH")
	err = os.Setenv("PATH", fmt.Sprintf("%s:%s", tempdir, origPath))
	require.NoError(t, err, "Setup: can’t prefix covered python mocks to PATH")

	tracedFile := include

	var mockedFile string
	var d []byte
	if commandOnStdin {
		mockedFile = "python3"
		tracedFile = filepath.Join(tempdir, filepath.Base(include))
		d = []byte(strings.ReplaceAll(python3Mock, "#SCRIPTFILE#", tracedFile))
	} else {
		// Create shell starting python module with python3-coverage
		realBinaryPath, err := filepath.Abs(include)
		require.NoError(t, err, "Setup: can’t resolve real binary path")
		mockedFile = filepath.Base(include)
		d = []byte(fmt.Sprintf(`#!/bin/sh
exec python3-coverage run -a %s $@
`, realBinaryPath))
	}
	// #nosec G306. We want this asset to be executable.
	err = os.WriteFile(filepath.Join(tempdir, mockedFile), d, 0700)
	require.NoError(t, err, "Setup: can’t create prefixed covered python mock")

	t.Cleanup(func() {
		defer func() {
			err = os.Unsetenv("COVERAGE_FILE")
			require.NoError(t, err, "Teardown: can’t restore coverage file env variable")

			// Restore mocks and env variables
			err = os.RemoveAll(tempdir)
			require.NoError(t, err, "Teardown: can’t remove temporary directory for covered python mocks")
			err = os.Setenv("PATH", origPath)
			require.NoError(t, err, "Teardown: can’t restore original PATH")
		}()

		// Only report python coverage if file was created
		if _, err := os.Stat(pythonCoverageFile); err != nil {
			return
		}

		// Convert to text format
		// #nosec G204 - we have a const for coverageCmd
		out, err := exec.Command(coverageCmd, "annotate", "-d", coverDir, "--include", tracedFile).CombinedOutput()
		require.NoErrorf(t, err, "Teardown: can’t combine python coverage: %v", string(out))

		// Convert to golang compatible cover format
		// search for go.mod to file fqdnFile
		fqdnFile := fqdnToPath(t, include)

		coverDir := filepath.Dir(goCoverProfile)

		inF, err := os.Open(filepath.Clean(filepath.Join(coverDir, strings.ReplaceAll(tracedFile, "/", "_")+",cover")))
		require.NoErrorf(t, err, "Teardown: failed opening python cover file: %s", err)
		defer func() { assert.NoError(t, inF.Close(), "Teardown: can’t close python cover file") }()

		golangInclude := filepath.Join(coverDir, t.Name()+".gocover")
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
		AddCoverageFile(golangInclude)
	})

	return true
}

// fqdnToPath allows to return the fqdn path for this file relative to go.mod.
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
