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

	testGoCoverage := TrackTestCoverage(t)
	if testGoCoverage == "" {
		return false
	}

	var testXMLCoverage string
	if generateXMLCoverage {
		testXMLCoverage = TrackTestCoverage(t, WithCoverageFormat(xmlCoverage))
	}

	// Check we have an executable "python3-coverage" in PATH for coverage request
	_, err := exec.LookPath(coverageCmd)
	require.NoErrorf(t, err, "Setup: coverage requested and no %s executable found in $PATH for python code", coverageCmd)

	pythonCoverageFile := testGoCoverage + ".pythoncode.coverage"
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

		// Convert to text format in a subdirectory named after the python coverage file.
		coverDir := pythonCoverageFile + ".annotated"
		// #nosec G204 - we have a const for coverageCmd
		out, err := exec.Command(coverageCmd, "annotate", "-d", coverDir, "--include", tracedFile).CombinedOutput()
		require.NoErrorf(t, err, "Teardown: can’t combine python coverage: %s", out)

		// Generate XML report if supported
		if testXMLCoverage != "" {
			// #nosec G204 - we have a const for coverageCmd
			out, err = exec.Command(coverageCmd, "xml", "-o", testXMLCoverage, "--include", tracedFile).CombinedOutput()
			require.NoErrorf(t, err, "Teardown: can’t convert python coverage to XML: %s", out)
		}

		// Convert to golang compatible cover format
		// The file will be transform with char_hexadecimal_filename_ext,cover if there is any / in the name.
		// Matching it with global by filename.
		endCoverFileName := strings.ReplaceAll(filepath.Base(tracedFile), ".", "_") + ",cover"
		founds, err := filepath.Glob(filepath.Clean(filepath.Join(coverDir, "*"+endCoverFileName)))
		require.NoError(t, err, "Teardown: glob pattern should be correct")
		if len(founds) != 1 {
			t.Fatalf("We should have one matching cover profile for python matching our pattern, got: %d", len(founds))
		}
		inF, err := os.Open(founds[0])
		require.NoErrorf(t, err, "Teardown: failed opening python cover file: %s", err)
		defer func() { assert.NoError(t, inF.Close(), "Teardown: can’t close python cover file") }()

		outF, err := os.Create(testGoCoverage)
		require.NoErrorf(t, err, "Teardown: failed opening output golang compatible cover file: %s", err)
		defer func() { assert.NoError(t, outF.Close(), "Teardown: can’t close golang compatible cover file") }()

		// search for go.mod to file fqdnFile
		fqdnFile := fqdnToPath(t, include)
		var lineNum int
		scanner := bufio.NewScanner(inF)
		for scanner.Scan() {
			lineNum++
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

			writeGoCoverageLine(t, outF, fqdnFile, lineNum, len(txt), covered)
		}

		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
	})

	return true
}
