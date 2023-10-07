// Package scripts includes script files used by the e2e test suite.
package scripts

import (
	"fmt"
	"path/filepath"
	"runtime"
)

// Dir returns the directory of the current file.
func Dir() (string, error) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to get current file path")
	}
	return filepath.Dir(currentFile), nil
}

// RootDir returns the root directory of the project.
func RootDir() (string, error) {
	currentDir, err := Dir()
	if err != nil {
		return "", err
	}

	return filepath.Dir(filepath.Dir(currentDir)), nil
}
