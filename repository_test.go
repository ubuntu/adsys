package adsys_test

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// TestTrackedFilesCanBePackedInModuleZip ensures that every tracked file has
// a path the Go module zip format accepts, so that
// "go install github.com/ubuntu/adsys/cmd/...@latest" keeps working.
func TestTrackedFilesCanBePackedInModuleZip(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available on this system")
	}

	// #nosec G204: arguments are controlled by the test.
	out, err := exec.Command("git", "ls-files", "-z").Output()
	require.NoError(t, err, "Setup: can't list the tracked files")

	var invalid []string
	for _, path := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		if err := checkModuleZipPath(path); err != nil {
			invalid = append(invalid, fmt.Sprintf("%s: %v", path, err))
		}
	}
	require.Empty(t, invalid, "Every tracked file should have a path accepted in a module zip")
}

// checkModuleZipPath mirrors the file path rules of golang.org/x/mod/module.CheckFilePath,
// which "go mod download" and the proxies enforce when they build a module zip.
func checkModuleZipPath(path string) error {
	for _, elem := range strings.Split(path, "/") {
		if elem == "" {
			return errors.New("empty path element")
		}
		if strings.HasSuffix(elem, ".") {
			return errors.New("path element ends with a dot")
		}
		for _, r := range elem {
			if !fileNameOK(r) {
				return fmt.Errorf("invalid character %q", r)
			}
		}

		// Windows reserved names and 8.3 short names are refused whatever the extension.
		short, _, _ := strings.Cut(elem, ".")
		if windowsReservedNames[strings.ToUpper(short)] {
			return fmt.Errorf("%q is a reserved Windows name", short)
		}
		if tilde := strings.LastIndex(short, "~"); tilde >= 0 && tilde < len(short)-1 {
			if _, err := fmt.Sscanf(short[tilde+1:], "%d", new(int)); err == nil && strings.Trim(short[tilde+1:], "0123456789") == "" {
				return fmt.Errorf("%q looks like a Windows short name", short)
			}
		}
	}
	return nil
}

var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// fileNameOK reports whether r can appear in a module zip path element.
// ASCII letters and digits are accepted along with a restricted set of
// punctuation and the space; shell special characters such as the quotes
// are refused, as are non-letter characters outside ASCII.
func fileNameOK(r rune) bool {
	if r < utf8.RuneSelf {
		const allowed = "!#$%&()+,-.=@[]^_{}~ "
		if '0' <= r && r <= '9' || 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z' {
			return true
		}
		return strings.ContainsRune(allowed, r)
	}
	return unicode.IsLetter(r)
}
