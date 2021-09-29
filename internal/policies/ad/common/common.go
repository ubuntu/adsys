// Package adcommon includes utilities for packages depending on ad
package adcommon

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
)

// KeyPrefix is the prefix for all our policies in the GPO.
const KeyPrefix = "Software/Policies"

// GetVersionID returns from root a the VERSION_ID field of os-release.
func GetVersionID(root string) (versionID string, err error) {
	defer decorate.OnError(&err, i18n.G("cannot get versionID"))

	releaseFile := filepath.Join(root, "etc/os-release")

	file, err := os.Open(filepath.Clean(releaseFile))
	if err != nil {
		return "", err
	}
	defer decorate.LogFuncOnError(file.Close)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "VERSION_ID=") {
			continue
		}
		versionID = strings.ReplaceAll(strings.TrimPrefix(scanner.Text(), "VERSION_ID="), `"`, "")
		break
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if versionID == "" {
		return "", fmt.Errorf("can't read VERSION_ID from %s", releaseFile)
	}

	return versionID, nil
}
