package testutils

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var update bool

// LoadWithUpdateFromGolden loads the element from a plaintext golden file in testdata/golden.
// It will update the file if the update flag is used prior to deserializing it.
func LoadWithUpdateFromGolden(t *testing.T, data string) string {
	t.Helper()

	goldPath := filepath.Join("testdata", "golden", NormalizeGoldenName(t, t.Name()))

	if update {
		t.Logf("updating golden file %s", goldPath)
		err := os.MkdirAll(filepath.Dir(goldPath), 0750)
		require.NoError(t, err, "Cannot create directory for updating golden files")
		err = os.WriteFile(goldPath, []byte(data), 0600)
		require.NoError(t, err, "Cannot write golden file")
	}

	want, err := os.ReadFile(goldPath)
	require.NoError(t, err, "Cannot load golden file")

	return string(want)
}

// NormalizeGoldenName returns the name of the golden file with illegal Windows
// characters replaced or removed.
func NormalizeGoldenName(t *testing.T, name string) string {
	t.Helper()

	name = strings.ReplaceAll(name, `\`, "_")
	name = strings.ReplaceAll(name, ":", "")
	return name
}

// InstallUpdateFlag install an update flag referenced in this package.
// The flags need to be parsed before running the tests.
func InstallUpdateFlag() {
	flag.BoolVar(&update, "update", false, "update golden files")
}
