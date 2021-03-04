package client

import (
	"os"
	"testing"

	"github.com/fatih/color"
	"github.com/stretchr/testify/require"
)

func TestColorizePolicies(t *testing.T) {
	t.Parallel()

	policies := `Policies from machine configuration:
* GPOName1 ({GPOId1})
** dconf:
*** path/to/key1: ValueOfKey1
*** path/to/key2: ValueOfKey2
** scripts:
***+ path/to/key3
* GPOName2 ({GPOId2})
** dconf:
*** path/to/keyGpo2-1: ValueOfKeyGpo2-1
Policies from user configuration:
* GPOName3 ({GPOId2})
** dconf:
***- path/to/key1: ValueOfKey1\nOn\nMultilines
***- path/to/key2: ValueOfKey2
** scripts:
***-+ path/to/key3
`

	// force color despite running tests without a tty
	color.NoColor = false

	got, err := colorizePolicies(policies)
	require.NoError(t, err, "colorizePolicies should not return an error")

	want, err := os.ReadFile("testdata/golden/colorize.golden")
	require.NoError(t, err, "Setup: failed to read colorized golden file")

	require.Equal(t, string(want), got, "colorizePolicies returned expected formatted output")
}
