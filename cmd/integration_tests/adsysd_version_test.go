package adsys_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
)

func TestAdsysdVersion(t *testing.T) {
	d := daemon.New()
	changeAppArgs(t, d, "", "version")

	// capture stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn’t fail")
	orig := os.Stdout
	os.Stdout = w

	err = d.Run()

	// restore and collect
	os.Stdout = orig
	w.Close()
	var out bytes.Buffer
	_, errCopy := io.Copy(&out, r)
	require.NoError(t, errCopy, "Couldn’t copy stdout to buffer")

	require.NoError(t, err, "daemon should't exit in error")

	// Daemon version is printed
	assert.True(t, strings.HasPrefix(out.String(), "adsysd\t"), "Print daemon name")
	version := strings.TrimSpace(strings.TrimPrefix(out.String(), "adsysd\t"))
	assert.NotEmpty(t, version, "Version is printed")
}
