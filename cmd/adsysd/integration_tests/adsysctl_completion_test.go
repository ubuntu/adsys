package adsys_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompletion(t *testing.T) {
	conf, quit := runDaemon(t, false)
	defer quit()

	out, err := runClient(t, conf, "completion")
	require.NoError(t, err, "client should exit with no error")
	require.NotEmpty(t, out, "output something for shell completion")
}
