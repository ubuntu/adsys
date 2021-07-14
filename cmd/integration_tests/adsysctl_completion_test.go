package adsys_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompletion(t *testing.T) {
	conf := createConf(t, "")
	defer runDaemon(t, conf)()

	out, err := runClient(t, conf, "completion", "bash")
	require.NoError(t, err, "client should exit with no error")
	require.NotEmpty(t, out, "output something for shell completion")
}
