package unixsocket_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/grpc/unixsocket"
	"golang.org/x/net/context"
)

func TestSocket(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	sock := filepath.Join(d, "test.socket")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err, "setup: creating socket failed")
	defer lis.Close()

	dial := unixsocket.ContextDialer()
	conn, err := dial(context.Background(), sock)
	require.NoError(t, err, "Dialing to unix returned an error when expecting none")
	defer conn.Close()
}

func TestNoSocketFile(t *testing.T) {
	t.Parallel()

	d := t.TempDir()

	dial := unixsocket.ContextDialer()
	_, err := dial(context.Background(), filepath.Join(d, "doesntexist"))
	require.NotNil(t, err, "dialing an unexisting socket path should fail")
}

func TestInvalidSocketFile(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	f, err := os.CreateTemp(d, "simplefile")
	require.NoError(t, err, "setup; creating temporary file failed")

	dial := unixsocket.ContextDialer()
	_, err = dial(context.Background(), f.Name())
	require.NotNil(t, err, "dialing a non socket file should fail")
}
