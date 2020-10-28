package service_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/service"
)

func TestServerStartStop(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	s, err := service.New(filepath.Join(dir, "test.sock"))
	require.NoError(t, err, "New should return the service handler")

	go func() {
		// make sure Serve() is called. Even std golang grpc has this timeout in tests
		time.Sleep(time.Millisecond * 10)
		s.Quit()
	}()

	err = s.Listen()
	require.NoError(t, err, "Listen should return no error when stopped normally")
}

func TestServerStopBeforeServe(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	s, err := service.New(filepath.Join(dir, "test.sock"))
	require.NoError(t, err, "New should return the service handler")

	s.Quit()
}

func TestServerChangeSocket(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	s, err := service.New(filepath.Join(dir, "test.sock"))
	require.NoError(t, err, "New should return the service handler")

	go func() {
		// make sure Serve() is called. Even std golang grpc has this timeout in tests
		time.Sleep(time.Millisecond * 10)
		s.UseSocket(filepath.Join(dir, "test2.sock"))
		time.Sleep(time.Millisecond * 10)
		s.Quit()
	}()

	err = s.Listen()
	require.NoError(t, err, "Listen should return no error when stopped after changing socket")
}

func TestServerFailingOption(t *testing.T) {
	t.Parallel()

	_, err := service.New("foo", service.FailingOption())
	require.NotNil(t, err, "Expected New to fail as an option failed")
}

func TestServerCannotCreateSocket(t *testing.T) {
	t.Parallel()

	_, err := service.New("/path/does/not/exist/daemon_test.sock")
	require.NotNil(t, err, "Expected New to fail as can't create socket")
}
