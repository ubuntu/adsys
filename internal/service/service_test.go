package service_test

import (
	"errors"
	"net"
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

func TestServerSocketActivation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sockets      []string
		listenerFail bool

		wantErr bool
	}{
		"success with one socket": {sockets: []string{"sock1"}},

		"fails when Listeners() fails": {listenerFail: true, wantErr: true},
		"fails with many sockets":      {sockets: []string{"socket1", "socket2"}, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tc
			t.Parallel()

			dir := t.TempDir()

			var listeners []net.Listener
			for _, socket := range tc.sockets {
				l, err := net.Listen("unix", filepath.Join(dir, socket))
				require.NoErrorf(t, err, "setup failed: couldn't create unix socket: %v", err)
				defer l.Close()
				listeners = append(listeners, l)
			}

			var f func() ([]net.Listener, error)
			if tc.listenerFail {
				f = func() ([]net.Listener, error) {
					return nil, errors.New("systemd activation error")
				}
			} else {
				f = func() ([]net.Listener, error) {
					return listeners, nil
				}
			}

			s, err := service.New("/tmp/this/is/ignored", service.WithSystemdActivationListener(f))
			if tc.wantErr {
				require.NotNil(t, err, "New should return an error")
				return
			} else if !tc.wantErr {
				require.NoError(t, err, "New should return no error")
			}

			go func() {
				time.Sleep(10 * time.Millisecond)
				s.Quit()
			}()
			err = s.Listen()
			require.NoError(t, err, "Listen should return no error")
		})
	}
}

func TestServerSdNotifier(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sent         bool
		notifierFail bool

		wantErr bool
	}{
		"sends signal":                        {sent: true},
		"doesn't fail when not under systemd": {sent: false},

		"fails when notifier fails": {notifierFail: true, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tc
			t.Parallel()

			dir := t.TempDir()

			l, err := net.Listen("unix", filepath.Join(dir, "socket"))
			require.NoErrorf(t, err, "setup failed: couldn't create unix socket: %v", err)
			defer l.Close()

			s, err := service.New("/tmp/this/is/ignored",
				service.WithSystemdActivationListener(func() ([]net.Listener, error) { return []net.Listener{l}, nil }),
				service.WithSystemdSdNotifier(func(unsetEnvironment bool, state string) (bool, error) {
					if tc.notifierFail {
						return false, errors.New("systemd notifier error")
					}
					return tc.sent, nil
				}))
			require.NoError(t, err, "New should return no error")

			go func() {
				time.Sleep(10 * time.Millisecond)
				s.Quit()
			}()

			err = s.Listen()
			if tc.wantErr {
				require.NotNil(t, err, "Listen should return an error")
				return
			} else if !tc.wantErr {
				require.NoError(t, err, "Listen should return no error")
			}
		})
	}
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
