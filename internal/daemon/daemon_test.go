package daemon_test

import (
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/daemon"
	"google.golang.org/grpc"
)

func TestServerStartStop(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Count the number of grpc call
	grpcRegister := &grpcServiceRegister{}

	s, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"))
	require.NoError(t, err, "New should return the daemon handler")

	go func() {
		// make sure Serve() is called. Even std golang grpc has this timeout in tests
		time.Sleep(time.Millisecond * 10)
		s.Quit()
	}()

	err = s.Listen()
	require.NoError(t, err, "Listen should return no error when stopped normally")

	require.Equal(t, 1, len(grpcRegister.daemonsCalled), "GRPC registerer has been called once")
	require.Equal(t, s, grpcRegister.daemonsCalled[0], "GRPC registerer has the built in daemon as argument")
}

func TestServerStopBeforeServe(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	grpcRegister := &grpcServiceRegister{}

	s, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"))
	require.NoError(t, err, "New should return the daemon handler")

	s.Quit()

	require.Equal(t, 1, len(grpcRegister.daemonsCalled), "GRPC registerer has been called during creation")
}

func TestServerChangeSocket(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	grpcRegister := &grpcServiceRegister{}

	s, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"))
	require.NoError(t, err, "New should return the daemon handler")

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err = s.Listen()
		wg.Done()
	}()

	// make sure Serve() is called. Even std golang grpc has this timeout in tests
	time.Sleep(time.Millisecond * 10)

	require.Equal(t, 1, len(grpcRegister.daemonsCalled), "GRPC registerer has been called once")
	require.Equal(t, s, grpcRegister.daemonsCalled[0], "GRPC registerer has the built in daemon as argument")

	s.UseSocket(filepath.Join(dir, "test2.sock"))
	time.Sleep(time.Millisecond * 10)

	require.Equal(t, 2, len(grpcRegister.daemonsCalled), "a new GRPC registerer has been requested")
	require.Equal(t, s, grpcRegister.daemonsCalled[1], "GRPC registerer has the built in daemon as argument")

	s.Quit()

	wg.Wait()
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
			grpcRegister := &grpcServiceRegister{}

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

			s, err := daemon.New(grpcRegister.registerGRPCServer, "/tmp/this/is/ignored", daemon.WithSystemdActivationListener(f))
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
			require.Equal(t, 1, len(grpcRegister.daemonsCalled), "GRPC registerer has been called during creation")

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
			grpcRegister := &grpcServiceRegister{}

			l, err := net.Listen("unix", filepath.Join(dir, "socket"))
			require.NoErrorf(t, err, "setup failed: couldn't create unix socket: %v", err)
			defer l.Close()

			s, err := daemon.New(grpcRegister.registerGRPCServer, "/tmp/this/is/ignored",
				daemon.WithSystemdActivationListener(func() ([]net.Listener, error) { return []net.Listener{l}, nil }),
				daemon.WithSystemdSdNotifier(func(unsetEnvironment bool, state string) (bool, error) {
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

	grpcRegister := &grpcServiceRegister{}

	_, err := daemon.New(grpcRegister.registerGRPCServer, "foo", daemon.FailingOption())
	require.NotNil(t, err, "Expected New to fail as an option failed")
}

func TestServerCannotCreateSocket(t *testing.T) {
	t.Parallel()

	grpcRegister := &grpcServiceRegister{}

	_, err := daemon.New(grpcRegister.registerGRPCServer, "/path/does/not/exist/daemon_test.sock")
	require.NotNil(t, err, "Expected New to fail as can't create socket")
}

type grpcServiceRegister struct {
	daemonsCalled []*daemon.Daemon
}

func (r *grpcServiceRegister) registerGRPCServer(d *daemon.Daemon) *grpc.Server {
	r.daemonsCalled = append(r.daemonsCalled, d)
	return grpc.NewServer()
}

func TestMain(m *testing.M) {
	debug := flag.Bool("verbose", false, "Print debug log level information within the test")
	flag.Parse()
	if *debug {
		logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	}

	os.Exit(m.Run())
}
