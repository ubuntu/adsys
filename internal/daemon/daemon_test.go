package daemon_test

import (
	"errors"
	"flag"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/daemon"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func TestStartStop(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	var serverQuitCalled int
	serverQuit := func(context.Context) {
		serverQuitCalled++
	}

	// Count the number of grpc call
	grpcRegister := &grpcServiceRegister{}

	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"),
		daemon.WithServerQuit(serverQuit))
	require.NoError(t, err, "New should return the daemon handler")

	go func() {
		// make sure Serve() is called. Even std golang grpc has this timeout in tests
		time.Sleep(time.Millisecond * 10)
		d.Quit(false)
	}()

	err = d.Listen()
	require.NoError(t, err, "Listen should return no error when stopped normally")

	require.Equal(t, 1, len(grpcRegister.daemonsCalled), "GRPC registerer has been called once")
	require.Equal(t, d, grpcRegister.daemonsCalled[0], "GRPC registerer has the built in daemon as argument")

	require.Equal(t, 1, serverQuitCalled, "Server service hooked up Quit has been called once")
}

func TestStopBeforeServe(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	grpcRegister := &grpcServiceRegister{}

	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"))
	require.NoError(t, err, "New should return the daemon handler")

	d.Quit(false)

	require.Equal(t, 1, len(grpcRegister.daemonsCalled), "GRPC registerer has been called during creation")
}

func TestChangeSocket(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	grpcRegister := &grpcServiceRegister{}

	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"))
	require.NoError(t, err, "New should return the daemon handler")

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err = d.Listen()
		wg.Done()
	}()

	// make sure Serve() is called. Even std golang grpc has this timeout in tests
	time.Sleep(time.Millisecond * 10)

	require.Equal(t, 1, len(grpcRegister.daemonsCalled), "GRPC registerer has been called once")
	require.Equal(t, d, grpcRegister.daemonsCalled[0], "GRPC registerer has the built in daemon as argument")

	newSocket := filepath.Join(dir, "test2.sock")
	err = d.UseSocket(newSocket)
	require.NoError(t, err, "UseSocket should return no error")
	time.Sleep(time.Millisecond * 10)

	gotSocket := d.GetSocketAddr()
	require.Equal(t, newSocket, gotSocket, "Socket was changed to expected one")

	d.Quit(false)
	wg.Wait()

	require.NoError(t, err, "Listen should return no error when stopped after changing socket")
	require.Equal(t, 2, len(grpcRegister.daemonsCalled), "a new GRPC registerer has been requested")
	require.Equal(t, d, grpcRegister.daemonsCalled[1], "GRPC registerer has the built in daemon as argument")
}

func TestSocketActivation(t *testing.T) {
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
			var sock string
			for _, socket := range tc.sockets {
				sock = filepath.Join(dir, socket)
				l, err := net.Listen("unix", sock)
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

			d, err := daemon.New(grpcRegister.registerGRPCServer, "/tmp/this/is/ignored", daemon.WithSystemdActivationListener(f))
			if tc.wantErr {
				require.NotNil(t, err, "New should return an error")
				return
			} else if !tc.wantErr {
				require.NoError(t, err, "New should return no error")
			}

			go func() {
				time.Sleep(10 * time.Millisecond)
				d.Quit(false)
			}()
			err = d.Listen()
			require.NoError(t, err, "Listen should return no error")
			require.Equal(t, 1, len(grpcRegister.daemonsCalled), "GRPC registerer has been called during creation")

			require.Equal(t, sock, d.GetSocketAddr(), "Socket is the socket activated value")
		})
	}
}

func TestUseSocketIgnoredWithSocketActivation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	grpcRegister := &grpcServiceRegister{}

	sock := filepath.Join(dir, "socket")
	l, err := net.Listen("unix", sock)
	require.NoErrorf(t, err, "setup failed: couldn't create unix socket: %v", err)
	defer l.Close()

	f := func() ([]net.Listener, error) {
		return []net.Listener{l}, nil
	}

	d, err := daemon.New(grpcRegister.registerGRPCServer, "/tmp/this/is/ignored", daemon.WithSystemdActivationListener(f))
	require.NoError(t, err, "New should return no error")

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err = d.Listen()
		wg.Done()
	}()

	// make sure Serve() is called. Even std golang grpc has this timeout in tests
	time.Sleep(time.Millisecond * 10)
	require.Equal(t, sock, d.GetSocketAddr(), "Socket is the socket activated value")

	require.Equal(t, 1, len(grpcRegister.daemonsCalled), "GRPC registerer has been called once")
	err = d.UseSocket("/tmp/this/is/also/ignored")
	require.NoError(t, err, "UsageSocket should return no error on invalid socket when in socket activation mode")
	time.Sleep(time.Millisecond * 10)
	require.Equal(t, sock, d.GetSocketAddr(), "Socket has not changed")

	d.Quit(false)

	require.Equal(t, 1, len(grpcRegister.daemonsCalled), "we are still using the previous GRPC registerer with the socket activated socket")

	wg.Wait()
	require.NoError(t, err, "Listen should return no error when stopped after changing socket")
}

func TestSdNotifier(t *testing.T) {
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
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			grpcRegister := &grpcServiceRegister{}

			l, err := net.Listen("unix", filepath.Join(dir, "socket"))
			require.NoErrorf(t, err, "setup failed: couldn't create unix socket: %v", err)
			defer l.Close()

			d, err := daemon.New(grpcRegister.registerGRPCServer, "/tmp/this/is/ignored",
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
				d.Quit(false)
			}()

			err = d.Listen()
			if tc.wantErr {
				require.NotNil(t, err, "Listen should return an error")
				return
			} else if !tc.wantErr {
				require.NoError(t, err, "Listen should return no error")
			}
		})
	}
}

func TestFailingOption(t *testing.T) {
	t.Parallel()

	grpcRegister := &grpcServiceRegister{}

	_, err := daemon.New(grpcRegister.registerGRPCServer, "foo", daemon.FailingOption())
	require.NotNil(t, err, "Expected New to fail as an option failed")
}

func TestCannotCreateSocket(t *testing.T) {
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

	m.Run()
}
