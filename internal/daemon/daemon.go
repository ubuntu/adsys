package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/coreos/go-systemd/activation"
	"github.com/coreos/go-systemd/daemon"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"google.golang.org/grpc"
)

const (
	defaultTimeout = 2 * time.Minute
)

type grpcRegisterer interface {
}

// Daemon is a grpc daemon with systemd activation, configuration changes like dynamic
// socket listening, idling timeout functionality…
type Daemon struct {
	grpcserver         *grpc.Server
	registerGRPCServer GRPCServerRegisterer

	lis chan net.Listener

	systemdSdNotifier   func(unsetEnvironment bool, state string) (bool, error)
	useSocketActivation bool
}

type options struct {
	socket        string
	idlingTimeout time.Duration

	// private member that we export for tests.
	systemdActivationListener func() ([]net.Listener, error)
	systemdSdNotifier         func(unsetEnvironment bool, state string) (bool, error)
}

type option func(*options) error

// GRPCServerRegisterer is a function that the daemon will call everytime we want to build a new GRPC object
type GRPCServerRegisterer func(srv *Daemon) *grpc.Server

// New returns an new, initialized daemon server, which handles systemd activation.
// If systemd activation is used, it will override any socket passed here.
func New(registerGRPCServer GRPCServerRegisterer, socket string, opts ...option) (s *Daemon, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("couldn't create server: %v"), err)
		}
	}()

	// defaults
	args := options{
		idlingTimeout: defaultTimeout,

		systemdActivationListener: activation.Listeners,
		systemdSdNotifier:         daemon.SdNotify,
	}
	// applied options
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}

	s = &Daemon{
		registerGRPCServer: registerGRPCServer,
		lis:                make(chan net.Listener, 1),
		systemdSdNotifier:  args.systemdSdNotifier,
	}

	// systemd socket activation or local creation
	listeners, err := args.systemdActivationListener()
	if err != nil {
		return nil, err
	}

	switch len(listeners) {
	case 0:
		if err = s.UseSocket(socket); err != nil {
			return nil, err
		}

	case 1:
		s.useSocketActivation = true
		s.lis <- listeners[0]
	default:
		return nil, fmt.Errorf(i18n.G("unexpected number of systemd socket activation (%d != 1)"), len(listeners))
	}

	s.grpcserver = s.registerGRPCServer(s)

	return s, nil
}

// UseSocket listens on new given socket. If we were listening on another socket first, the connection will be teared down.
// Note that this has no effect if we were using socket activation.
func (s *Daemon) UseSocket(socket string) (err error) {
	if s.useSocketActivation {
		return nil
	}

	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("couldn't listen on new socket %q: %v"), socket, err)
		}
	}()

	lis, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err = os.Chmod(socket, 0666); err != nil {
		lis.Close()
		return err
	}

	s.lis <- lis
	// Listen on new socket by stopping previous service
	if s.grpcserver != nil {
		s.stop()
	}

	return nil
}

// Listen serves on its unix socket path.
// It handles systemd activation notification.
// When the server stop listening, the socket is removed automatically.
// Configuration can be reloaded and we will then listen on the new socket
func (s *Daemon) Listen() error {
	if sent, err := s.systemdSdNotifier(false, "READY=1"); err != nil {
		return fmt.Errorf(i18n.G("couldn't send ready notification to systemd: %v"), err)
	} else if sent {
		log.Debug(context.Background(), i18n.G("Ready state sent to systemd"))
	}

	lis, ok := <-s.lis
	if !ok {
		return nil
	}

	// handle socket configuration reloading
	for {
		log.Infof(context.Background(), i18n.G("Serving on %s"), lis.Addr().String())
		if err := (s.grpcserver.Serve(lis)); err != nil {
			return fmt.Errorf("unable to start GRPC server: %s", err)
		}

		// check if we need to reconnect using a new socket
		lis, ok = <-s.lis
		if !ok {
			break
		}
		s.grpcserver = s.registerGRPCServer(s)
	}
	log.Debug(context.Background(), i18n.G("Quitting"))

	return nil
}

// Quit gracefully quits listening loop and stops the grpc server
func (s *Daemon) Quit() {
	close(s.lis)
	s.stop()
}

// stop gracefully stops the grpc server
func (s *Daemon) stop() {
	log.Debug(context.Background(), i18n.G("Stopping daemon requested. Wait for active requests to close"))
	s.grpcserver.GracefulStop()
	log.Debug(context.Background(), i18n.G("All connections are now closed"))
}
