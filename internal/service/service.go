package service

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/coreos/go-systemd/activation"
	"github.com/coreos/go-systemd/daemon"
	"github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/grpc/connectionnotify"
	"github.com/ubuntu/adsys/internal/grpc/interceptorschainer"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"google.golang.org/grpc"
)

// Server is used to implement adsys.ServiceServer.
type Server struct {
	grpcserver *grpc.Server
	adsys.UnimplementedServiceServer

	lis chan net.Listener

	systemdSdNotifier   func(unsetEnvironment bool, state string) (bool, error)
	useSocketActivation bool
}

type options struct {
	socket string

	// private member that we export for tests.
	systemdActivationListener func() ([]net.Listener, error)
	systemdSdNotifier         func(unsetEnvironment bool, state string) (bool, error)
}

type option func(*options) error

// New returns an new, initialized daemon server, which handles systemd activation.
// If systemd activation is used, it will override any socket passed here.
func New(socket string, opts ...option) (s *Server, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("couldn't create server: %v"), err)
		}
	}()

	// defaults
	args := options{
		systemdActivationListener: activation.Listeners,
		systemdSdNotifier:         daemon.SdNotify,
	}
	// applied options
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}

	s = &Server{
		lis:               make(chan net.Listener, 1),
		systemdSdNotifier: args.systemdSdNotifier,
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

	return s, nil
}

// UseSocket listens on new given socket. If we were listening on another socket first, the connection will be teared down.
// Note that this has no effect if we were using socket activation.
func (s *Server) UseSocket(socket string) (err error) {
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
func (s *Server) Listen() error {
	if sent, err := s.systemdSdNotifier(false, "READY=1"); err != nil {
		return fmt.Errorf(i18n.G("couldn't send ready notification to systemd while supported: %v"), err)
	} else if sent {
		log.Debug(context.Background(), i18n.G("Ready state sent to systemd"))
	}

	// handle socket configuration reloading
	for {
		lis, ok := <-s.lis
		if !ok {
			break
		}

		// Load a new server
		srv := grpc.NewServer(grpc.StreamInterceptor(
			interceptorschainer.ChainStreamServerInterceptors(
				connectionnotify.StreamServerInterceptor,
				log.StreamServerInterceptor(logrus.StandardLogger()))))
		adsys.RegisterServiceServer(srv, s)
		s.grpcserver = srv

		log.Infof(context.Background(), i18n.G("Serving on %s"), lis.Addr().String())
		if err := (s.grpcserver.Serve(lis)); err != nil {
			return fmt.Errorf("unable to start GRPC server: %s", err)
		}
	}
	log.Debug(context.Background(), i18n.G("Quitting"))

	return nil
}

// Quit gracefully quit and stops the grpc server
func (s *Server) Quit() {
	close(s.lis)
	s.stop()
}

// stop gracefully stops the grpc server
func (s *Server) stop() {
	log.Debug(context.Background(), i18n.G("Stopping daemon requested. Wait for active requests to close"))
	s.grpcserver.GracefulStop()
	log.Debug(context.Background(), i18n.G("All connections are now closed"))
}
