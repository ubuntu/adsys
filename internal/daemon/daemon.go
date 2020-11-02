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

// Daemon is a grpc daemon with systemd activation, configuration changes like dynamic
// socket listening, idling timeout functionality…
type Daemon struct {
	grpcserver         *grpc.Server
	registerGRPCServer GRPCServerRegisterer

	idler

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

// WithTimeout adds a timeout to the daemon. A 0 duration means no timeout.
func WithTimeout(timeout time.Duration) func(o *options) error {
	return func(o *options) error {
		o.idlingTimeout = timeout
		return nil
	}
}

// New returns an new, initialized daemon server, which handles systemd activation.
// If systemd activation is used, it will override any socket passed here.
func New(registerGRPCServer GRPCServerRegisterer, socket string, opts ...option) (d *Daemon, err error) {
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

	d = &Daemon{
		registerGRPCServer: registerGRPCServer,

		idler: newIdler(args.idlingTimeout),

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
		if err = d.UseSocket(socket); err != nil {
			return nil, err
		}

	case 1:
		d.useSocketActivation = true
		d.lis <- listeners[0]
	default:
		return nil, fmt.Errorf(i18n.G("unexpected number of systemd socket activation (%d != 1)"), len(listeners))
	}

	d.grpcserver = d.registerGRPCServer(d)

	go d.idler.checkTimeout(d)

	return d, nil
}

// UseSocket listens on new given socket. If we were listening on another socket first, the connection will be teared down.
// Note that this has no effect if we were using socket activation.
func (d *Daemon) UseSocket(socket string) (err error) {
	if d.useSocketActivation {
		log.Debugf(context.Background(), "Call to UseSocket %q ignored: using systemd socket activation", socket)
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

	d.lis <- lis
	// Listen on new socket by stopping previous service
	if d.grpcserver != nil {
		d.stop()
	}

	return nil
}

// Listen serves on its unix socket path.
// It handles systemd activation notification.
// When the server stop listening, the socket is removed automatically.
// Configuration can be reloaded and we will then listen on the new socket
func (d *Daemon) Listen() error {
	if sent, err := d.systemdSdNotifier(false, "READY=1"); err != nil {
		return fmt.Errorf(i18n.G("couldn't send ready notification to systemd: %v"), err)
	} else if sent {
		log.Debug(context.Background(), i18n.G("Ready state sent to systemd"))
	}

	lis := <-d.lis

	// handle socket configuration reloading
	for {
		log.Infof(context.Background(), i18n.G("Serving on %s"), lis.Addr().String())
		if err := (d.grpcserver.Serve(lis)); err != nil {
			return fmt.Errorf("unable to start GRPC server: %s", err)
		}

		// check if we need to reconnect using a new socket
		var ok bool
		lis, ok = <-d.lis
		if !ok {
			break
		}
		d.grpcserver = d.registerGRPCServer(d)
	}
	log.Debug(context.Background(), i18n.G("Quitting"))

	return nil
}

// Quit gracefully quits listening loop and stops the grpc server
func (d *Daemon) Quit() {
	close(d.lis)
	d.stop()
}

// stop gracefully stops the grpc server
func (d *Daemon) stop() {
	log.Debug(context.Background(), i18n.G("Stopping daemon requested. Wait for active requests to close"))
	d.grpcserver.GracefulStop()
	log.Debug(context.Background(), i18n.G("All connections are now closed"))
}
