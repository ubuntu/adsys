package adsysservice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/daemon"
	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/grpc/connectionnotify"
	"github.com/ubuntu/adsys/internal/grpc/interceptorschain"
	"github.com/ubuntu/adsys/internal/grpc/logconnections"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/ad"
	"google.golang.org/grpc"
	"gopkg.in/ini.v1"
)

// Service is used to implement adsys.ServiceServer.
type Service struct {
	adsys.UnimplementedServiceServer
	logger *logrus.Logger

	adc           *ad.AD
	policyManager *policies.Manager

	authorizer authorizerer

	state          state
	initSystemTime *time.Time

	bus    *dbus.Conn
	daemon *daemon.Daemon
}

type state struct {
	cacheDir    string
	runDir      string
	dconfDir    string
	sssCacheDir string
	sssConf     string

	adServer string
	adDomain string
}

type options struct {
	cacheDir    string
	runDir      string
	dconfDir    string
	sssCacheDir string
	sssdConf    string
	authorizer  authorizerer
}
type option func(*options) error

type authorizerer interface {
	IsAllowedFromContext(context.Context, authorizer.Action) error
}

// WithCacheDir specifies a personalized daemon cache directory
func WithCacheDir(p string) func(o *options) error {
	return func(o *options) error {
		o.cacheDir = p
		return nil
	}
}

// WithRunDir specifies a personalized /run
func WithRunDir(p string) func(o *options) error {
	return func(o *options) error {
		o.runDir = p
		return nil
	}
}

// WithDconfDir specifies a personalized /etc/dconf
func WithDconfDir(p string) func(o *options) error {
	return func(o *options) error {
		o.dconfDir = p
		return nil
	}
}

// WithSSSCacheDir specifies a personalized /
func WithSSSCacheDir(p string) func(o *options) error {
	return func(o *options) error {
		o.sssCacheDir = p
		return nil
	}
}

// New returns a new instance of an AD service.
// If url or domain is empty, we load the missing parameters from sssd.conf, taking first
// domain in the list if not provided.
func New(ctx context.Context, url, domain string, opts ...option) (s *Service, err error) {
	defer decorate.OnError(&err, i18n.G("couldn't create adsys service"))

	// defaults
	args := options{
		sssdConf: consts.DefaultSSSConf,
	}
	// applied options
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}

	// Don’t call dbus.SystemBus which caches globally system dbus (issues in tests)
	bus, err := dbus.SystemBusPrivate()
	if err != nil {
		return nil, err
	}
	if err = bus.Auth(nil); err != nil {
		_ = bus.Close()
		return nil, err
	}
	if err = bus.Hello(); err != nil {
		_ = bus.Close()
		return nil, err
	}

	url, domain, err = loadServerInfo(args.sssdConf, url, domain)
	if err != nil {
		return nil, err
	}

	// Try sssd discovered ad server url
	if url == "" {
		log.Debug(ctx, "AD server not specified in sssd.conf nor set manually to the user, try autodiscovering mode")
		sssd := bus.Object("org.freedesktop.sssd.infopipe",
			dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/sssd/infopipe/Domains/%s", strings.ReplaceAll(domain, ".", "_2e"))))
		if err := sssd.Call("org.freedesktop.sssd.infopipe.Domains.Domain.ActiveServer", 0, "AD").Store(&url); err != nil || url == "" {
			return nil, errors.New(i18n.G("failed to find active AD server address in sssd (sssd.conf or sssd discovery) and url is not provided"))
		}
	}

	log.Debugf(ctx, "AD domain: %q, server: %q", domain, url)

	if !strings.HasPrefix(url, "ldap://") {
		url = fmt.Sprintf("ldap://%s", url)
	}
	var adOptions []ad.Option
	if args.cacheDir != "" {
		adOptions = append(adOptions, ad.WithCacheDir(args.cacheDir))
	}
	if args.runDir != "" {
		adOptions = append(adOptions, ad.WithRunDir(args.runDir))
	}
	if args.sssCacheDir != "" {
		adOptions = append(adOptions, ad.WithSSSCacheDir(args.sssCacheDir))
	}
	adc, err := ad.New(ctx, url, domain, adOptions...)
	if err != nil {
		return nil, err
	}

	if args.authorizer == nil {
		args.authorizer, err = authorizer.New(bus)
		if err != nil {
			_ = bus.Close()
			return nil, err
		}
	}

	var policyOptions []policies.Option
	if args.cacheDir != "" {
		policyOptions = append(policyOptions, policies.WithCacheDir(args.cacheDir))
	}
	if args.dconfDir != "" {
		policyOptions = append(policyOptions, policies.WithDconfDir(args.dconfDir))
	}
	m, err := policies.New(policyOptions...)
	if err != nil {
		return nil, err
	}

	// Init system reference time
	initSysTime := initSystemTime(bus)

	return &Service{
		adc:           adc,
		policyManager: m,
		authorizer:    args.authorizer,
		state: state{
			cacheDir:    args.cacheDir,
			dconfDir:    args.dconfDir,
			runDir:      args.runDir,
			sssCacheDir: args.sssCacheDir,
			adServer:    url,
			adDomain:    domain,
		},
		initSystemTime: initSysTime,
		bus:            bus,
	}, nil
}

func loadServerInfo(sssdConf, url, domain string) (rurl string, rdomain string, err error) {
	defer decorate.OnError(&err, i18n.G("can't load server info from %s"), sssdConf)

	if url != "" && domain != "" {
		return url, domain, nil
	}

	cfg, err := ini.Load(sssdConf)
	if err != nil {
		// Allow autodiscovery for server if domain was manually set.
		if domain != "" {
			return "", domain, nil
		}
		return "", "", fmt.Errorf(i18n.G("can't read sssd.conf and no url or domain provided: %v"), err)
	}
	if domain == "" {
		domain = strings.Split(cfg.Section("sssd").Key("domains").String(), ",")[0]
		if domain == "" {
			return "", "", errors.New(i18n.G("failed to find default domain in sssd.conf and domain is not provided"))
		}
	}
	// domain is either domain section provided by the user or read in sssd.conf
	adDomain := cfg.Section(fmt.Sprintf("domain/%s", domain)).Key("ad_domain").String()

	if url == "" {
		url = cfg.Section(fmt.Sprintf("domain/%s", domain)).Key("ad_server").String()
	}

	if adDomain != "" {
		domain = adDomain
	}

	return url, domain, nil
}

// RegisterGRPCServer registers our service with the new interceptor chains.
// It will notify the daemon of any new connection
func (s *Service) RegisterGRPCServer(d *daemon.Daemon) *grpc.Server {
	s.logger = logrus.StandardLogger()
	srv := grpc.NewServer(grpc.StreamInterceptor(
		interceptorschain.StreamServer(
			log.StreamServerInterceptor(s.logger),
			connectionnotify.StreamServerInterceptor(d),
			logconnections.StreamServerInterceptor(),
		)), authorizer.WithUnixPeerCreds())
	adsys.RegisterServiceServer(srv, s)
	s.daemon = d
	return srv
}

// Quit cleans every ressources than the service was using.
func (s *Service) Quit(ctx context.Context) {
	if err := s.bus.Close(); err != nil {
		log.Warningf(ctx, i18n.G("Can't disconnect system dbus: %v"), err)
	}
}

// initSystemTime returns systemd generator init system time
func initSystemTime(bus *dbus.Conn) *time.Time {
	systemd := bus.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	val, err := systemd.GetProperty("org.freedesktop.systemd1.Manager.GeneratorsStartTimestamp")
	if err != nil {
		log.Warningf(context.Background(), "could not get system startup time? Can’t list next refresh: %v", err)
		return nil
	}
	start, ok := val.Value().(uint64)
	if !ok {
		log.Warningf(context.Background(), "invalid next system startup time: %q", val.Value())
		return nil
	}

	initSystemTime := time.Unix(int64(start)/1000000, 0)
	return &initSystemTime
}
