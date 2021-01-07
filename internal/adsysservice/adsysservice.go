package adsysservice

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/daemon"
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
	policyManager policies.Manager

	quit quitter
}

type options struct {
	sssdConf string
}
type option func(*options) error

// New returns a new instance of an AD service.
// If url or domain is empty, we load the missing parameters from sssd.conf, taking first
// domain in the list if not provided.
func New(ctx context.Context, url, domain string, opts ...option) (*Service, error) {
	// defaults
	args := options{
		sssdConf: "/etc/sssd/sssd.conf",
	}
	// applied options
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}

	url, domain, err := loadServerInfo(args.sssdConf, url, domain)
	if !strings.HasPrefix(url, "ldap://") {
		url = fmt.Sprintf("ldap://%s", url)
	}
	adc, err := ad.New(ctx, url, domain)
	if err != nil {
		return nil, err
	}
	return &Service{
		adc:           adc,
		policyManager: policies.New(),
	}, nil
}

func loadServerInfo(sssdConf, url, domain string) (string, string, error) {
	if url != "" && domain != "" {
		return url, domain, nil
	}

	cfg, err := ini.Load(sssdConf)
	if err != nil {
		return "", "", fmt.Errorf(i18n.G("can't read %s and no url or domain provided: %v"), sssdConf, err)
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
		if url == "" {
			return "", "", errors.New(i18n.G("failed to find server address in sssd.conf and url is not provided"))
		}
	}

	if adDomain != "" {
		domain = adDomain
	}

	return url, domain, nil
}

type quitter interface {
	Quit(bool)
}

// RegisterGRPCServer registers our service with the new interceptor chains.
// It will notify the daemon of any new connection
func (s *Service) RegisterGRPCServer(d *daemon.Daemon) *grpc.Server {
	s.logger = logrus.StandardLogger()
	s.quit = d
	srv := grpc.NewServer(grpc.StreamInterceptor(
		interceptorschain.StreamServer(
			log.StreamServerInterceptor(s.logger),
			connectionnotify.StreamServerInterceptor(d),
			logconnections.StreamServerInterceptor(),
		)))
	adsys.RegisterServiceServer(srv, s)
	return srv
}
