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
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/ad"
	"google.golang.org/grpc"
	"gopkg.in/ini.v1"
)

// Service is used to implement adsys.ServiceServer.
type Service struct {
	adsys.UnimplementedServiceServer
	logger *logrus.Logger

	adc *ad.AD

	quit quitter
}

// New returns a new instance of an AD service.
// If url or domain is empty, we load the missing parameters from sssd.conf, taking first
// domain in the list if not provided.
func New(ctx context.Context, url, domain string) (*Service, error) {
	url, domain, err := loadServerInfo(url, domain)
	adc, err := ad.New(ctx, url, domain)
	if err != nil {
		return nil, err
	}
	return &Service{
		adc: adc,
	}, nil
}

func loadServerInfo(url, domain string) (string, string, error) {
	if url != "" && domain != "" {
		return url, domain, nil
	}

	cfg, err := ini.Load("/etc/sssd/sssd.conf")
	if err != nil {
		return "", "", fmt.Errorf(i18n.G("can't read sssd.conf and no url or domain provided"), err)
	}
	if domain == "" {
		domain = strings.Split(cfg.Section("sssd").Key("domains").String(), ",")[0]
		if domain == "" {
			return "", "", errors.New(i18n.G("failed to find default domain in sssd.conf and domain is not provided"))
		}
	}
	// domain is either domain section provided by the user or read in sssd.conf
	adDomain := cfg.Section(fmt.Sprintf("domain/%s", domain)).Key("ad_domain").String()
	if adDomain != "" {
		domain = adDomain
	}

	if url == "" {
		url = cfg.Section(fmt.Sprintf("domain/%s", domain)).Key("ad_server").String()
		if url == "" {
			return "", "", errors.New(i18n.G("failed to find server address in sssd.conf and url is not provided"))
		}
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
		)))
	adsys.RegisterServiceServer(srv, s)
	return srv
}
