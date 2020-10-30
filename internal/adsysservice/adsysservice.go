package adsysservice

import (
	"github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/daemon"
	"github.com/ubuntu/adsys/internal/grpc/connectionnotify"
	"github.com/ubuntu/adsys/internal/grpc/interceptorschain"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"google.golang.org/grpc"
)

// Service is used to implement adsys.ServiceServer.
type Service struct {
	adsys.UnimplementedServiceServer
}

// RegisterGRPCServer registers our service with the new interceptor chains.
// It will notify the daemon of any new connection
func (s *Service) RegisterGRPCServer(d *daemon.Daemon) *grpc.Server {
	srv := grpc.NewServer(grpc.StreamInterceptor(
		interceptorschain.StreamServer(
			connectionnotify.StreamServerInterceptor(d),
			log.StreamServerInterceptor(logrus.StandardLogger()))))
	adsys.RegisterServiceServer(srv, s)
	return srv
}
