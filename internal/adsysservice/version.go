package adsysservice

import (
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/config"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// Version returns version from server
func (s *Service) Version(r *adsys.Empty, stream adsys.Service_VersionServer) error {
	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	if err := stream.Send(&adsys.VersionResponse{
		Version: config.Version,
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send service version to client: %v", err)
	}
	return nil
}
