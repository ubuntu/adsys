package adsysservice

import (
	"github.com/leonelquinteros/gotext"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/decorate"
)

// Version returns version from server.
func (s *Service) Version(_ *adsys.Empty, stream adsys.Service_VersionServer) (err error) {
	defer decorate.OnError(&err, gotext.Get("error while getting daemon version"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	if err := stream.Send(&adsys.StringResponse{
		Msg: consts.Version,
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send service version to client: %v", err)
	}
	return nil
}
