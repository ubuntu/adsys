package adsysservice

import (
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/decorate"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Version returns version from server.
func (s *Service) Version(_ *emptypb.Empty, stream adsys.Service_VersionServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while getting daemon version"))

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
