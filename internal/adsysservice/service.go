package adsysservice

import (
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice/actions"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/stdforward"
	"google.golang.org/grpc"
)

// Cat forwards any messages from all requests to the client.
// Anything logged by the server on stdout, stderr or via the standard logger.
// Only one call at a time can be performed here.
func (s *Service) Cat(r *adsys.Empty, stream adsys.Service_CatServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while trying to display daemon output"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), actions.ActionServiceManage); err != nil {
		return err
	}

	// Redirect stdout and stderr
	f := streamWriter{stream}
	remove, err := stdforward.AddStdoutWriter(f)
	if err != nil {
		return err
	}
	defer remove()
	remove, err = stdforward.AddStderrWriter(f)
	if err != nil {
		return err
	}
	defer remove()

	// Redirect all logs
	defer log.AddStreamToForward(stream)()

	<-stream.Context().Done()
	return nil
}

type streamWriter struct {
	grpc.ServerStream
}

func (ss streamWriter) Write(b []byte) (n int, err error) {
	return len(b), ss.SendMsg(&adsys.StringResponse{Msg: string(b)})
}

// Stop requests to stop the service once all connections are done. Force will shut it down immediately and drop
// existing connections.
func (s *Service) Stop(r *adsys.StopRequest, stream adsys.Service_StopServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while trying to stop daemon"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), actions.ActionServiceManage); err != nil {
		return err
	}

	go s.quit.Quit(r.GetForce())
	return nil
}
