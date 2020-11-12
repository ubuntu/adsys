package adsysservice

import (
	"fmt"

	"github.com/ubuntu/adsys"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/stdforward"
	"google.golang.org/grpc"
)

// Cat forwards any messages from all requests to the client.
// Anything logged by the server on stdout, stderr or via the standard logger.
// Only one call at a time can be performed here.
func (s *Service) Cat(r *adsys.Empty, stream adsys.Service_CatServer) error {

	// Redirect stdout and stderr

	f := streamWriter{stream}
	// take object as ID
	id := fmt.Sprint(&f)
	stdforward.AddStdoutWriter(id, f)
	defer stdforward.RemoveStdoutWriter(id)
	stdforward.AddStderrWriter(id, f)
	defer stdforward.RemoveStderrWriter(id)

	// Redirect all logs
	log.AddStreamToForward(id, stream)
	defer log.RemoveStreamToForward(id)

	<-stream.Context().Done()
	return nil
}

type streamWriter struct {
	grpc.ServerStream
}

func (ss streamWriter) Write(b []byte) (n int, err error) {
	return len(b), ss.SendMsg(&adsys.StringResponse{Msg: string(b)})
}
