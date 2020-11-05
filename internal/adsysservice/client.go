package adsysservice

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/grpc/contextidler"
	"github.com/ubuntu/adsys/internal/grpc/interceptorschain"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/grpc/unixsocket"
	"google.golang.org/grpc"
)

// AdSysClient is a wrapper around a grpc service client which can close the underlying connection
type AdSysClient struct {
	adsys.ServiceClient
	conn *grpc.ClientConn
}

// NewClient connect to the socket and returns a new AdSysClient
func NewClient(socket string, timeout time.Duration) (c *AdSysClient, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("Could not create client for service: %q", err)
		}
	}()

	conn, err := grpc.Dial(socket, grpc.WithInsecure(),
		grpc.WithStreamInterceptor(interceptorschain.StreamClient(
			log.StreamClientInterceptor(logrus.StandardLogger()),
			// This is the last element which will be the first interceptor to execute to get all pings.
			contextidler.StreamClientInterceptor(timeout),
		)),
		grpc.WithContextDialer(unixsocket.ContextDialer()),
	)
	if err != nil {
		return nil, err
	}
	client := adsys.NewServiceClient(conn)
	return &AdSysClient{
		ServiceClient: client,
		conn:          conn,
	}, nil
}

// Close ends the underlying connection
func (c *AdSysClient) Close() {
	c.conn.Close()
}
