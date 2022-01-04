package adsysservice

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/grpc/contextidler"
	"github.com/ubuntu/adsys/internal/grpc/interceptorschain"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// AdSysClient is a wrapper around a grpc service client which can close the underlying connection.
type AdSysClient struct {
	adsys.ServiceClient
	conn *grpc.ClientConn
}

// NewClient connect to the socket and returns a new AdSysClient.
func NewClient(socket string, timeout time.Duration) (c *AdSysClient, err error) {
	defer decorate.OnError(&err, i18n.G("can't create client for service"))

	conn, err := grpc.Dial(fmt.Sprintf("unix:%s", socket), grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStreamInterceptor(interceptorschain.StreamClient(
			log.StreamClientInterceptor(logrus.StandardLogger()),
			// This is the last element which will be the first interceptor to execute to get all pings.
			contextidler.StreamClientInterceptor(timeout),
		)),
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

// Close ends the underlying connection.
func (c *AdSysClient) Close() {
	decorate.LogFuncOnError(c.conn.Close)
}
