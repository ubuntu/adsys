package contextidler_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/grpc/contextidler"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestActiveConnection(t *testing.T) {
	t.Parallel()

	var s *clientStream

	streamCreation := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		s = &clientStream{ctx: ctx}
		return s, nil
	}
	c, err := contextidler.StreamClientInterceptor(10*time.Millisecond)(context.Background(), nil, nil, "method", streamCreation)
	require.NoError(t, err, "StreamClient Interceptor should return no error")

	// Ping once and get expected value on child stream called
	require.NoError(t, c.RecvMsg("something"), "RecvMsg with no error")
	require.Equal(t, "something", s.recvMsgCalledWith, "Streamer RecvMsg called with expected message")

	// Ping multiple times, each ping is less than timeout, but total time is more than the timeout
	for i := 0; i < 5; i++ {
		time.Sleep(5 * time.Millisecond)
		require.NoError(t, c.RecvMsg("something"), "RecvMsg with no error")
	}
}

type clientStream struct {
	grpc.ClientStream
	wantErrRecvMsg    error
	ctx               context.Context
	recvMsgCalledWith interface{}
}

func (c *clientStream) RecvMsg(m interface{}) error {
	c.recvMsgCalledWith = m
	select {
	// simulate context cancellation: either client (if we haven’t timeout yet) or timeout
	case <-c.ctx.Done():
		return status.New(codes.Canceled, "Client cancelled request").Err()
	default:
	}
	return c.wantErrRecvMsg
}
