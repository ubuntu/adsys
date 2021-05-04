package contextidler_test

import (
	"context"
	"errors"
	"io"
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
	c, err := contextidler.StreamClientInterceptor(100*time.Millisecond)(context.Background(), nil, nil, "method", streamCreation)
	require.NoError(t, err, "StreamClient Interceptor should return no error")

	// Ping once and get expected value on child stream called
	require.NoError(t, c.RecvMsg("something"), "RecvMsg with no error")
	require.Equal(t, "something", s.recvMsgCalledWith, "Streamer RecvMsg called with expected message")

	// Ping multiple times, each ping is less than timeout, but total time is more than the timeout
	for i := 0; i < 5; i++ {
		time.Sleep(30 * time.Millisecond)
		require.NoError(t, c.RecvMsg("something"), "RecvMsg with no error")
	}
}

func TestTimeoutOnInactiveConnection(t *testing.T) {
	t.Parallel()

	var s *clientStream

	streamCreation := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		s = &clientStream{ctx: ctx}
		return s, nil
	}
	c, err := contextidler.StreamClientInterceptor(10*time.Millisecond)(context.Background(), nil, nil, "method", streamCreation)
	require.NoError(t, err, "StreamClient Interceptor should return no error")

	// Wait for more than timeout
	time.Sleep(50 * time.Millisecond)
	err = c.RecvMsg("something")
	require.Error(t, err, "RecvMsg should return an error")
	require.Equal(t, codes.DeadlineExceeded, status.Code(err), "Got DeadlineExceeded code")
}

func TestCancelOnClientSide(t *testing.T) {
	t.Parallel()

	var s *clientStream

	clientCtx, clientCancel := context.WithCancel(context.Background())

	streamCreation := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		s = &clientStream{ctx: ctx}
		return s, nil
	}
	c, err := contextidler.StreamClientInterceptor(0)(clientCtx, nil, nil, "method", streamCreation)
	require.NoError(t, err, "StreamClient Interceptor should return no error")

	// Cancel client request (like Ctrl+C)
	clientCancel()

	err = c.RecvMsg("something")
	require.Error(t, err, "RecvMsg should return an error")
	require.Equal(t, io.EOF, err, "Got EOF")
}

func TestClientInterceptorFailed(t *testing.T) {
	t.Parallel()

	streamCreation := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return nil, errors.New("My interceptor error")
	}
	_, err := contextidler.StreamClientInterceptor(0)(context.Background(), nil, nil, "method", streamCreation)
	require.Error(t, err, "StreamClient Interceptor should return an error")
}

func TestRecvMessageError(t *testing.T) {
	t.Parallel()

	var s *clientStream

	childErr := errors.New("Server error")
	streamCreation := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		s = &clientStream{wantErrRecvMsg: childErr, ctx: ctx}
		return s, nil
	}
	c, err := contextidler.StreamClientInterceptor(10*time.Millisecond)(context.Background(), nil, nil, "method", streamCreation)
	require.NoError(t, err, "StreamClient Interceptor should return no error")

	err = c.RecvMsg("something")

	// We should receive the error sent from the child
	require.Equal(t, childErr, err, "RecvMsg returned child error")
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
