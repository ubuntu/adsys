package interceptorschain_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/grpc/interceptorschain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type keyCtxType string

func TestStreamServer(t *testing.T) {
	t.Parallel()

	someService := &struct{}{}
	someServiceName := "MyService"
	recvMessage := "received"
	sentMessage := "sent"
	outputError := fmt.Errorf("some error")

	parentContext := context.WithValue(context.TODO(), keyCtxType("parent"), 42)
	parentStreamInfo := &grpc.StreamServerInfo{
		FullMethod:     someServiceName,
		IsServerStream: true,
	}

	first := func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		requireContextValue(t, 42, stream.Context(), "parent", "first interceptor must know the parent context value")
		require.Equal(t, parentStreamInfo, info, "first interceptor must know the parentStreamInfo")
		require.Equal(t, someService, srv, "first interceptor must know someService")
		wrapped := wrapServerStream(stream)
		wrapped.wrappedContext = context.WithValue(stream.Context(), keyCtxType("first"), 43)
		return handler(srv, wrapped)
	}
	second := func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		requireContextValue(t, 42, stream.Context(), "parent", "second interceptor must know the parent context value")
		requireContextValue(t, 43, stream.Context(), "first", "second interceptor must know the first context value")
		require.Equal(t, parentStreamInfo, info, "second interceptor must know the parentStreamInfo")
		require.Equal(t, someService, srv, "second interceptor must know someService")
		wrapped := wrapServerStream(stream)
		wrapped.wrappedContext = context.WithValue(stream.Context(), keyCtxType("second"), 44)
		return handler(srv, wrapped)
	}
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		require.Equal(t, someService, srv, "handler must know someService")
		requireContextValue(t, 42, stream.Context(), "parent", "handler must know the parent context value")
		requireContextValue(t, 43, stream.Context(), "first", "handler must know the first context value")
		requireContextValue(t, 44, stream.Context(), "second", "handler must know the second context value")
		require.NoError(t, stream.RecvMsg(recvMessage), "handler must have access to stream messages")
		require.NoError(t, stream.SendMsg(sentMessage), "handler must be able to send stream messages")
		return outputError
	}
	fakeStream := &fakeServerStream{ctx: parentContext, recvMessage: recvMessage}
	chain := interceptorschain.StreamServer(first, second)
	err := chain(someService, fakeStream, parentStreamInfo, handler)
	require.Equal(t, outputError, err, "chain must return handler's error")
	require.Equal(t, sentMessage, fakeStream.sentMessage, "handler's sent message must propagate to stream")
}

func TestStreamClient(t *testing.T) {
	t.Parallel()

	someServiceName := "MyService"
	parentContext := context.WithValue(context.TODO(), keyCtxType("parent"), 42)

	ignoredMd := metadata.Pairs("foo", "bar")
	parentOpts := []grpc.CallOption{grpc.Header(&ignoredMd)}
	clientStream := &fakeClientStream{}
	fakeStreamDesc := &grpc.StreamDesc{ClientStreams: true, ServerStreams: true, StreamName: someServiceName}

	first := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		requireContextValue(t, 42, ctx, "parent", "first must know the parent context value")
		require.Equal(t, someServiceName, method, "first must know someService")
		require.Len(t, opts, 1, "first should see parent CallOptions")
		wrappedCtx := context.WithValue(ctx, keyCtxType("first"), 43)
		return streamer(wrappedCtx, desc, cc, method, opts...)
	}
	second := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		requireContextValue(t, 42, ctx, "parent", "second must know the parent context value")
		requireContextValue(t, 43, ctx, "first", "second must know the first context value")
		require.Equal(t, someServiceName, method, "second must know someService")
		require.Len(t, opts, 1, "second should see parent CallOptions")
		wrappedOpts := append(opts, grpc.WaitForReady(false))
		wrappedCtx := context.WithValue(ctx, keyCtxType("second"), 44)
		return streamer(wrappedCtx, desc, cc, method, wrappedOpts...)
	}
	streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		require.Equal(t, someServiceName, method, "streamer must know someService")
		require.Equal(t, fakeStreamDesc, desc, "streamer must see the right StreamDesc")

		requireContextValue(t, 42, ctx, "parent", "streamer must know the parent context value")
		requireContextValue(t, 43, ctx, "first", "streamer must know the first context value")
		requireContextValue(t, 44, ctx, "second", "streamer must know the second context value")
		require.Len(t, opts, 2, "streamer should see both CallOpts from second and parent")
		return clientStream, nil
	}
	chain := interceptorschain.StreamClient(first, second)
	someStream, err := chain(parentContext, fakeStreamDesc, nil, someServiceName, streamer, parentOpts...)
	require.NoError(t, err, "chain must not return an error")
	require.Equal(t, clientStream, someStream, "chain must return invokers's clientstream")
}

// nolint:revive // Helper function for a require assertion (expected, got)
func requireContextValue(t *testing.T, expected interface{}, ctx context.Context, key string, msg ...interface{}) {
	t.Helper()
	val := ctx.Value(keyCtxType(key))
	require.NotNil(t, val, msg...)
	require.Equal(t, expected, val, msg...)
}

// wrappedServerStream is a thin wrapper around grpc.ServerStream that allows modifying context.
type wrappedServerStream struct {
	grpc.ServerStream
	// wrappedContext is the wrapper's own Context. You can assign it.
	wrappedContext context.Context
}

// Context returns the wrapper's WrappedContext, overwriting the nested grpc.ServerStream.Context().
func (w *wrappedServerStream) Context() context.Context {
	return w.wrappedContext
}

// wrapServerStream returns a ServerStream that has the ability to overwrite context.
func wrapServerStream(stream grpc.ServerStream) *wrappedServerStream {
	if existing, ok := stream.(*wrappedServerStream); ok {
		return existing
	}
	return &wrappedServerStream{ServerStream: stream, wrappedContext: stream.Context()}
}

type fakeServerStream struct {
	grpc.ServerStream
	ctx         context.Context
	recvMessage interface{}
	sentMessage interface{}
}

func (f *fakeServerStream) Context() context.Context {
	return f.ctx
}

func (f *fakeServerStream) SendMsg(m interface{}) error {
	if f.sentMessage != nil {
		return status.Errorf(codes.AlreadyExists, "fakeServerStream only takes one message, sorry")
	}
	f.sentMessage = m
	return nil
}

func (f *fakeServerStream) RecvMsg(m interface{}) error {
	if f.recvMessage == nil {
		return status.Errorf(codes.NotFound, "fakeServerStream has no message, sorry")
	}
	return nil
}

type fakeClientStream struct {
	grpc.ClientStream
}
