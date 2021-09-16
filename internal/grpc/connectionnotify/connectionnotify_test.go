package connectionnotify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/grpc/connectionnotify"
	"google.golang.org/grpc"
)

type myStream struct {
	grpc.ServerStream
}

func (myStream) Context() context.Context {
	return context.Background()
}

func TestNoNotification(t *testing.T) {
	t.Parallel()

	callOrder := 1

	// the pingued object doesn’t have any method and so, shouldn’t get a panic trying to call the notify methods
	pingued, s := struct{}{}, struct{}{}

	var handlerCalled int
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = callOrder
		callOrder++
		return nil
	}

	err := connectionnotify.StreamServerInterceptor(pingued)(s, myStream{}, nil, handler)
	require.NoError(t, err, "StreamServerInterceptor returned an error when expecting none")

	assert.Equal(t, 1, handlerCalled, "handler was expected to be called at pos 1")
}

type newConnectionPingued struct {
	globalCallOrder          *int
	newConnectionCalledCount int
}

func (n *newConnectionPingued) OnNewConnection(_ context.Context, info *grpc.StreamServerInfo) {
	// store current count and increment the global one
	n.newConnectionCalledCount = *n.globalCallOrder
	*n.globalCallOrder++
}

func TestNewConnectionNotification(t *testing.T) {
	t.Parallel()

	callOrder := 1
	pingued := &newConnectionPingued{globalCallOrder: &callOrder}
	s := struct{}{}

	var handlerCalled int
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = callOrder
		callOrder++

		return nil
	}

	err := connectionnotify.StreamServerInterceptor(pingued)(s, myStream{}, nil, handler)
	require.NoError(t, err, "StreamServerInterceptor returned an error when expecting none")

	assert.Equal(t, 1, pingued.newConnectionCalledCount, "onNewConnection was called first at pos 1")
	assert.Equal(t, 2, handlerCalled, "handler was then called at pos 2")
}

type doneConnectionPingued struct {
	globalCallOrder           *int
	doneConnectionCalledCount int
}

func (n *doneConnectionPingued) OnDoneConnection(_ context.Context, info *grpc.StreamServerInfo) {
	// store current count and increment the global one
	n.doneConnectionCalledCount = *n.globalCallOrder
	*n.globalCallOrder++
}

func TestDoneConnectionNotification(t *testing.T) {
	t.Parallel()

	callOrder := 1
	pingued := &doneConnectionPingued{globalCallOrder: &callOrder}
	s := struct{}{}

	var handlerCalled int
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = callOrder
		callOrder++

		return nil
	}

	err := connectionnotify.StreamServerInterceptor(pingued)(s, myStream{}, nil, handler)
	require.NoError(t, err, "StreamServerInterceptor returned an error when expecting none")

	assert.Equal(t, 1, handlerCalled, "handler was called first at pos 1")
	assert.Equal(t, 2, pingued.doneConnectionCalledCount, "onDoneConnection was called after the handler at pos 2")
}

func TestErrorFromHandlerReturned(t *testing.T) {
	t.Parallel()

	pingued, s := struct{}{}, struct{}{}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return errors.New("Any error")
	}

	err := connectionnotify.StreamServerInterceptor(pingued)(s, myStream{}, nil, handler)
	require.NotNil(t, err, "StreamServerInterceptor should return the handler error")
}

func TestErrorOnNilStream(t *testing.T) {
	t.Parallel()

	pingued, s := struct{}{}, struct{}{}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	err := connectionnotify.StreamServerInterceptor(pingued)(s, nil, nil, handler)
	require.NotNil(t, err, "StreamServerInterceptor should return an error due to nil stream")
}
