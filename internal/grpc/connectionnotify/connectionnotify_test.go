package connectionnotify_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/grpc/connectionnotify"
	"google.golang.org/grpc"
)

func TestNoNotification(t *testing.T) {
	t.Parallel()

	callOrder := 1

	// the server doesn’t have any method and so, shouldn’t get a panic trying to call the notify methods
	s := struct{}{}

	var handlerCalled int
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = callOrder
		callOrder++
		return nil
	}

	err := connectionnotify.StreamServerInterceptor(s, nil, nil, handler)
	require.NoError(t, err, "StreamServerInterceptor returned an error when expecting none")

	assert.Equal(t, 1, handlerCalled, "handler was expected to be called at pos 1")
}

type newConnectionServer struct {
	globalCallOrder          *int
	newConnectionCalledCount int
}

func (n *newConnectionServer) OnNewConnection(info *grpc.StreamServerInfo) {
	// store current count and increment the global one
	n.newConnectionCalledCount = *n.globalCallOrder
	*n.globalCallOrder++
}

func TestNewConnectionNotification(t *testing.T) {
	t.Parallel()

	// the server doesn’t have any method and so, shouldn’t get a panic trying to call the notify methods
	callOrder := 1
	s := &newConnectionServer{globalCallOrder: &callOrder}

	var handlerCalled int
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = callOrder
		callOrder++

		return nil
	}

	err := connectionnotify.StreamServerInterceptor(s, nil, nil, handler)
	require.NoError(t, err, "StreamServerInterceptor returned an error when expecting none")

	assert.Equal(t, 1, s.newConnectionCalledCount, "onNewConnection was called first at pos 1")
	assert.Equal(t, 2, handlerCalled, "handler was then called at pos 2")
}

type doneConnectionServer struct {
	globalCallOrder           *int
	doneConnectionCalledCount int
}

func (n *doneConnectionServer) OnDoneConnection(info *grpc.StreamServerInfo) {
	// store current count and increment the global one
	n.doneConnectionCalledCount = *n.globalCallOrder
	*n.globalCallOrder++
}

func TestDoneConnectionNotification(t *testing.T) {
	t.Parallel()

	// the server doesn’t have any method and so, shouldn’t get a panic trying to call the notify methods
	callOrder := 1
	s := &doneConnectionServer{globalCallOrder: &callOrder}

	var handlerCalled int
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = callOrder
		callOrder++

		return nil
	}

	err := connectionnotify.StreamServerInterceptor(s, nil, nil, handler)
	require.NoError(t, err, "StreamServerInterceptor returned an error when expecting none")

	assert.Equal(t, 1, handlerCalled, "handler was called first at pos 1")
	assert.Equal(t, 2, s.doneConnectionCalledCount, "onDoneConnection was called after the handler at pos 2")

}

func TestErrorFromHandlerReturned(t *testing.T) {
	t.Parallel()

	s := struct{}{}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return errors.New("Any error")
	}

	err := connectionnotify.StreamServerInterceptor(s, nil, nil, handler)
	require.NotNil(t, err, "StreamServerInterceptor should return the handler error")
}
