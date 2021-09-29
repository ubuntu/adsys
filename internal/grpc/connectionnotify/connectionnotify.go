package connectionnotify

import (
	"context"
	"errors"

	"google.golang.org/grpc"
)

type onNewConnectionner interface {
	OnNewConnection(ctx context.Context, info *grpc.StreamServerInfo)
}

type onDoneConnectionner interface {
	OnDoneConnection(ctx context.Context, info *grpc.StreamServerInfo)
}

// StreamServerInterceptor notifies the pingued object on each new and ended connections.
// If the pingued object implements onNewConnectionner, it will have OnNewConnection called when the connection is established (can be used for logging for instance)
// If the pingued object implements onDoneConnectionner, it will have OnDoneConnection called when the connection was handled by the server (can be used to reset an internal timeout for instance).
func StreamServerInterceptor(pingued interface{}) func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if ss == nil {
			return errors.New("can't intercept a nil stream")
		}
		if s, ok := pingued.(onNewConnectionner); ok {
			s.OnNewConnection(ss.Context(), info)
		}
		if s, ok := pingued.(onDoneConnectionner); ok {
			defer s.OnDoneConnection(ss.Context(), info)
		}
		return handler(srv, ss)
	}
}
