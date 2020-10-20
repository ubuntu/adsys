package connectionnotify

import "google.golang.org/grpc"

type onNewConnectionner interface {
	OnNewConnection(info *grpc.StreamServerInfo)
}

type onDoneConnectionner interface {
	OnDoneConnection(info *grpc.StreamServerInfo)
}

// StreamServerInterceptor notifies the server on each new and ended connections.
// If the server implements onNewConnectionner, it will have OnNewConnection called when the connection is established (can be used for logging for instance)
// If the server implements onDoneConnectionner, it will have OnDoneConnection called when the connection was handled by the server (can be used to reset an internal timeout for instance)
func StreamServerInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if s, ok := srv.(onNewConnectionner); ok {
		s.OnNewConnection(info)
	}
	if s, ok := srv.(onDoneConnectionner); ok {
		defer s.OnDoneConnection(info)
	}
	return handler(srv, ss)
}
