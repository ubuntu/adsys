package unixsocket

import (
	"context"
	"net"
)

// ContextDialer returns a dialer for a local connection on an unix socket.
func ContextDialer() func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (conn net.Conn, err error) {
		unixAddr, err := net.ResolveUnixAddr("unix", addr)
		if err != nil {
			return nil, err
		}
		conn, err = net.DialUnix("unix", nil, unixAddr)
		return conn, err
	}
}
