package unixsocket

import (
	"context"
	"fmt"
	"net"
)

// ContextDialer returns a dialer for a local connection on an unix socket.
func ContextDialer() func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (conn net.Conn, err error) {
		defer func() {
			if err != nil {
				err = fmt.Errorf("couldn't connect to unix socket: %v", err)
			}
		}()

		unixAddr, err := net.ResolveUnixAddr("unix", addr)
		if err != nil {
			return nil, err
		}
		conn, err = net.DialUnix("unix", nil, unixAddr)
		return conn, err
	}
}
