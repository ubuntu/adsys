package unixsocket

import (
	"context"
	"net"

	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
)

// ContextDialer returns a dialer for a local connection on an unix socket.
func ContextDialer() func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (conn net.Conn, err error) {
		defer decorate.OnError(&err, i18n.G("can't dial to %s"), addr)

		unixAddr, err := net.ResolveUnixAddr("unix", addr)
		if err != nil {
			return nil, err
		}
		conn, err = net.DialUnix("unix", nil, unixAddr)
		return conn, err
	}
}
