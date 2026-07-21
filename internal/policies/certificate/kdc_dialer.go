package certificate

import (
	"context"
	"net"
	"sync"
	"time"

	krbclient "github.com/oiweiwei/gokrb5.fork/v9/client"
)

// contextKDCDialer implements krbclient.KDCDialer, binding every KDC/TGS
// dial gokrb5 performs (e.g. from GetServiceTicket during InitSecContext) to
// ctx.
//
// gokrb5's default KDCDialer (github.com/oiweiwei/gokrb5.fork/v9/client,
// Settings.Dialer) is a bare *net.Dialer with a fixed 5-minute Timeout and no
// awareness of the caller's context; it also always sets a hardcoded
// now+5s read/write deadline on the connections it dials (see
// client/network.go's dialSendTCP/dialSendUDP) regardless of how much time
// the caller actually has left. Without this dialer, a canceled or expired
// candidate context would not interrupt an in-flight KDC round-trip or any
// subsequent KDC/referral attempt, and could block for up to 5 minutes on the
// dial alone.
func newContextKDCDialer(ctx context.Context) krbclient.KDCDialer {
	return &contextKDCDialer{ctx: ctx}
}

type contextKDCDialer struct {
	ctx    context.Context
	dialer net.Dialer
}

// Dial implements krbclient.KDCDialer. It uses net.Dialer.DialContext so the
// dial itself is interrupted by ctx cancellation/deadline, and wraps the
// resulting connection so post-dial reads/writes are interrupted too.
func (d *contextKDCDialer) Dial(network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(d.ctx, network, address)
	if err != nil {
		return nil, err
	}
	contextConn := newContextConn(d.ctx, conn)
	if packetConn, ok := conn.(net.PacketConn); ok {
		return &contextPacketConn{contextConn: contextConn, packetConn: packetConn}, nil
	}
	return contextConn, nil
}

// contextConn wraps a net.Conn so that:
//   - ctx cancellation or deadline expiry sets an immediate deadline on the
//     underlying connection, interrupting any in-flight Read/Write;
//   - deadlines requested via SetDeadline/SetReadDeadline/SetWriteDeadline are
//     capped to ctx's deadline (if any), so a caller that sets its own fixed
//     deadline (as gokrb5 does: now+5s on every KDC request) cannot outlive
//     the context;
//   - Close stops the context.AfterFunc watching ctx, so the watch does not
//     outlive the connection and no goroutine/registration is leaked.
type contextConn struct {
	net.Conn
	ctx       context.Context
	closeOnce sync.Once
	closeErr  error
	stop      func() bool
}

func newContextConn(ctx context.Context, conn net.Conn) *contextConn {
	c := &contextConn{Conn: conn, ctx: ctx}
	c.stop = context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	return c
}

// capDeadline lowers t to ctx's deadline when ctx has one that is earlier
// (including when t is the zero Time, meaning "no deadline").
func (c *contextConn) capDeadline(t time.Time) time.Time {
	if c.ctx.Err() != nil {
		return time.Now()
	}
	if deadline, ok := c.ctx.Deadline(); ok && (t.IsZero() || deadline.Before(t)) {
		return deadline
	}
	return t
}

func (c *contextConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(c.capDeadline(t))
}

func (c *contextConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(c.capDeadline(t))
}

func (c *contextConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(c.capDeadline(t))
}

// Close stops watching ctx before closing the underlying connection, so the
// context.AfterFunc registration is released as soon as the connection is no
// longer used.
func (c *contextConn) Close() error {
	c.closeOnce.Do(func() {
		c.stop()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

// contextPacketConn preserves net.PacketConn for UDP KDC requests while
// applying context deadlines through contextConn.
type contextPacketConn struct {
	*contextConn
	packetConn net.PacketConn
}

func (c *contextPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.packetConn.ReadFrom(p)
}

func (c *contextPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.packetConn.WriteTo(p, addr)
}
