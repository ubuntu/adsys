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
//
// Cancellation and every SetDeadline/SetReadDeadline/SetWriteDeadline call
// are serialized through mu so that, once ctx is canceled, no deadline
// requested concurrently or afterwards can extend I/O past that
// cancellation. Without this, a caller's SetDeadline could decide on a
// future deadline while ctx is still live, then actually apply it to the
// underlying connection after the cancellation callback has already set an
// immediate deadline, silently reverting the cancellation. mu is only held
// across the (fast, non-blocking) underlying SetDeadline call itself, never
// across Read/Write, so it cannot deadlock against in-flight I/O.
type contextConn struct {
	net.Conn
	ctx       context.Context
	closeOnce sync.Once
	closeErr  error
	stop      func() bool

	mu       sync.Mutex
	canceled bool
}

func newContextConn(ctx context.Context, conn net.Conn) *contextConn {
	c := &contextConn{Conn: conn, ctx: ctx}
	c.stop = context.AfterFunc(ctx, c.cancel)
	return c
}

// cancel is invoked once ctx is done. It marks the connection as canceled
// and sets an immediate deadline on the underlying connection, all while
// holding mu so that no concurrent SetDeadline call can race with it: either
// the SetDeadline call completes first (and cancel then applies the
// immediate deadline afterwards, overriding it) or cancel completes first
// (and the SetDeadline call then observes canceled and refuses to extend).
func (c *contextConn) cancel() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.canceled = true
	_ = c.Conn.SetDeadline(time.Now())
}

// applyDeadline decides the effective deadline for a SetDeadline-family call
// and applies it via set, atomically with respect to cancel: once ctx is
// canceled (observed either through c.canceled or c.ctx.Err()), the
// requested deadline t is ignored and an immediate deadline is applied
// instead, so a stale decision made before cancellation can never overwrite
// it.
func (c *contextConn) applyDeadline(set func(time.Time) error, t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.canceled || c.ctx.Err() != nil {
		c.canceled = true
		return set(time.Now())
	}
	if deadline, ok := c.ctx.Deadline(); ok && (t.IsZero() || deadline.Before(t)) {
		t = deadline
	}
	return set(t)
}

func (c *contextConn) SetDeadline(t time.Time) error {
	return c.applyDeadline(c.Conn.SetDeadline, t)
}

func (c *contextConn) SetReadDeadline(t time.Time) error {
	return c.applyDeadline(c.Conn.SetReadDeadline, t)
}

func (c *contextConn) SetWriteDeadline(t time.Time) error {
	return c.applyDeadline(c.Conn.SetWriteDeadline, t)
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
