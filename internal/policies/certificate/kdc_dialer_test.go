package certificate

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContextKDCDialerDialCancellation(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = newContextKDCDialer(ctx).Dial("tcp", ln.Addr().String())
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestContextKDCDialerPreservesPacketConn(t *testing.T) {
	t.Parallel()

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()

	conn, err := newContextKDCDialer(context.Background()).Dial("udp", server.LocalAddr().String())
	require.NoError(t, err)
	defer conn.Close()

	assert.Implements(t, (*net.PacketConn)(nil), conn)
}

func TestContextConnCancellationInterruptsInFlightIO(t *testing.T) {
	t.Parallel()

	tests := map[string]func(net.Conn) error{
		"read": func(conn net.Conn) error {
			_, err := conn.Read(make([]byte, 1))
			return err
		},
		"write": func(conn net.Conn) error {
			_, err := conn.Write([]byte{0})
			return err
		},
	}

	for name, operation := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()

			started := make(chan struct{})
			signalingConn := &ioSignalingConn{Conn: clientConn, started: started}
			ctx, cancel := context.WithCancel(context.Background())
			wrapped := newContextConn(ctx, signalingConn)
			defer wrapped.Close()

			ioErr := make(chan error, 1)
			go func() {
				ioErr <- operation(wrapped)
			}()

			<-started
			cancel()

			select {
			case err := <-ioErr:
				assert.Error(t, err)
			case <-time.After(2 * time.Second):
				t.Fatal("I/O did not return after context cancellation")
			}
		})
	}
}

func TestContextConnCapsDeadlineToContext(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	ctxDeadline := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(context.Background(), ctxDeadline)
	recordingConn := &deadlineRecordingConn{Conn: clientConn}
	wrapped := newContextConn(ctx, recordingConn)
	defer func() {
		wrapped.Close()
		cancel()
	}()

	require.NoError(t, wrapped.SetDeadline(ctxDeadline.Add(time.Hour)))
	assert.Equal(t, ctxDeadline, recordingConn.lastDeadline())
}

func TestContextConnCanceledContextCannotExtendDeadline(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recordingConn := &deadlineRecordingConn{Conn: clientConn}
	wrapped := &contextConn{
		Conn: recordingConn,
		ctx:  ctx,
		stop: func() bool { return true },
	}

	before := time.Now()
	require.NoError(t, wrapped.SetDeadline(before.Add(time.Hour)))
	assert.WithinDuration(t, before, recordingConn.lastDeadline(), time.Second)
}

// TestContextConnCancellationRaceCannotExtendDeadline deterministically forces
// the exact interleaving that used to let a concurrent SetDeadline call
// overwrite a cancellation: a SetDeadline call decides its deadline while ctx
// is still live (so it would extend the deadline into the future), but is
// paused with the lock held right before it reaches the underlying
// connection. Cancellation is triggered while that call is paused there, and
// only afterwards is the paused call allowed to finish applying its (stale)
// future deadline. If cancellation and SetDeadline were not serialized, the
// paused call's future deadline could be applied after cancellation's
// immediate one, silently reverting it. This test proves the final applied
// deadline is never extended past cancellation, regardless of which
// goroutine's underlying SetDeadline call happens to run last.
func TestContextConnCancellationRaceCannotExtendDeadline(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	blocking := &blockingFirstDeadlineConn{Conn: clientConn, entered: make(chan struct{}), release: make(chan struct{})}

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	wrapped := newContextConn(ctx, blocking)
	defer wrapped.Close()

	future := time.Now().Add(time.Hour)
	setDeadlineErr := make(chan error, 1)
	go func() {
		// This call reads ctx as not-yet-canceled and decides to extend the
		// deadline to "future", then blocks (still holding wrapped's
		// internal lock) right before actually applying it to the
		// underlying connection.
		setDeadlineErr <- wrapped.SetDeadline(future)
	}()

	// Wait until the goroutine above is paused inside the underlying
	// SetDeadline call, holding wrapped's lock.
	<-blocking.entered

	// Trigger cancellation while the future deadline is still in flight and
	// unapplied. cancel() must block on the same lock until the paused call
	// above releases it.
	cancelDone := make(chan struct{})
	go func() {
		wrapped.cancel()
		close(cancelDone)
	}()

	// Let the paused SetDeadline(future) call proceed and finish applying
	// its stale decision.
	close(blocking.release)

	require.NoError(t, <-setDeadlineErr)
	<-cancelDone

	// No matter the interleaving between the two underlying SetDeadline
	// calls, the final applied deadline must never be the extended future
	// value: cancellation must always win.
	final := blocking.lastDeadline()
	assert.NotEqual(t, future, final)
	assert.WithinDuration(t, time.Now(), final, 5*time.Second)
}

func TestContextConnCloseStopsContextWatch(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	stopCalls := 0
	wrapped := &contextConn{
		Conn: clientConn,
		ctx:  context.Background(),
		stop: func() bool {
			stopCalls++
			return true
		},
	}

	require.NoError(t, wrapped.Close())
	require.NoError(t, wrapped.Close())
	assert.Equal(t, 1, stopCalls)
}

type ioSignalingConn struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (c *ioSignalingConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(p)
}

func (c *ioSignalingConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

type deadlineRecordingConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

func (c *deadlineRecordingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *deadlineRecordingConn) lastDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}

// blockingFirstDeadlineConn records every deadline passed to SetDeadline,
// like deadlineRecordingConn, but pauses the very first call right after
// recording it and before returning, signaling entered once it is paused and
// waiting on release. Every subsequent call proceeds immediately without
// pausing. This lets a test deterministically force a decided-but-not-yet-
// applied SetDeadline call to overlap with a concurrent cancellation.
type blockingFirstDeadlineConn struct {
	net.Conn
	mu         sync.Mutex
	deadline   time.Time
	blockedYet bool
	entered    chan struct{}
	release    chan struct{}
}

func (c *blockingFirstDeadlineConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	first := !c.blockedYet
	c.blockedYet = true
	c.deadline = t
	c.mu.Unlock()

	if first {
		close(c.entered)
		<-c.release
	}
	return c.Conn.SetDeadline(t)
}

func (c *blockingFirstDeadlineConn) lastDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}
