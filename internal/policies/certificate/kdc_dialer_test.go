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
