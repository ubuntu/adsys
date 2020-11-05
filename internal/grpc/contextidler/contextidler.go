package contextidler

import (
	"context"
	"io"
	"time"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxDuration = time.Duration(1<<63 - 1)
)

// StreamClientInterceptor allows to tag the client with an unique ID and request the server
// to stream back to the client logs corresponding to that request to the given logger.
// It will use ReportCaller value from logger to decide if we print the call	ck (first frame outside
// of that package)
func StreamClientInterceptor(timeout time.Duration) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx, cancel := context.WithCancel(ctx)

		if timeout == 0 {
			timeout = maxDuration
		}
		timer := time.NewTimer(timeout)

		go func() {
			select {
			case <-timer.C:
				log.Debug(context.Background(), "hasn't received response from the server timely. Cancelling Request")
				cancel()
			// Something else cancelled the context, like Ctrl+C on client
			case <-ctx.Done():
			}
		}()

		clientStream, err := streamer(ctx, desc, cc, method, opts...)
		return &idlerClientStream{
			ClientStream: clientStream,

			timer:   timer,
			timeout: timeout,
		}, err
	}
}

type idlerClientStream struct {
	grpc.ClientStream
	timer   *time.Timer
	timeout time.Duration
}

// RecvMsg is used to reset the timer as we got a new messages.
// If we get an error from server, it will analyze the kind of error transform it appropriately,
// after ensuring the timer is stopped.
// 1. If the error isn’t a cancellation error, returns it raw.
// 2. If the error is a cancellation error and the timer was already been stopped: this was a timeout,
//    transform it as cancellation.
// 3. If the error is a cancellation error and the timer wasn’t stopped, this is a client cancellation
//    being requested (like Ctrl+C), returns then EOF.
func (ss *idlerClientStream) RecvMsg(m interface{}) error {
	if err := ss.ClientStream.RecvMsg(m); err != nil {
		// Transform grpc context cancel deadline if this is what we got.
		st := status.Convert(err)

		// The timer timed out (as nothing else will stop it concurrently).
		// The error can be a concurrent server error OR the timeout, cast it in the latter case only.
		if !ss.timer.Stop() {
			// optionally drain the channel (if this is an error sent by the server just before getting the timeout)
			select {
			case <-ss.timer.C:
			default:
			}

			if st.Code() == codes.Canceled {
				err = status.Error(codes.DeadlineExceeded, st.Message())
			}
			return err
		}

		// We stopped the timer, so if there was a cancellation,
		// this is client cancellation (under our control), but not timeout.
		if st.Code() == codes.Canceled {
			err = io.EOF
		}
		return err
	}

	// Stop the timer and drain the channel before resetting it
	if !ss.timer.Stop() {
		<-ss.timer.C
	}
	ss.timer.Reset(ss.timeout)
	return nil
}
