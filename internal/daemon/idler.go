package daemon

import (
	"context"
	"sync"
	"time"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"google.golang.org/grpc"
)

const (
	maxDuration = time.Duration(1<<63 - 1)
)

type operation int

const (
	stopTimeout operation = iota
	startTimeout
	quitGracefully
	quitNow
)

type idler struct {
	timeout time.Duration

	timer *time.Timer

	operations      chan operation
	currentRequests int
	mu              sync.Mutex
}

func newIdler(timeout time.Duration) idler {
	if timeout == 0 {
		timeout = maxDuration
	}
	return idler{
		timeout:    timeout,
		timer:      time.NewTimer(timeout),
		operations: make(chan operation),
	}
}

func (i *idler) keepAlive(d *Daemon) {
	// we need to proceed any timer event in the same goroutine to avoid races.
out:
	for {
		select {
		case <-i.timer.C:
			log.Debug(context.Background(), "idling timeout expired")
			// as the receiver of the signal sent is this loop, we need to run that in a separate goroutine.
			go d.Quit(true)
		case o := <-i.operations:
			switch o {
			case stopTimeout:
				if !i.timer.Stop() {
					<-i.timer.C
				}
			case startTimeout:
				i.timer.Reset(i.timeout)
			case quitGracefully:
				d.stop(false)
				break out
			case quitNow:
				d.stop(true)
				break out
			}
		}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	close(i.operations)
	i.operations = nil
}

func (i *idler) OnNewConnection(_ context.Context, info *grpc.StreamServerInfo) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.currentRequests++
	if i.currentRequests != 1 {
		return
	}

	i.sendOrTimeout(stopTimeout)
}

func (i *idler) OnDoneConnection(_ context.Context, info *grpc.StreamServerInfo) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.currentRequests--
	if i.currentRequests > 0 {
		return
	}

	i.sendOrTimeout(startTimeout)
}

// ChangeTimeout changes and reset idling timeout time.
func (i *idler) ChangeTimeout(d time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// the mutex ensures you nothing is calling in between the 2 channel send
	i.sendOrTimeout(stopTimeout)
	i.timeout = d
	i.sendOrTimeout(startTimeout)
}

func (i *idler) sendOrTimeout(op operation) {
	select {
	case i.operations <- op:
	case <-time.After(1 * time.Second):
	}
}

// Timeout returns current daemon idle timeout.
func (i *idler) Timeout() time.Duration {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.timeout
}
