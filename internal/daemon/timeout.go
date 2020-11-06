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

type idler struct {
	timeout time.Duration

	timer *time.Timer

	currentRequests int
	mu              sync.Mutex
}

func newIdler(timeout time.Duration) idler {
	if timeout == 0 {
		timeout = maxDuration
	}
	return idler{
		timeout: timeout,
		timer:   time.NewTimer(timeout),
	}

}

func (i *idler) checkTimeout(d *Daemon) {
	<-i.timer.C
	log.Debug(context.Background(), "idling timeout expired")
	d.Quit()
}

func (i *idler) OnNewConnection(_ context.Context, info *grpc.StreamServerInfo) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.currentRequests++

	// Stop can return false if the timeout has fired OR if it's already stopped.
	// Base on currentRequests number to decide if we need to drain the timer channel
	// if the timeout has already fired.
	if i.currentRequests == 1 && !i.timer.Stop() {
		<-i.timer.C
	}
}

func (i *idler) OnDoneConnection(_ context.Context, info *grpc.StreamServerInfo) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.currentRequests--
	if i.currentRequests > 0 {
		return
	}

	i.timer.Reset(i.timeout)
}
