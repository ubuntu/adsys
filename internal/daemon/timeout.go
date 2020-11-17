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
	stop operation = iota
	start
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

func (i *idler) checkTimeout(d *Daemon) {
	// we need to proceed any timer event in the same goroutine to avoid races.
	for {
		select {
		case <-i.timer.C:
			log.Debug(context.Background(), "idling timeout expired")
			d.Quit()
			return
		case o := <-i.operations:
			switch o {
			case stop:
				if !i.timer.Stop() {
					<-i.timer.C
				}
			case start:
				i.timer.Reset(i.timeout)
			}
		}
	}
}

func (i *idler) OnNewConnection(_ context.Context, info *grpc.StreamServerInfo) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.currentRequests++
	if i.currentRequests != 1 {
		return
	}

	i.operations <- stop
}

func (i *idler) OnDoneConnection(_ context.Context, info *grpc.StreamServerInfo) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.currentRequests--
	if i.currentRequests > 0 {
		return
	}

	i.operations <- start
}

// ChangeTimeout changes and reset idling timeout time.
func (i *idler) ChangeTimeout(d time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.timeout = d
	// the mutex ensures you nothing is calling in between the 2 channel send
	i.operations <- stop
	i.operations <- start
}
