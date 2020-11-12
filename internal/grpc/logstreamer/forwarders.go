package log

import (
	"sync"

	"google.golang.org/grpc"
)

var (
	streamsForwarders streamsForwarder
)

type streamsForwarder struct {
	fw map[grpc.Stream]bool
	mu sync.RWMutex

	once sync.Once
}

// AddStreamToForward adds stream identified to forward all logs to it.
func AddStreamToForward(stream grpc.Stream) func() {
	// Initialize our forwarder
	streamsForwarders.once.Do(func() {
		streamsForwarders.fw = make(map[grpc.Stream]bool)
	})

	streamsForwarders.mu.Lock()
	defer streamsForwarders.mu.Unlock()
	streamsForwarders.fw[stream] = true

	return func() {
		streamsForwarders.mu.Lock()
		defer streamsForwarders.mu.Unlock()
		delete(streamsForwarders.fw, stream)
	}
}
