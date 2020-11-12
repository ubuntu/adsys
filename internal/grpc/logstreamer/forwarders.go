package log

import (
	"sync"

	"google.golang.org/grpc"
)

var (
	streamsForwarders streamsForwarder
)

type streamsForwarder struct {
	fw map[string]grpc.Stream
	mu sync.RWMutex

	once sync.Once
}

// AddStreamToForward adds stream identified by ID to forward all logs to it.
func AddStreamToForward(id string, ss grpc.Stream) {
	// Initialize our forwarder
	streamsForwarders.once.Do(func() {
		streamsForwarders.fw = make(map[string]grpc.Stream)
	})

	streamsForwarders.mu.Lock()
	defer streamsForwarders.mu.Unlock()
	streamsForwarders.fw[id] = ss
}

// RemoveStreamToForward remove stream identified by ID which was forwarding all logs to it.
func RemoveStreamToForward(id string) {
	streamsForwarders.mu.Lock()
	defer streamsForwarders.mu.Unlock()
	delete(streamsForwarders.fw, id)
}
