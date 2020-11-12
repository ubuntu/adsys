package log

import (
	"sync"

	"google.golang.org/grpc"
)

var (
	streamsForwarders streamsForwarder
)

type streamsForwarder struct {
	fw map[streamWithCaller]bool
	mu sync.RWMutex

	once sync.Once
}

type streamWithCaller struct {
	grpc.Stream
	wantsCaller bool
}

// AddStreamToForward adds stream identified to forward all logs to it.
func AddStreamToForward(stream grpc.Stream) func() {
	// Initialize our forwarder
	streamsForwarders.once.Do(func() {
		streamsForwarders.fw = make(map[streamWithCaller]bool)
	})

	var wantsCaller bool
	if logCtx, withLogCtx := stream.Context().Value(logContextKey).(logContext); withLogCtx {
		wantsCaller = logCtx.withCallerForRemote
	}

	streamsForwarders.mu.Lock()
	defer streamsForwarders.mu.Unlock()
	streamWcaller := streamWithCaller{
		Stream:      stream,
		wantsCaller: wantsCaller,
	}
	streamsForwarders.fw[streamWcaller] = true

	return func() {
		streamsForwarders.mu.Lock()
		defer streamsForwarders.mu.Unlock()
		delete(streamsForwarders.fw, streamWcaller)
	}
}

func (sf *streamsForwarder) wantsCaller() bool {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	for stream := range sf.fw {
		if stream.wantsCaller {
			return true
		}
	}
	return false
}
