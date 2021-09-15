package log

import (
	"sync"

	"google.golang.org/grpc"
)

var (
	streamsForwarders streamsForwarder
)

type streamsForwarder struct {
	fw         map[streamWithCaller]bool
	mu         sync.RWMutex
	showCaller bool

	once sync.Once
}

type streamWithCaller struct {
	grpc.ServerStream
	showCaller bool
}

// AddStreamToForward adds stream identified to forward all logs to it.
func AddStreamToForward(stream grpc.ServerStream) (disconnect func()) {
	// Initialize our forwarder
	streamsForwarders.once.Do(func() {
		streamsForwarders.mu.Lock()
		streamsForwarders.fw = make(map[streamWithCaller]bool)
		streamsForwarders.mu.Unlock()
	})

	var showCaller bool
	if logCtx, withLogCtx := stream.Context().Value(logContextKey).(logContext); withLogCtx {
		showCaller = logCtx.withCallerForRemote
	}

	streamsForwarders.mu.Lock()
	defer streamsForwarders.mu.Unlock()
	streamWcaller := streamWithCaller{
		ServerStream: stream,
		showCaller:   showCaller,
	}
	streamsForwarders.fw[streamWcaller] = true
	streamsForwarders.showCaller = showCaller || streamsForwarders.showCaller

	return func() {
		streamsForwarders.mu.Lock()
		defer streamsForwarders.mu.Unlock()
		delete(streamsForwarders.fw, streamWcaller)
		// reupdate global showCaller based on remaining streamForwards
		var showCaller bool
		for stream := range streamsForwarders.fw {
			if stream.showCaller {
				showCaller = true
				break
			}
		}
		streamsForwarders.showCaller = showCaller
	}
}

// RemoveAllStreams flushes all streams from the existing forwarders.
func RemoveAllStreams() {
	streamsForwarders.mu.Lock()
	defer streamsForwarders.mu.Unlock()

	streamsForwarders.fw = make(map[streamWithCaller]bool)
}
