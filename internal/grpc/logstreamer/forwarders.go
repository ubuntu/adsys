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
	grpc.Stream
	showCaller bool
}

// AddStreamToForward adds stream identified to forward all logs to it.
func AddStreamToForward(stream grpc.Stream) func() {
	// Initialize our forwarder
	streamsForwarders.once.Do(func() {
		streamsForwarders.fw = make(map[streamWithCaller]bool)
	})

	var showCaller bool
	if logCtx, withLogCtx := stream.Context().Value(logContextKey).(logContext); withLogCtx {
		showCaller = logCtx.withCallerForRemote
	}

	streamsForwarders.mu.Lock()
	defer streamsForwarders.mu.Unlock()
	streamWcaller := streamWithCaller{
		Stream:     stream,
		showCaller: showCaller,
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
