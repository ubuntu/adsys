// Package stdforward handles the totality of process stdout and stderr forwarding to one or multiple writers.
//
// This is used to connect one or multiple GRPC stream writers.
package stdforward

import (
	"io"
	"os"
	"sync"

	"github.com/leonelquinteros/gotext"
	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/decorate"
)

// stdforward will forward to any number of writers the messages on Stdout and StdErr.
// contrary to multiwriters, the list can go and shrink dynamically.

var (
	stdoutForwarder, stderrForwarder forwarder
)

type forwarder struct {
	out      *os.File
	capturer *os.File
	writers  map[io.Writer]bool
	mu       sync.RWMutex

	// setupMu serializes the initialization and the teardown of the forwarder.
	// Contrary to mu, it is never taken by Write(), so it can be held while
	// waiting for the io.Copy goroutine to finish.
	setupMu sync.Mutex

	// wgIOCopy tracks the io.Copy goroutine draining the capturer. It belongs to
	// the forwarder and not to a given addWriter call, as the writer tearing the
	// forwarder down is not necessarily the one that initialized it.
	wgIOCopy sync.WaitGroup

	once sync.Once
}

func (f *forwarder) Write(p []byte) (int, error) {
	// Write to regular output first
	if _, err := f.out.Write(p); err != nil {
		log.Warningf("Failed to write to regular output: %v", err)
	}

	// Now, forward to any registered writers
	f.mu.RLock()
	defer f.mu.RUnlock()
	for w := range f.writers {
		if _, err := w.Write(p); err != nil {
			log.Warningf("Failed to forward log: %v", err)
		}
	}

	return len(p), nil
}

// AddStdoutWriter will forward stdout to writer (and all previous writers).
// First call switch Stdout to intercept any calls and forward it. Anything that
// referenced beforehand os.Stdout directly and captured it will thus
// not be forwarded.
// It returns a function to unsubcribe the writer.
func AddStdoutWriter(w io.Writer) (remove func(), err error) {
	return addWriter(&stdoutForwarder, &os.Stdout, w)
}

// AddStderrWriter will forward stderr to writer (and all previous writers).
// First call switch Stderr to intercept any calls and forward it. Anything that
// referenced beforehand os.Stderr directly and captured it will thus
// not be forwarded.
// It returns a function to unsubcribe the writer.
func AddStderrWriter(w io.Writer) (remove func(), err error) {
	return addWriter(&stderrForwarder, &os.Stderr, w)
}

func addWriter(dest *forwarder, std **os.File, w io.Writer) (f func(), err error) {
	defer decorate.OnError(&err, gotext.Get("can't redirect output"))

	// Initialize our forwarder
	var onceErr error

	// Initialization and teardown must not interleave, otherwise a writer
	// subscribing while the last one tears the forwarder down would attach to a
	// forwarder that is being dismantled.
	dest.setupMu.Lock()
	defer dest.setupMu.Unlock()

	// we can change the number of children, but also reinitialize the forwarder
	dest.mu.Lock()
	dest.once.Do(func() {
		dest.out = *std
		dest.writers = make(map[io.Writer]bool)

		rOut, wOut, err := os.Pipe()
		if err != nil {
			onceErr = err
			return
		}
		dest.capturer = wOut
		dest.wgIOCopy.Add(1)

		go func() {
			defer dest.wgIOCopy.Done()
			if _, err := io.Copy(dest, rOut); err != nil {
				log.Warningf("We couldn’t forward all messages: %v", err)
			}
		}()

		*std = dest.capturer
	})
	if onceErr != nil {
		// Let a subsequent call retry the initialization.
		dest.once = sync.Once{}
		dest.mu.Unlock()
		return nil, onceErr
	}

	dest.writers[w] = true
	dest.mu.Unlock()

	return func() {
		dest.setupMu.Lock()
		defer dest.setupMu.Unlock()

		dest.mu.Lock()

		// Already removed: nothing to unsubscribe nor to tear down.
		if !dest.writers[w] {
			dest.mu.Unlock()
			return
		}

		// Other writers are still subscribed: only unsubscribe this one and keep
		// the forwarder running for them.
		if len(dest.writers) > 1 {
			delete(dest.writers, w)
			dest.mu.Unlock()
			return
		}

		// Last writer: restore std so that new messages go to the regular output
		// directly, then close the capturer to make io.Copy drain and return.
		*std = dest.out
		capturer := dest.capturer
		dest.mu.Unlock()

		if capturer != nil {
			decorate.LogFuncOnError(capturer.Close)
		}

		// Wait for io.Copy to flush the messages still buffered in the pipe. This
		// must happen without holding the lock: forwarding them goes through
		// Write(), which takes the read lock, and would otherwise deadlock.
		dest.wgIOCopy.Wait()

		dest.mu.Lock()
		defer dest.mu.Unlock()

		delete(dest.writers, w)
		dest.capturer = nil

		// reset std forwarder to be ready for reinitialization
		dest.once = sync.Once{}
	}, nil
}
