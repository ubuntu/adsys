package stdforward

import (
	"io"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
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
	defer decorate.OnError(&err, i18n.G("can't redirect output"))

	// Initialize our forwarder
	var onceErr error

	// Wait on teardown for io.Copy to finish
	wgIOCopy := sync.WaitGroup{}

	// we can change the number of children, but also reinitialize the forwarder
	dest.mu.Lock()
	defer dest.mu.Unlock()
	dest.once.Do(func() {
		dest.out = *std
		dest.writers = make(map[io.Writer]bool)

		rOut, wOut, err := os.Pipe()
		dest.capturer = wOut
		if err != nil {
			onceErr = err
			return
		}
		wgIOCopy.Add(1)

		go func() {
			defer wgIOCopy.Done()
			if _, err = io.Copy(dest, rOut); err != nil {
				log.Warningf("We couldn’t forward all messages: %v", err)
			}
		}()

		*std = dest.capturer
	})
	if onceErr != nil {
		return nil, onceErr
	}

	dest.writers[w] = true

	return func() {
		dest.mu.Lock()
		defer dest.mu.Unlock()

		delete(dest.writers, w)

		// restore std and unblock goroutine
		if len(dest.writers) == 0 {
			*std = dest.out
			decorate.LogFuncOnError(dest.capturer.Close)
			wgIOCopy.Wait()

			// reset std forwarder to be ready for reinitialization
			dest.once = sync.Once{}
		}
	}, nil
}
