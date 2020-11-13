package stdforward

import (
	"fmt"
	"io"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
)

// stdforward will forward to any number of writers the messages on Stdout and StdErr.
// contrary to multiwriters, the list can go and shrink dynamically.

var (
	stdoutForwarder, stderrForwarder forwarder
)

type forwarder struct {
	out     *os.File
	writers map[io.Writer]bool
	mu      sync.RWMutex

	once sync.Once
}

func (f *forwarder) Write(p []byte) (int, error) {
	// Write to regular output first
	n, err := f.out.Write(p)
	if err != nil {
		log.Warningf("Failed to write to regular output: %v", err)
	}

	// Now, forward to any registered writers
	f.mu.RLock()
	defer f.mu.RUnlock()
	for w := range f.writers {
		if _, err := w.Write(p); err != nil {
			log.Warningf("Failed to forward logs: %v", err)
		}
	}

	return n, nil
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

func addWriter(dest *forwarder, std **os.File, w io.Writer) (func(), error) {
	// Initialize our forwarder
	var onceErr error

	// we can change the number of children, but also reinitialize the forwarder
	dest.mu.Lock()
	defer dest.mu.Unlock()
	dest.once.Do(func() {
		dest.out = *std
		dest.writers = make(map[io.Writer]bool)

		rOut, wOut, err := os.Pipe()
		if err != nil {
			onceErr = fmt.Errorf("Can't redirect output: %v", err)
			return
		}

		go func() {
			if _, err = io.Copy(dest, rOut); err != nil {
				log.Warningf("Forwarding some messages failed: %v", err)
			}
		}()

		*std = wOut
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
			w := *std
			*std = dest.out
			w.Close()

			// reset std forwarder to be ready for reinitialization
			*&dest.once = sync.Once{}
		}

	}, nil
}
