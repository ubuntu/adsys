package stdforward_test

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/stdforward"
)

func TestAddStdoutForwarder(t *testing.T) {
	// We don’t use a goroutine to streamline the tests. We control what we send and won’t overload the pipe buffer.
	stdErrText := "content on stderr"
	commonText := "content on stdout and writer"
	stdoutOnlyText := "|content only on stdout"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)
	defer restoreStdout()
	stderrReader, restoreStderr := fileToReader(t, &os.Stderr)
	defer restoreStderr()

	// 1. Hook up the writer
	var myWriter strings.Builder
	restore, err := stdforward.AddStdoutWriter(&myWriter)
	require.NoError(t, err, "AddStdoutWriter should add myWriter")

	// 2. Write common text
	fmt.Print(commonText)
	fmt.Fprint(os.Stderr, stdErrText)
	time.Sleep(time.Millisecond) // Let the copy in io.Copy goroutine to proceed

	// 3. Disconnect the writer
	restore()

	// 4. Write now again, only stdout should capture it
	fmt.Print(stdoutOnlyText)
	time.Sleep(time.Millisecond)

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStdout()
	restoreStderr()

	// Check content
	assert.Equal(t, commonText+stdoutOnlyText, stringFromOpenedReader(t, stdoutReader), "Both messages are on stdout")
	assert.Equal(t, commonText, myWriter.String(), "Only message before remove() is in our custom writer")
	assert.Equal(t, stdErrText, stringFromOpenedReader(t, stderrReader), "Nothing was sent on stderr")
}

// TODO: test close before restore myWriter.Close()
// with another writer, should still forward

// multiple writers
// some removed in between

// stdout fail or stuck
// -> writer still get the message

// one writer fail or stuck
// -> other writers and stdout still get the message

// stderr and stdout separated

func fileToReader(t *testing.T, f **os.File) (io.Reader, func()) {
	t.Helper()

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		require.NoError(t, err, "Setup issue while creating pipe")
	}

	origStdout := *f
	*f = stdoutWriter

	// Only restore once (defer or direct call)
	once := sync.Once{}
	return stdoutReader, func() {
		once.Do(func() {
			*f = origStdout
			stdoutWriter.Close()
		})
	}
}

func stringFromOpenedReader(t *testing.T, r io.Reader) string {
	t.Helper()

	data := make([]byte, 1024)
	n, err := r.Read(data)
	require.NoError(t, err, "No error while reading stdout content")
	return string(data[:n])
}
