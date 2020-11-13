package stdforward_test

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/stdforward"
)

// TODO: can we do better?
const durationForFlushingIoCopy = 2 * time.Millisecond

func TestAddStdoutForwarder(t *testing.T) {
	// We don’t use a goroutine to streamline the tests. We control what we send and won’t overload the pipe buffer.
	commonText := "content on stdout and writer"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)
	defer restoreStdout()

	// 1. Hook up the writer
	var myWriter strings.Builder
	restore, err := stdforward.AddStdoutWriter(&myWriter)
	require.NoError(t, err, "AddStdoutWriter should add myWriter")

	// 2. Write common text twice
	fmt.Print(commonText)
	fmt.Print(commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 3. Disconnect the writer
	restore()

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStdout()

	// Check content
	assert.Equal(t, commonText+commonText, stringFromReader(t, stdoutReader), "Both messages are on stdout")
	assert.Equal(t, commonText+commonText, myWriter.String(), "Both messages are on the custom writer")
}

func TestAddStdoutForwarderAndDisconnect(t *testing.T) {
	commonText := "content on stdout and writer"
	stdoutOnlyText := "|content only on stdout"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)
	defer restoreStdout()

	// 1. Hook up the writer
	var myWriter strings.Builder
	restore, err := stdforward.AddStdoutWriter(&myWriter)
	require.NoError(t, err, "AddStdoutWriter should add myWriter")

	// 2. Write common text
	fmt.Print(commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 3. Disconnect the writer
	restore()

	// 4. Write now again, only stdout should capture it
	fmt.Print(stdoutOnlyText)
	time.Sleep(durationForFlushingIoCopy)

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStdout()

	// Check content
	assert.Equal(t, commonText+stdoutOnlyText, stringFromReader(t, stdoutReader), "Both messages are on stdout")
	assert.Equal(t, commonText, myWriter.String(), "Only message before remove() is in our custom writer")
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

func stringFromReader(t *testing.T, r io.Reader) string {
	t.Helper()

	data, err := ioutil.ReadAll(r)
	require.NoError(t, err, "No error while reading stdout content")
	return string(data)
}
