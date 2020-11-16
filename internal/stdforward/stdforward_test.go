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

func TestAddStderrForwarder(t *testing.T) {
	commonText := "content on stderr and writer"

	stderrReader, restoreStderr := fileToReader(t, &os.Stderr)
	defer restoreStderr()

	// 1. Hook up the writer
	var myWriter strings.Builder
	restore, err := stdforward.AddStderrWriter(&myWriter)
	require.NoError(t, err, "AddStderrWriter should add myWriter")

	// 2. Write common text twice
	fmt.Fprint(os.Stderr, commonText)
	fmt.Fprint(os.Stderr, commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 3. Disconnect the writer
	restore()

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStderr()

	// Check content
	assert.Equal(t, commonText+commonText, stringFromReader(t, stderrReader), "Both messages are on stderr")
	assert.Equal(t, commonText+commonText, myWriter.String(), "Both messages are on the custom writer")
}

func TestAddStdoutForwarderEnsureStderrNoPolluted(t *testing.T) {
	stdOutText := "content on stdout and writer"
	stdErrText := "content on stderr"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)
	defer restoreStdout()
	stderrReader, restoreStderr := fileToReader(t, &os.Stderr)
	defer restoreStderr()

	// 1. Hook up the writer
	var myWriter strings.Builder
	restore, err := stdforward.AddStdoutWriter(&myWriter)
	require.NoError(t, err, "AddStdoutWriter should add myWriter")

	// 2. Write text
	fmt.Print(stdOutText)
	fmt.Fprint(os.Stderr, stdErrText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 3. Disconnect the writer
	restore()

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStdout()
	restoreStderr()

	// Check content
	assert.Equal(t, stdOutText, stringFromReader(t, stdoutReader), "Message is on stdout")
	assert.Equal(t, stdOutText, myWriter.String(), "Message for stdout is on the custom writer")
	assert.Equal(t, stdErrText, stringFromReader(t, stderrReader), "Nothing was sent on stderr")
}

func TestAddForwarderAndDisconnect(t *testing.T) {
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

func TestAddForwardersGraduallyAndDisconnect(t *testing.T) {
	text1 := "content 1"
	text2 := "|content 2"
	text3 := "|content 3"

	_, restoreStdout := fileToReader(t, &os.Stdout)
	defer restoreStdout()

	// 1. Hook up the first writer and write first text
	var myWriter1 strings.Builder
	restore1, err := stdforward.AddStdoutWriter(&myWriter1)
	require.NoError(t, err, "AddStdoutWriter should add myWriter1")
	fmt.Print(text1)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 2. Hook up the second writer and write second text
	var myWriter2 strings.Builder
	restore2, err := stdforward.AddStdoutWriter(&myWriter2)
	require.NoError(t, err, "AddStdoutWriter should add myWriter1")
	fmt.Print(text2)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 2. Disconnect first writer and write third text
	restore1()
	time.Sleep(durationForFlushingIoCopy) // Let the time for first writer to disconnect
	fmt.Print(text3)
	// TODO: fix race…
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	restore2()

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStdout()

	// Check content
	assert.Equal(t, text1+text2, myWriter1.String(), "Writer1 contains first 2 messages")
	assert.Equal(t, text2+text3, myWriter2.String(), "Writer2 contains last 2 messages")
}

func TestAddForwarderDifferentWriterStdoutStderr(t *testing.T) {
	stdOutText := "content on stdout"
	stdErrText := "content on stderr"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)
	defer restoreStdout()
	stderrReader, restoreStderr := fileToReader(t, &os.Stderr)
	defer restoreStderr()

	// 1. Hook up the writer
	var myWriterStdout, myWriterStderr strings.Builder
	restoreWriterStdout, err := stdforward.AddStdoutWriter(&myWriterStdout)
	require.NoError(t, err, "AddStdoutWriter should add myWriter")
	restoreWriterStderr, err := stdforward.AddStderrWriter(&myWriterStderr)
	require.NoError(t, err, "AddStderrWriter should add myWriter")

	// 2. Write text
	fmt.Print(stdOutText)
	fmt.Fprint(os.Stderr, stdErrText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 3. Disconnect the writers
	restoreWriterStdout()
	restoreWriterStderr()

	// Restore stdout and stderr (and disconnect our Writer) for other tests
	restoreStdout()
	restoreStderr()

	// Check content
	assert.Equal(t, stdOutText, stringFromReader(t, stdoutReader), "Expected message on stdout")
	assert.Equal(t, stdOutText, myWriterStdout.String(), "Writer for stdout has only stdout content")
	assert.Equal(t, stdErrText, stringFromReader(t, stderrReader), "Expected message on stderr")
	assert.Equal(t, stdErrText, myWriterStderr.String(), "Writer for stderr has only stderr content")
}

func TestAddForwarderSameWriterStdoutStderr(t *testing.T) {
	stdOutText := "content on stdout"
	stdErrText := "content on stderr"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)
	defer restoreStdout()
	stderrReader, restoreStderr := fileToReader(t, &os.Stderr)
	defer restoreStderr()

	// 1. Hook up the writer
	var myWriter strings.Builder
	restoreWriterStdout, err := stdforward.AddStdoutWriter(&myWriter)
	require.NoError(t, err, "AddStdoutWriter should add myWriter")
	restoreWriterStderr, err := stdforward.AddStderrWriter(&myWriter)
	require.NoError(t, err, "AddStderrWriter should add myWriter")

	// 2. Write text
	fmt.Print(stdOutText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed
	fmt.Fprint(os.Stderr, stdErrText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 3. Disconnect the writers
	restoreWriterStdout()
	restoreWriterStderr()

	// Restore stdout and stderr (and disconnect our Writer) for other tests
	restoreStdout()
	restoreStderr()

	// Check content
	assert.Equal(t, stdOutText, stringFromReader(t, stdoutReader), "Expected message on stdout")
	assert.Equal(t, stdErrText, stringFromReader(t, stderrReader), "Expected message on stderr")
	assert.Equal(t, stdOutText+stdErrText, myWriter.String(), "Both messages are on the custom writer")
}

// TODO: one writer with capacity full (or closed): other writers should still forward
// with another writer, should still forward

// stdout fail or stuck
// -> writer still get the message

// one writer fail or stuck
// -> other writers and stdout still get the message

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
