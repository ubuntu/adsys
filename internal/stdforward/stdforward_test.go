package stdforward_test

import (
	"errors"
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

// TODO: can we do better?
const durationForFlushingIoCopy = 2 * time.Millisecond

func TestAddStdoutForwarder(t *testing.T) {
	// We don’t use a goroutine to streamline the tests. We control what we send and won’t overload the pipe buffer.
	commonText := "content on stdout and writer"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)

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
	stderrReader, restoreStderr := fileToReader(t, &os.Stderr)

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
	stderrReader, restoreStderr := fileToReader(t, &os.Stderr)

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

type concurrentStringsBuilder struct {
	strings.Builder
	mu sync.Mutex
}

func (sb *concurrentStringsBuilder) Write(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.Builder.Write(p)
}

func TestAddForwarderSameWriterStdoutStderr(t *testing.T) {
	stdOutText := "content on stdout"
	stdErrText := "content on stderr"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)
	stderrReader, restoreStderr := fileToReader(t, &os.Stderr)

	// 1. Hook up the writer
	myWriter := concurrentStringsBuilder{}
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

func TestAddStdoutForwarderWithBlockedStdout(t *testing.T) {
	commonText := "content on stdout and writer"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)

	// close our fake stdout
	os.Stdout.Close()

	// 1. Hook up the writer
	var myWriter strings.Builder
	restore, err := stdforward.AddStdoutWriter(&myWriter)
	require.NoError(t, err, "AddStdoutWriter should add myWriter")

	// 2. Write text multiple times to ensure not blocked by stdout
	fmt.Print(commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed
	fmt.Print(commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed
	fmt.Print(commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 3. Disconnect the writer
	restore()

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStdout()

	// Check content is still forwarded to writer
	assert.Equal(t, commonText+commonText+commonText, myWriter.String(), "Messages weren’t blocked on the custom writer")
	// We should have only warnings, not on stdout
	assert.Empty(t, stringFromReader(t, stdoutReader), "Nothing on stdout")
}

func TestAddStderrForwarderWithBlockedStderr(t *testing.T) {
	commonText := "content on stderr and writer"

	stderrReader, restoreStderr := fileToReader(t, &os.Stderr)

	// close our fake stderr
	os.Stderr.Close()

	// 1. Hook up the writer
	var myWriter strings.Builder
	restore, err := stdforward.AddStderrWriter(&myWriter)
	require.NoError(t, err, "AddStderrWriter should add myWriter")

	// 2. Write common text twice
	fmt.Fprint(os.Stderr, commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed
	fmt.Fprint(os.Stderr, commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed
	fmt.Fprint(os.Stderr, commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 3. Disconnect the writer
	restore()

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStderr()

	// Check content is still forwarded to writer
	assert.Equal(t, commonText+commonText+commonText, myWriter.String(), "Messages weren’t blocked on the custom writer")
	// We should have only warnings, not on stderr
	assert.Empty(t, stringFromReader(t, stderrReader), "Nothing on stderr")
}

func TestAddStdoutForwarderOneWithFailingForwarder(t *testing.T) {
	commonText := "content on stdout and writer"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)

	// 1. Hook up the writer and failed writer
	restorefailed, err := stdforward.AddStdoutWriter(failedWriter{})
	require.NoError(t, err, "AddStdoutWriter should add the failed writer")
	var myWriter strings.Builder
	restore, err := stdforward.AddStdoutWriter(&myWriter)
	require.NoError(t, err, "AddStdoutWriter should add myWriter")

	// 2. Write common text multiple times
	fmt.Print(commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed
	fmt.Print(commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed
	fmt.Print(commonText)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed

	// 3. Disconnect the writers
	restore()
	restorefailed()

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStdout()

	// Check content is still forwarded to other writers
	assert.Equal(t, commonText+commonText+commonText, stringFromReader(t, stdoutReader), "Both messages are on stdout")
	assert.Equal(t, commonText+commonText+commonText, myWriter.String(), "Both messages are on the custom writer")
}

// TestRemoveForwarderWithPendingMessages ensures that disconnecting the last
// writer while io.Copy still has buffered messages to forward neither deadlocks
// nor drops those messages.
func TestRemoveForwarderWithPendingMessages(t *testing.T) {
	commonText := "content on stdout and writer"

	stdoutReader, restoreStdout := fileToReader(t, &os.Stdout)

	// Pause io.Copy after it has read the message but before it takes the
	// forwarder's writer lock.
	copyStarted := make(chan struct{})
	releaseCopy := make(chan struct{})
	var releaseCopyOnce sync.Once
	unblockCopy := func() {
		releaseCopyOnce.Do(func() { close(releaseCopy) })
	}
	var copyOnce sync.Once
	restoreCopyHook := stdforward.SetStdoutBeforeWriteHook(func() {
		copyOnce.Do(func() {
			close(copyStarted)
			<-releaseCopy
		})
	})
	t.Cleanup(restoreCopyHook)

	teardownStarted := make(chan struct{})
	var teardownOnce sync.Once
	restoreTeardownHook := stdforward.SetStdoutBeforeTeardownHook(func() {
		teardownOnce.Do(func() { close(teardownStarted) })
	})
	t.Cleanup(restoreTeardownHook)

	// 1. Hook up the writer after installing the hook, before io.Copy starts.
	var myWriter concurrentStringsBuilder
	restore, err := stdforward.AddStdoutWriter(&myWriter)
	require.NoError(t, err, "AddStdoutWriter should add myWriter")
	var removeOnce sync.Once
	remove := func() {
		removeOnce.Do(restore)
	}
	t.Cleanup(func() {
		unblockCopy()
		remove()
	})

	// 2. Write and wait until io.Copy has a pending message.
	fmt.Print(commonText)
	select {
	case <-copyStarted:
	case <-time.After(30 * time.Second):
		t.Fatal("io.Copy should have read the pending message")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		remove()
	}()
	select {
	case <-teardownStarted:
	case <-time.After(30 * time.Second):
		t.Fatal("teardown should acquire the setup lock")
	}
	select {
	case <-done:
		t.Fatal("Disconnecting the writer should wait for the pending message")
	case <-time.After(100 * time.Millisecond):
	}

	unblockCopy()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Disconnecting the writer should not block on a pending message")
	}

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStdout()

	// Check content
	assert.Equal(t, commonText, stringFromReader(t, stdoutReader), "Message is on stdout")
	assert.Equal(t, commonText, myWriter.String(), "Pending message is still forwarded to the custom writer")
}

// TestAddForwarderWaitsForTeardown ensures a writer added while the last
// writer is being removed attaches only after the old forwarder has drained.
func TestAddForwarderWaitsForTeardown(t *testing.T) {
	oldText := "content before teardown"
	newText := "|content after teardown"

	_, restoreStdout := fileToReader(t, &os.Stdout)

	copyStarted := make(chan struct{})
	releaseCopy := make(chan struct{})
	var releaseCopyOnce sync.Once
	unblockCopy := func() {
		releaseCopyOnce.Do(func() { close(releaseCopy) })
	}
	var copyOnce sync.Once
	restoreCopyHook := stdforward.SetStdoutBeforeWriteHook(func() {
		copyOnce.Do(func() {
			close(copyStarted)
			<-releaseCopy
		})
	})
	t.Cleanup(restoreCopyHook)

	teardownStarted := make(chan struct{})
	releaseTeardown := make(chan struct{})
	var releaseTeardownOnce sync.Once
	unblockTeardown := func() {
		releaseTeardownOnce.Do(func() { close(releaseTeardown) })
	}
	var teardownOnce sync.Once
	restoreTeardownHook := stdforward.SetStdoutBeforeTeardownHook(func() {
		teardownOnce.Do(func() {
			close(teardownStarted)
			<-releaseTeardown
		})
	})
	t.Cleanup(restoreTeardownHook)

	var oldWriter concurrentStringsBuilder
	restoreOld, err := stdforward.AddStdoutWriter(&oldWriter)
	require.NoError(t, err, "AddStdoutWriter should add oldWriter")

	removeDone := make(chan struct{})
	var removeOnce sync.Once
	removeOld := func() {
		removeOnce.Do(func() {
			restoreOld()
			close(removeDone)
		})
	}

	var restoreNew func()
	var addErr error
	addDone := make(chan struct{})
	addStarted := false
	var restoreSetupHook func()
	t.Cleanup(func() {
		unblockTeardown()
		unblockCopy()
		removeOld()
		if addStarted {
			<-addDone
			if restoreNew != nil {
				restoreNew()
			}
		}
		if restoreSetupHook != nil {
			restoreSetupHook()
		}
	})

	fmt.Print(oldText)
	select {
	case <-copyStarted:
	case <-time.After(30 * time.Second):
		t.Fatal("io.Copy should have read the pending message")
	}

	go func() {
		removeOld()
	}()
	select {
	case <-teardownStarted:
	case <-time.After(30 * time.Second):
		t.Fatal("teardown should acquire the setup lock")
	}

	var newWriter concurrentStringsBuilder
	addAttempted := make(chan struct{})
	var addAttemptOnce sync.Once
	restoreSetupHook = stdforward.SetStdoutBeforeSetupLockHook(func() {
		addAttemptOnce.Do(func() { close(addAttempted) })
	})
	addStarted = true
	go func() {
		restoreNew, addErr = stdforward.AddStdoutWriter(&newWriter)
		close(addDone)
	}()
	select {
	case <-addAttempted:
	case <-time.After(30 * time.Second):
		t.Fatal("AddStdoutWriter should reach the setup lock")
	}
	duringTeardownText := "|during teardown"
	fmt.Print(duringTeardownText)
	select {
	case <-addDone:
		t.Fatal("AddStdoutWriter should wait for teardown to finish")
	case <-time.After(100 * time.Millisecond):
	}

	unblockTeardown()
	unblockCopy()

	select {
	case <-removeDone:
	case <-time.After(30 * time.Second):
		t.Fatal("teardown should finish after the pending message is released")
	}
	select {
	case <-addDone:
	case <-time.After(30 * time.Second):
		t.Fatal("AddStdoutWriter should finish after teardown")
	}
	require.NoError(t, addErr, "AddStdoutWriter should add newWriter")

	fmt.Print(newText)
	restoreNew()

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStdout()

	assert.Equal(t, oldText+duringTeardownText, oldWriter.String(), "Old writer gets messages buffered during teardown")
	assert.Equal(t, newText, newWriter.String(), "New writer gets messages after teardown")
}

// TestReAddForwarderAfterDisconnectByOtherWriter ensures the forwarder can be
// reinitialized after being torn down by a writer that did not initialize it.
func TestReAddForwarderAfterDisconnectByOtherWriter(t *testing.T) {
	text1 := "content 1"
	text2 := "|content 2"

	_, restoreStdout := fileToReader(t, &os.Stdout)

	// 1. Hook up two writers: the second one does not initialize the forwarder.
	var myWriter1, myWriter2 concurrentStringsBuilder
	restore1, err := stdforward.AddStdoutWriter(&myWriter1)
	require.NoError(t, err, "AddStdoutWriter should add myWriter1")
	restore2, err := stdforward.AddStdoutWriter(&myWriter2)
	require.NoError(t, err, "AddStdoutWriter should add myWriter2")

	// 2. Disconnect them in order, so the last teardown is done by myWriter2.
	restore1()
	restore2()

	// 3. Reinitializing must attach a brand new forwarder, with no leftover
	// io.Copy goroutine forwarding to the previous writers.
	var myWriter3 concurrentStringsBuilder
	restore3, err := stdforward.AddStdoutWriter(&myWriter3)
	require.NoError(t, err, "AddStdoutWriter should add myWriter3")
	fmt.Print(text1)
	time.Sleep(durationForFlushingIoCopy) // Let the copy in io.Copy goroutine to proceed
	restore3()

	fmt.Print(text2)

	// Restore stdout (and disconnect our Writer) for other tests
	restoreStdout()

	// Check content
	assert.Equal(t, text1, myWriter3.String(), "Writer3 gets the message sent while it was connected")
	assert.Empty(t, myWriter1.String(), "Writer1 doesn’t get messages after being disconnected")
	assert.Empty(t, myWriter2.String(), "Writer2 doesn’t get messages after being disconnected")
}

// fileToReader redirects file to a reader.
// It returns a restore function if you don’t want to wait for the end of the test to restore the output.
func fileToReader(t *testing.T, f **os.File) (r io.Reader, restore func()) {
	t.Helper()

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		require.NoError(t, err, "Setup issue while creating pipe")
	}

	origStdout := *f
	*f = stdoutWriter

	// Only restore once (defer or direct call)
	once := sync.Once{}
	restore = func() {
		once.Do(func() {
			*f = origStdout
			stdoutWriter.Close()
		})
	}
	t.Cleanup(restore)
	return stdoutReader, restore
}

func stringFromReader(t *testing.T, r io.Reader) string {
	t.Helper()

	data, err := io.ReadAll(r)
	require.NoError(t, err, "No error while reading stdout content")
	return string(data)
}

type failedWriter struct{}

func (failedWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("Error from failedWriter")
}
