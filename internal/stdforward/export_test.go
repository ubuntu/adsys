package stdforward

// SetStdoutBeforeWriteHook pauses forwarding before the stdout forwarder's
// writer lock is acquired. Install it before adding a writer, and restore it
// only after removal has joined the copy goroutine.
func SetStdoutBeforeWriteHook(hook func()) (restore func()) {
	stdoutForwarder.testHooksMu.Lock()
	stdoutForwarder.beforeWrite = hook
	stdoutForwarder.testHooksMu.Unlock()
	return func() {
		stdoutForwarder.testHooksMu.Lock()
		stdoutForwarder.beforeWrite = nil
		stdoutForwarder.testHooksMu.Unlock()
	}
}

// SetStdoutBeforeSetupLockHook signals when an add operation reaches the setup
// lock. Install it before starting the add attempt and restore it after the
// attempt returns.
func SetStdoutBeforeSetupLockHook(hook func()) (restore func()) {
	stdoutForwarder.testHooksMu.Lock()
	stdoutForwarder.beforeSetupLock = hook
	stdoutForwarder.testHooksMu.Unlock()
	return func() {
		stdoutForwarder.testHooksMu.Lock()
		stdoutForwarder.beforeSetupLock = nil
		stdoutForwarder.testHooksMu.Unlock()
	}
}

// SetStdoutBeforeTeardownHook pauses teardown after it acquires the setup lock.
// Install it before adding a writer and restore it after teardown completes.
func SetStdoutBeforeTeardownHook(hook func()) (restore func()) {
	stdoutForwarder.testHooksMu.Lock()
	stdoutForwarder.beforeTeardown = hook
	stdoutForwarder.testHooksMu.Unlock()
	return func() {
		stdoutForwarder.testHooksMu.Lock()
		stdoutForwarder.beforeTeardown = nil
		stdoutForwarder.testHooksMu.Unlock()
	}
}
