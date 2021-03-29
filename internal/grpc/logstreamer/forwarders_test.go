package log_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

func TestAddStreamToForwardLocalLogs(t *testing.T) {
	// t.Parallel() There is no log struct to pass around to every function by design.
	// Forwarders are thus global.

	streamListener, localLogListener, remoteLogsListener := createLogStream(t, logrus.DebugLevel, false, false, nil)
	disconnect := log.AddStreamToForward(streamListener)
	defer disconnect()

	log.Warning(context.Background(), "something")

	// Teardown goroutine listening
	_ = localLogListener()

	requireLog(t, remoteLogsListener(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// local log
		[]string{"level=warning msg=", "something"})
}

func TestAddStreamToForwardOtherStream(t *testing.T) {
	streamListener, localLogListener, remoteLogsListener := createLogStream(t, logrus.DebugLevel, false, false, nil)
	disconnect := log.AddStreamToForward(streamListener)
	defer disconnect()

	streamClient, localLog, _ := createLogStream(t, logrus.DebugLevel, false, false, nil)
	log.Warning(streamClient.Context(), "something")

	// Teardown goroutine listening
	_ = localLog()
	_ = localLogListener()

	requireLog(t, remoteLogsListener(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// stream client content
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=warning msg=", "something"})
}

func TestAddStreamToForwardAfterClientIsConnected(t *testing.T) {
	streamClient, localLog, _ := createLogStream(t, logrus.DebugLevel, false, false, nil)
	log.Warning(streamClient.Context(), "something")

	streamListener, localLogListener, remoteLogsListener := createLogStream(t, logrus.DebugLevel, false, false, nil)
	disconnect := log.AddStreamToForward(streamListener)
	defer disconnect()

	log.Warning(streamClient.Context(), "else")

	// Teardown goroutine listening
	_ = localLog()
	_ = localLogListener()

	requireLog(t, remoteLogsListener(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// stream client content
		[]string{"level=warning msg=", "else"})
}

func TestAddStreamToForwardDisconnect(t *testing.T) {
	streamListener, localLogListener, remoteLogsListener := createLogStream(t, logrus.DebugLevel, false, false, nil)
	disconnect := log.AddStreamToForward(streamListener)

	streamClient, localLog, remoteClientLog := createLogStream(t, logrus.DebugLevel, false, false, nil)
	log.Warning(streamClient.Context(), "something")

	// disconnect forwarder
	disconnect()

	log.Warning(streamClient.Context(), "else")

	// Teardown goroutine listening
	_ = localLog()
	_ = localLogListener()

	// log contains something
	requireLog(t, remoteLogsListener(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// stream client content
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=warning msg=", "something"})

	requireLog(t, remoteClientLog(),
		[]string{"level=debug msg=", "Connecting as [[123456:"},
		[]string{"level=warning msg=", "something"},
		[]string{"level=warning msg=", "else"})
}

func TestAddStreamToForwardTwoClients(t *testing.T) {
	streamListener, localLogListener, remoteLogsListener := createLogStream(t, logrus.DebugLevel, false, false, nil)
	disconnect := log.AddStreamToForward(streamListener)
	defer disconnect()

	streamClient1, localLog1, _ := createLogStream(t, logrus.DebugLevel, false, false, nil)
	streamClient2, localLog2, _ := createLogStream(t, logrus.DebugLevel, false, false, nil)

	log.Warning(streamClient1.Context(), "something")
	log.Warning(streamClient2.Context(), "else")

	// Teardown goroutine listening
	_ = localLog1()
	_ = localLog2()
	_ = localLogListener()

	requireLog(t, remoteLogsListener(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// clients content with fake client ID
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=warning msg=", "something"},
		[]string{"level=warning msg=", "else"})
}

func TestAddStreamToForwardWithListenerCaller(t *testing.T) {
	streamListener, localLogListener, remoteLogsListener := createLogStream(t, logrus.DebugLevel, false, true, nil)
	disconnect := log.AddStreamToForward(streamListener)
	defer disconnect()

	streamClient, localLog, remoteLogs := createLogStream(t, logrus.DebugLevel, false, false, nil)
	log.Warning(streamClient.Context(), "something")

	// Teardown goroutine listening
	_ = localLog()
	_ = localLogListener()

	requireLog(t, remoteLogsListener(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// stream client content with caller info
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=warning msg=", "something", "HASCALLER", "/logstreamer/forwarders_test.go:"})

	requireLog(t, remoteLogs(),
		[]string{"level=debug msg=", "Connecting as [[123456:"},
		// Remote receives the caller, but will filter it
		[]string{"level=warning msg=", "something", "HASCALLER", "/logstreamer/forwarders_test.go:"})
}

func TestAddStreamMultipleForwarders(t *testing.T) {
	streamListener1, localLogListener1, remoteLogsListener1 := createLogStream(t, logrus.DebugLevel, false, false, nil)
	disconnect1 := log.AddStreamToForward(streamListener1)
	defer disconnect1()
	streamListener2, localLogListener2, remoteLogsListener2 := createLogStream(t, logrus.DebugLevel, false, false, nil)
	disconnect2 := log.AddStreamToForward(streamListener2)
	defer disconnect2()

	streamClient, localLog, _ := createLogStream(t, logrus.DebugLevel, false, false, nil)
	log.Warning(streamClient.Context(), "something")

	// Teardown goroutine listening
	_ = localLog()
	_ = localLogListener1()
	_ = localLogListener2()

	requireLog(t, remoteLogsListener1(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// stream client content, including second forwarder
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=warning msg=", "something"})

	// second listener does not contain first connection
	requireLog(t, remoteLogsListener2(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// stream client content
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=warning msg=", "something"})
}

func TestAddStreamMultipleForwardersOneWithCaller(t *testing.T) {
	streamListener1, localLogListener1, remoteLogsListener1 := createLogStream(t, logrus.DebugLevel, false, true, nil)
	disconnect1 := log.AddStreamToForward(streamListener1)
	defer disconnect1()
	streamListener2, localLogListener2, remoteLogsListener2 := createLogStream(t, logrus.DebugLevel, false, false, nil)
	disconnect2 := log.AddStreamToForward(streamListener2)
	defer disconnect2()

	streamClient, localLog, _ := createLogStream(t, logrus.DebugLevel, false, false, nil)
	log.Warning(streamClient.Context(), "something")

	// Teardown goroutine listening
	_ = localLog()
	_ = localLogListener1()
	_ = localLogListener2()

	requireLog(t, remoteLogsListener1(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// stream client content, including second forwarder
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=warning msg=", "something", "HASCALLER", "/logstreamer/forwarders_test.go:"})

	requireLog(t, remoteLogsListener2(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// stream client content
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=warning msg=", "something", "HASCALLER", "/logstreamer/forwarders_test.go:"})
}

func TestAddStreamToForwardFailSend(t *testing.T) {
	streamListener, localLogListener, remoteLogsListener := createLogStream(t, logrus.DebugLevel, false, false, errors.New("SendMsg failed"))
	disconnect := log.AddStreamToForward(streamListener)
	defer disconnect()

	streamClient, localLog, remoteLogs := createLogStream(t, logrus.DebugLevel, false, false, nil)
	log.Warning(streamClient.Context(), "something")

	// Teardown goroutine listening
	_ = localLogListener()

	requireLog(t, remoteLogsListener(), nil)

	// Other clients still received something (but not failure to send to other listeners)
	requireLog(t, remoteLogs(),
		[]string{"level=debug msg=", "Connecting as [[123456:"},
		[]string{"level=warning msg=", "something"})

	requireLog(t, localLog(),
		[]string{"level=warning msg=", "something"},
		[]string{"level=warning msg=", "Couldn't send log to one or more listener: SendMsg failed"})
}

func TestRemoveAllStreams(t *testing.T) {
	streamListener1, localLogListener1, remoteLogsListener1 := createLogStream(t, logrus.DebugLevel, false, false, nil)
	disconnect1 := log.AddStreamToForward(streamListener1)
	defer disconnect1()
	streamListener2, localLogListener2, remoteLogsListener2 := createLogStream(t, logrus.DebugLevel, false, false, nil)
	disconnect2 := log.AddStreamToForward(streamListener2)
	defer disconnect2()

	streamClient, localLogs, _ := createLogStream(t, logrus.DebugLevel, false, false, nil)
	log.Warning(streamClient.Context(), "something")

	// Teardown goroutine listening
	_ = localLogs()
	_ = localLogListener1()
	_ = localLogListener2()

	log.RemoveAllStreams()

	log.Warning(streamClient.Context(), "else")

	// Does not contain else line as disconnected before
	requireLog(t, remoteLogsListener1(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// stream client content, including second forwarder
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=warning msg=", "something"})

	// Does not contain else line as disconnected before
	requireLog(t, remoteLogsListener2(),
		// This is us (with fake client ID)
		[]string{"level=debug msg=", "Connecting as [[123456:"},

		// stream client content
		[]string{"level=info msg=", "New connection from client [[123456:"},
		[]string{"level=warning msg=", "something"})
}
