package log_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

func TestLogWarningOnly(t *testing.T) {
	t.Parallel()

	stream, localLogs, remoteLogs := createLogStream(t, logrus.DebugLevel, false, false, nil)

	log.Warning(stream.Context(), "something")

	requireLog(t, localLogs(), []string{"level=warning msg=", "[[123456:", "something"})
	requireLog(t, remoteLogs(),
		[]string{"level=debug msg=", "Connecting as [[123456:"},
		[]string{"level=warning msg=", "something"})
}

func TestMultipleLogs(t *testing.T) {
	t.Parallel()

	stream, localLogs, remoteLogs := createLogStream(t, logrus.DebugLevel, false, false, nil)

	log.Warning(stream.Context(), "something")
	log.Debug(stream.Context(), "else")

	requireLog(t, localLogs(),
		[]string{"level=warning msg=", "[[123456:", "something"},
		[]string{"level=debug msg=", "else"},
	)
	requireLog(t, remoteLogs(),
		[]string{"level=debug msg=", "Connecting as [[123456:"},
		[]string{"level=warning msg=", "something"},
		[]string{"level=debug msg=", "else"},
	)
}

func TestAllLogLevels(t *testing.T) {
	t.Parallel()

	stream, localLogs, remoteLogs := createLogStream(t, logrus.DebugLevel, false, false, nil)

	log.Infof(stream.Context(), "infof %s log", "logstreamer")
	log.Debugf(stream.Context(), "debugf %s log", "logstreamer")
	log.Warningf(stream.Context(), "warningf %s log", "logstreamer")
	log.Errorf(stream.Context(), "errorf %s log", "logstreamer")

	log.Info(stream.Context(), "info log")
	log.Debug(stream.Context(), "debug log")
	log.Warning(stream.Context(), "warning log")
	log.Error(stream.Context(), "error log")

	log.Infoln(stream.Context(), "infoln log")
	log.Debugln(stream.Context(), "debugln log")
	log.Warningln(stream.Context(), "warningln log")
	log.Errorln(stream.Context(), "errorln log")

	requireLog(t, localLogs(),
		[]string{"level=info msg=", "[[123456:", "infof logstreamer log"},
		[]string{"level=debug msg=", "[[123456:", "debugf logstreamer log"},
		[]string{"level=warning msg=", "[[123456:", "warningf logstreamer log"},
		[]string{"level=error msg=", "[[123456:", "errorf logstreamer log"},
		[]string{"level=info msg=", "[[123456:", "info log"},
		[]string{"level=debug msg=", "[[123456:", "debug log"},
		[]string{"level=warning msg=", "[[123456:", "warning log"},
		[]string{"level=error msg=", "[[123456:", "error log"},
		[]string{"level=info msg=", "[[123456:", "infoln log"},
		[]string{"level=debug msg=", "[[123456:", "debugln log"},
		[]string{"level=warning msg=", "[[123456:", "warningln log"},
		[]string{"level=error msg=", "[[123456:", "errorln log"},
	)
	requireLog(t, remoteLogs(),
		[]string{"level=debug msg=", "Connecting as [[123456:"},
		[]string{"level=info msg=", "infof logstreamer log"},
		[]string{"level=debug msg=", "debugf logstreamer log"},
		[]string{"level=warning msg=", "warningf logstreamer log"},
		[]string{"level=error msg=", "errorf logstreamer log"},
		[]string{"level=info msg=", "info log"},
		[]string{"level=debug msg=", "debug log"},
		[]string{"level=warning msg=", "warning log"},
		[]string{"level=error msg=", "error log"},
		[]string{"level=info msg=", "infoln log"},
		[]string{"level=debug msg=", "debugln log"},
		[]string{"level=warning msg=", "warningln log"},
		[]string{"level=error msg=", "errorln log"},
	)
}
func TestDebugSentToRemoteEvenIfLocalIsWarning(t *testing.T) {
	t.Parallel()

	stream, localLogs, remoteLogs := createLogStream(t, logrus.WarnLevel, false, false, nil)

	log.Debug(stream.Context(), "something")

	// Nothing is printed locally
	requireLog(t, localLogs(), nil)
	// Remote still has everything sent out
	requireLog(t, remoteLogs(),
		[]string{"level=debug msg=", "Connecting as [[123456:"},
		[]string{"level=debug msg=", "something"},
	)
}

func TestLogWarningWithLocalCaller(t *testing.T) {
	t.Parallel()

	stream, localLogs, remoteLogs := createLogStream(t, logrus.DebugLevel, true, false, nil)

	log.Warning(stream.Context(), "something")

	requireLog(t, localLogs(), []string{"level=warning msg=", "/logstreamer/log_test.go:", "[[123456:", "something"})
	// Caller info are still sent to client. Client will filter it
	requireLog(t, remoteLogs(),
		[]string{"level=debug msg=", "Connecting as [[123456:"}, // This one doesn’t have HASCALLER
		[]string{"level=warning msg=", "something", "HASCALLER", "/logstreamer/log_test.go:"})
}

func TestLogWarningWithRemoteCaller(t *testing.T) {
	t.Parallel()

	stream, localLogs, remoteLogs := createLogStream(t, logrus.DebugLevel, false, true, nil)

	log.Warning(stream.Context(), "something")

	requireLog(t, localLogs(), []string{"level=warning msg=", "[[123456:", "something"})
	require.NotContains(t, localLogs(), "/logstreamer/log_test.go:", "Local logs don’t have caller info")
	// Caller info are sent to client
	requireLog(t, remoteLogs(),
		[]string{"level=debug msg=", "Connecting as [[123456:"}, // This one doesn’t have HASCALLER
		[]string{"something", "HASCALLER", "/logstreamer/log_test.go:"})
}

func TestLogWithNoCaller(t *testing.T) {
	t.Parallel()

	stream, localLogs, remoteLogs := createLogStream(t, logrus.DebugLevel, false, false, nil)

	log.Warning(stream.Context(), "something")

	assert.NotContains(t, localLogs(), "/logstreamer/log_test.go:", "No caller info shown locally")
	assert.NotContains(t, remoteLogs(), "HASCALLER", "No caller info sent remotely")
}

func TestSetReportCaller(t *testing.T) {
	tests := map[string]struct {
		reportCaller bool

		want string
	}{
		"Report caller":  {reportCaller: true, want: "level=warning msg=something func=github.com/ubuntu/adsys/internal/grpc/logstreamer_test.TestSetReportCaller"},
		"Disable caller": {reportCaller: false, want: "level=warning msg=something"},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			orig := logrus.StandardLogger().ReportCaller
			defer logrus.SetReportCaller(orig)

			// This should safely set
			log.SetReportCaller(tc.reportCaller)

			localLogger := logrus.New()
			localLogger.SetLevel(logrus.DebugLevel)
			localLogger.ReportCaller = logrus.StandardLogger().ReportCaller
			logs := captureLogs(t, localLogger)

			localLogger.Warning("something")

			require.Contains(t, logs(), tc.want, "contains expected logs")
		})
	}
}

func TestLogSendingFail(t *testing.T) {
	t.Parallel()

	stream, localLogs, remoteLogs := createLogStream(t, logrus.DebugLevel, false, false, errors.New("Sent to remote fail"))

	log.Warning(stream.Context(), "something")

	// local logs shows which logs can’t be sent to client. It still logs locally though.
	requireLog(t, localLogs(),
		[]string{"level=warning msg=", "[[123456:", "Couldn't send initial connection log to client"},
		[]string{"level=warning msg=", "[[123456:", "something"},
		[]string{"level=warning msg=", "[[123456:", "couldn't send logs to client"},
	)
	// nothing was successfully sent to client
	requireLog(t, remoteLogs(), nil)
}

func TestLogStreamsAreSeparated(t *testing.T) {
	t.Parallel()

	stream1, localLogsLogger1, remoteLogsStream1 := createLogStream(t, logrus.DebugLevel, false, false, nil)
	stream2, localLogsLogger2, remoteLogsStream2 := createLogStream(t, logrus.DebugLevel, false, false, nil)

	log.Warning(stream1.Context(), "something stream 1")
	log.Warning(stream2.Context(), "something stream 2")

	requireLog(t, localLogsLogger1(), []string{"level=warning msg=", "[[123456:", "something stream 1"})
	requireLog(t, localLogsLogger2(), []string{"level=warning msg=", "[[123456:", "something stream 2"})
	requireLog(t, remoteLogsStream1(),
		[]string{"level=debug msg=", "Connecting as [[123456:"},
		[]string{"level=warning msg=", "something stream 1"})
	requireLog(t, remoteLogsStream2(),
		[]string{"level=debug msg=", "Connecting as [[123456:"},
		[]string{"level=warning msg=", "something stream 2"})
}

func TestLogAddHook(t *testing.T) {
	log.AddHook(context.Background(), &mockLogHook{})

	// capture stderr
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn’t fail")
	orig := os.Stderr
	os.Stderr = w

	log.Info(context.Background(), "")

	// restore and collect
	os.Stderr = orig
	w.Close()
	var out bytes.Buffer
	_, err = io.Copy(&out, r)
	require.NoError(t, err, "Couldn’t copy stderr to buffer")

	require.Contains(t, out.String(), "hook fired", "does not contain expected hook message")
}

type mockLogHook struct{}

// Fire is called by logrus and will print a message to stderr.
func (*mockLogHook) Fire(entry *logrus.Entry) error { return errors.New("hook fired") }
func (*mockLogHook) Levels() []logrus.Level         { return logrus.AllLevels }

func requireLog(t *testing.T, logs string, want ...[]string) {
	t.Helper()

	logLines := strings.Split(strings.TrimSpace(logs), "\n")

	require.Len(t, logLines, len(want), "Have the expected number of lines")
	for i, wantInLine := range want {
		for _, w := range wantInLine {
			assert.Contains(t, logLines[i], w, "Should contain substring")
		}
	}
}
