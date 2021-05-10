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
	"github.com/ubuntu/adsys/internal/grpc/logstreamer/test"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func TestRecvLogMsg(t *testing.T) {
	t.Parallel()

	recvMsgError := errors.New("Error from RecvMsg")

	tests := map[string]struct {
		logMsgs           []*log.Log
		errRecv           error
		withCaller        bool
		invalidObjectCall bool

		wantLogs      [][]string
		wantNotInLogs []string
		wantErr       bool
	}{
		"One log (and one closing empty message)": {logMsgs: []*log.Log{
			{
				LogHeader: log.LogIdentifier,
				Level:     logrus.InfoLevel.String(),
				Msg:       "My server log",
				Caller:    "my/caller/function",
			}},
			wantLogs:      [][]string{{"level=info", `msg="My server log"`}},
			wantNotInLogs: []string{"my/caller/function"},
		},
		"Two logs with different debug level": {logMsgs: []*log.Log{
			{
				LogHeader: log.LogIdentifier,
				Level:     logrus.InfoLevel.String(),
				Msg:       "My first server log",
				Caller:    "my/caller/function1",
			}, {
				LogHeader: log.LogIdentifier,
				Level:     logrus.DebugLevel.String(),
				Msg:       "My second server log",
				Caller:    "my/caller/function2",
			}},
			wantLogs: [][]string{
				{"level=info", `msg="My first server log"`},
				{"level=debug", `msg="My second server log"`}},
		},
		"Log with caller": {logMsgs: []*log.Log{
			{
				LogHeader: log.LogIdentifier,
				Level:     logrus.InfoLevel.String(),
				Msg:       "My server log",
				Caller:    "my/caller/function",
			}},
			withCaller: true,
			wantLogs:   [][]string{{"level=info", `My server log`, "my/caller/function"}},
		},
		"No caller when not requested": {logMsgs: []*log.Log{
			{
				LogHeader: log.LogIdentifier,
				Level:     logrus.InfoLevel.String(),
				Msg:       "My server log",
				Caller:    "my/caller/function",
			}},
			wantLogs:      [][]string{{"level=info", `msg="My server log"`}},
			wantNotInLogs: []string{"my/caller/function"},
		},
		"No caller on any logs": {logMsgs: []*log.Log{
			{
				LogHeader: log.LogIdentifier,
				Level:     logrus.InfoLevel.String(),
				Msg:       "My first server log",
				Caller:    "my/caller/function1",
			}, {
				LogHeader: log.LogIdentifier,
				Level:     logrus.DebugLevel.String(),
				Msg:       "My second server log",
				Caller:    "my/caller/function2",
			}},
			wantLogs: [][]string{
				{"level=info", `msg="My first server log"`},
				{"level=debug", `msg="My second server log"`}},
			wantNotInLogs: []string{"my/caller/function1", "my/caller/function2"},
		},

		"One message, no log":                                {},
		"One message with error, no log, error is preserved": {errRecv: recvMsgError, wantErr: true},
		"Logs and then message with error, error is preserved": {
			logMsgs: []*log.Log{
				{
					LogHeader: log.LogIdentifier,
					Level:     logrus.InfoLevel.String(),
					Msg:       "My server log",
				}},
			errRecv:  recvMsgError,
			wantLogs: [][]string{{"level=info", `msg="My server log"`}},
			wantErr:  true,
		},

		"Unknown log level triggers a client error (protocole issue)": {logMsgs: []*log.Log{
			{
				LogHeader: log.LogIdentifier,
				Level:     "Unknown",
				Msg:       "My first server log",
			}},
			wantErr: true,
		},
		"Invalid object passed to RecvMsg is gracefully skipped": {logMsgs: []*log.Log{
			{
				LogHeader: log.LogIdentifier,
				Level:     logrus.InfoLevel.String(),
				Msg:       "My first server log",
			}},
			invalidObjectCall: true,
			// the whole reception is skipped as the object is invalid
			wantNotInLogs: []string{"My first server log"},
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			logger := logrus.New()
			logger.SetOutput(os.Stderr)
			logger.SetLevel(logrus.DebugLevel)
			logger.SetReportCaller(tc.withCaller)

			s := &clientStream{
				logCalls:       tc.logMsgs,
				wantErrRecvMsg: tc.errRecv,
			}

			streamCreation := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
				return s, nil
			}
			c, err := log.StreamClientInterceptor(logger)(context.Background(), nil, nil, "method", streamCreation)
			require.NoError(t, err, "StreamClient Interceptor should return no error")

			logs := captureLogs(t, logger)

			if !tc.invalidObjectCall {
				err = c.RecvMsg(&test.EmptyLogTest{})
			} else {
				err = c.RecvMsg("Some invalid struct")
			}

			if tc.wantErr {
				// assert and not require as we want to check logs still
				assert.Error(t, err, "RecvMsg should have errored out but did not")
				if tc.errRecv != nil {
					assert.Equal(t, err, tc.errRecv, "error from errRecv is directly sent back to client")
				}
			} else {
				require.NoError(t, err, "RecvMsg with no error")
			}

			out := logs()
			for i, wanted := range tc.wantLogs {
				line := strings.Split(out, "\n")[i]
				assert.Contains(t, line, wanted[0], "Message log level is preserved")
				assert.Contains(t, line, wanted[1], "Message content is preserved")
				if len(wanted) > 2 {
					assert.Contains(t, line, wanted[2], "Message caller is displayed")
				}
			}

			for i, notWanted := range tc.wantNotInLogs {
				line := strings.Split(out, "\n")[i]
				assert.NotContains(t, line, notWanted, "Should not contain caller information")
			}

			if tc.wantLogs == nil {
				require.Empty(t, out, "No log output expected")
			}
		})
	}
}

type clientStream struct {
	logCalls       []*log.Log
	wantErrRecvMsg error

	grpc.ClientStream

	callCount int
}

func (c *clientStream) RecvMsg(m interface{}) error {
	mv, ok := m.(proto.Message)
	if !ok {
		return nil
	}
	if c.callCount < len(c.logCalls) {
		// marshall our log into the passed struct
		d, _ := proto.Marshal(c.logCalls[c.callCount])
		_ = proto.Unmarshal(d, mv)
		c.callCount++
		return nil
	}

	if c.wantErrRecvMsg != nil {
		return c.wantErrRecvMsg
	}

	_ = proto.Unmarshal(nil, mv)
	return c.wantErrRecvMsg
}

// captureLogs captures current logs for logger.
// It returns a couple one function to read the buffer, which will restore the logger output.
func captureLogs(t *testing.T, logger *logrus.Logger) (out func() string) {
	t.Helper()

	orig := logger.Out
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal("Setup error: creating pipe:", err)
	}
	logger.SetOutput(w)

	return func() string {
		w.Close()
		var buf bytes.Buffer
		_, errCopy := io.Copy(&buf, r)
		if errCopy != nil {
			t.Fatal("Setup error: couldn’t get buffer content:", err)
		}
		logger.SetOutput(orig)
		return buf.String()
	}
}
