package log_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// TODO: create a real stream log so that SendMsg() does not fail but capture it somewhere.
type myStream struct {
	sendMsgError error

	grpc.ServerStream
	ctx context.Context

	msgs []interface{}
}

func (s myStream) Context() context.Context {
	return s.ctx
}

func (s *myStream) SendMsg(m interface{}) error {
	if s.sendMsgError != nil {
		return s.sendMsgError
	}

	s.msgs = append(s.msgs, m)
	return nil
}

func TestStreamServerInterceptor(t *testing.T) {
	t.Parallel()

	callOrder := 1
	var handlerCalled int
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = callOrder
		callOrder++
		return nil
	}

	stream := &myStream{
		ctx: addMetaToContext(context.Background(), false),
	}

	logger := logrus.New()
	s := struct{}{}
	err := log.StreamServerInterceptor(logger)(s, stream, nil, handler)
	require.NoError(t, err, "StreamServerInterceptor returned an error when expecting none")

	assert.Equal(t, 1, handlerCalled, "handler was expected to be called once")

	assert.Equal(t, 1, len(stream.msgs), "Send id as log to client")
	msgContains(t, "Connecting as [[123456:", stream.msgs[0], "Send id string to client")
}

func TestStreamServerInterceptorSendLogsFails(t *testing.T) {
	t.Parallel()

	callOrder := 1
	var handlerCalled int
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = callOrder
		callOrder++
		return nil
	}

	stream := &myStream{
		ctx:          addMetaToContext(context.Background(), false),
		sendMsgError: errors.New("Send error"),
	}

	logger := logrus.New()
	s := struct{}{}
	err := log.StreamServerInterceptor(logger)(s, stream, nil, handler)
	require.NoError(t, err, "StreamServerInterceptor returned an error when expecting none")

	assert.Equal(t, 1, handlerCalled, "handler was expected to be called once")

	assert.Equal(t, 0, len(stream.msgs), "Send to client did not succeed")
}

func TestStreamServerInterceptorLoggerInvalidMetadata(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientID      string
		wantCallerKey string
		multipleMetas bool
	}{
		"No meta sent": {},

		"Missing client ID":           {wantCallerKey: "false"},
		"Missing caller key":          {clientID: "123456"},
		"Caller key is not a boolean": {clientID: "123456", wantCallerKey: "not a boolean"},

		"Multiple log metas": {clientID: "123456", wantCallerKey: "false", multipleMetas: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			callOrder := 1
			var handlerCalled int
			handler := func(srv interface{}, stream grpc.ServerStream) error {
				handlerCalled = callOrder
				callOrder++
				return nil
			}

			ctx := context.Background()
			meta := make(map[string]string)
			if tc.clientID != "" {
				meta[log.ClientIDKey] = tc.clientID
				if tc.multipleMetas {
					meta[strings.ToUpper(log.ClientIDKey)] = "OtherID"
				}
			}
			if tc.wantCallerKey != "" {
				meta[log.ClientWantCallerKey] = tc.wantCallerKey
				// Fake multiple metas by readding the key with a different case
			}
			if len(meta) > 0 {
				ctx = metadata.NewIncomingContext(ctx, metadata.New(meta))
			}

			stream := myStream{
				ctx: ctx,
			}

			s := struct{}{}
			logger := logrus.New()
			err := log.StreamServerInterceptor(logger)(s, &stream, nil, handler)
			assert.Error(t, err, "StreamServerInterceptor should return an error when no expected metadata are there")
			assert.Equal(t, 0, handlerCalled, "handler should not be called when in error")
		})
	}
}

func addMetaToContext(ctx context.Context, reportCaller bool) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.New(map[string]string{
		log.ClientIDKey:         "123456",
		log.ClientWantCallerKey: strconv.FormatBool(reportCaller)}))
}

func msgContains(t *testing.T, expected string, msg interface{}, description string) {
	t.Helper()

	l, ok := msg.(*log.Log)
	if !ok {
		t.Fatalf("Expected a log, but send: %+v", msg)
	}
	assert.Contains(t, l.Msg, expected, description)
}

func createLogStream(t *testing.T, level logrus.Level, callerForLocal, callerForRemote bool, sendError error) (stream grpc.ServerStream, localLogs func() string, remoteLogs func() string) {
	t.Helper()
	handler := func(srv interface{}, s grpc.ServerStream) error {
		stream = s
		return nil
	}

	myS := &myStream{
		ctx:          addMetaToContext(context.Background(), callerForRemote),
		sendMsgError: sendError,
	}

	localLogger := logrus.New()
	localLogger.SetLevel(level)
	localLogger.ReportCaller = callerForLocal
	localLogs = captureLogs(t, localLogger)
	s := struct{}{}
	err := log.StreamServerInterceptor(localLogger)(s, myS, nil, handler)
	require.NoError(t, err, "StreamServerInterceptor returned an error when expecting none")

	return stream, localLogs, func() string {
		var out []string
		for _, m := range myS.msgs {
			l, ok := m.(*log.Log)
			if !ok {
				t.Fatalf("Expected a log, but send: %+v", m)
			}
			msg := fmt.Sprintf("level=%s msg=%s", l.Level, l.Msg)
			if l.Caller != "" {
				msg = fmt.Sprintf("%s HASCALLER: %s", msg, l.Caller)
			}
			out = append(out, msg)
		}
		return strings.Join(out, "\n")
	}
}
