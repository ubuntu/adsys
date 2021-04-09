package logconnections_test

import (
	"context"
	"errors"
	"flag"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/grpc/logconnections"
	"google.golang.org/grpc"
)

type myStream struct {
	grpc.ServerStream
	recvMsgError   bool
	callRecvMsgNum int
}

func (ss *myStream) RecvMsg(m interface{}) error {
	ss.callRecvMsgNum++
	var err error
	if ss.recvMsgError {
		err = errors.New("Failing handler")
	}
	return err
}

func (myStream) Context() context.Context {
	return context.Background()
}

func TestChildRecvMsgAndHandlerCalled(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		infoIsNil         bool
		recvMsgError      bool
		handlerShouldFail bool

		wantRecvMsgNum    int
		wantHandlerNum    int
		wantCreationError bool
		wantRecvMsgError  bool
	}{
		"Handler and RecvMsg are called": {wantRecvMsgNum: 1, wantHandlerNum: 1},
		"Info being nil has no impact":   {infoIsNil: true, wantRecvMsgNum: 1, wantHandlerNum: 1},

		// Error cases
		"Handler fails out":    {handlerShouldFail: true, wantCreationError: true},
		"RecvMsg erroring out": {recvMsgError: true, wantHandlerNum: 1, wantRecvMsgError: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// we can’t really test the debug output, so only test that we get RecvMsg called

			var callHandlerNum int
			var loggerStream grpc.ServerStream

			var handler grpc.StreamHandler = func(srv interface{}, stream grpc.ServerStream) error {
				loggerStream = stream
				callHandlerNum++
				var err error
				if tc.handlerShouldFail {
					err = errors.New("Failing handler")
				}
				return err
			}

			ss, info := &myStream{recvMsgError: tc.recvMsgError}, &grpc.StreamServerInfo{FullMethod: "My method"}
			if tc.infoIsNil {
				info = nil
			}

			// test handler
			err := logconnections.StreamServerInterceptor()(nil, ss, info, handler)
			if tc.wantCreationError {
				require.Error(t, err, "New connection creation should have errored out")
				return
			}
			require.NoError(t, err, "New connection creation shouldn’t return an error")
			require.Equal(t, tc.wantHandlerNum, callHandlerNum, "Should have called the handler the expected number of time")

			// test RecvMsg
			request := &struct {
				Field1  int
				Field2  string
				private string
			}{1, "two", "private"}
			err = loggerStream.RecvMsg(request)
			if tc.wantRecvMsgError {
				require.Error(t, err, "RecvMsg should have errored out")
				return
			}
			require.NoError(t, err, "RecvMsg shouldn’t return an error")
			require.Equal(t, tc.wantRecvMsgNum, ss.callRecvMsgNum, "RecvMsg have called the child stream the expected number of time")
		})
	}
}

func TestMain(m *testing.M) {
	debug := flag.Bool("verbose", false, "Print debug log level information within the test")
	flag.Parse()
	if *debug {
		logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	}

	m.Run()
}
