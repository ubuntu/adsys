package log

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"

	proto "github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/runtime/protoiface"
)

// StreamClientInterceptor allows to tag the client with an unique ID and request the server
// to stream back to the client logs corresponding to that request to the given logger.
// It will use ReportCaller value from logger to decide if we print the callstack (first frame outside
// of that package)
func StreamClientInterceptor(logger *logrus.Logger) grpc.StreamClientInterceptor {
	clientID := strconv.Itoa(os.Getpid())
	reportCallerMsg := strconv.FormatBool(logger.ReportCaller)
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = metadata.AppendToOutgoingContext(ctx,
			clientIDKey, clientID,
			clientWantCallerKey, reportCallerMsg)
		clientStream, err := streamer(ctx, desc, cc, method, opts...)
		return &logClientStream{
			ClientStream: clientStream,
			logger:       logger,
			callerMu:     sync.Mutex{},
		}, err
	}
}

type logClientStream struct {
	grpc.ClientStream
	logger   *logrus.Logger
	callerMu sync.Mutex
}

// RecvMsg is used to intercept log messages from server before hitting the client
func (ss *logClientStream) RecvMsg(m interface{}) error {
	for {
		if err := ss.ClientStream.RecvMsg(m); err != nil {
			return err
		}

		// we should have returned an error above if the proto isn’t a valid message.

		// Try to see if this is a log message
		message, ok := m.(protoiface.MessageV1)
		if !ok {
			// this should be a proto message but it’s not, let the client handling it
			return nil
		}
		bytes, err := proto.Marshal(message)
		if err != nil {
			// similarly, we just received this message but it’s invalid, let the client handling it
			return nil
		}
		var logMsg Log
		proto.Unmarshal(bytes, &logMsg)
		if logMsg.LogHeader == logIdentifier {
			level, err := logrus.ParseLevel(logMsg.Level)
			if err != nil {
				return fmt.Errorf("client received an invalid debug log level: %s", logMsg.Level)
			}

			reportCaller := ss.logger.ReportCaller
			ss.logger.SetReportCaller(false)
			// We are controlling and unwrapping the caller ourself outside of this package.
			// As logrus doesn't allow to specify which package to exclude manually, do it there.
			// https://github.com/sirupsen/logrus/issues/867
			ss.logger.Log(level, logMsg.Msg)
			// Restore if we use direct calls
			ss.logger.SetReportCaller(reportCaller)

			// this message doesn’t concern the client, treat next one
			continue

		}

		// this returns the message to the client stream
		return nil
	}
}
