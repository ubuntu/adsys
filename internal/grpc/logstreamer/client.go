package logstreamer

import (
	"context"
	"fmt"
	"os"
	"strconv"

	proto "github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/runtime/protoiface"
)

// StreamClientInterceptor allows to tag the client with an unique ID and request the server
// to stream back to the client logs corresponding to that request to the given logger.
// Log levels and other options are directly set on the logger.
// reportCaller allows to report the real remote caller name. This function will call SetReportCaller(false) on the logger then.
func StreamClientInterceptor(logger *logrus.Logger, reportCaller bool) grpc.StreamClientInterceptor {
	clientID := strconv.Itoa(os.Getpid())
	logger.SetReportCaller(false)
	reportCallerMsg := strconv.FormatBool(reportCaller)
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = metadata.AppendToOutgoingContext(ctx,
			clientIDKey, clientID,
			clientWantCallerKey, reportCallerMsg)
		clientStream, err := streamer(ctx, desc, cc, method, opts...)
		return logClientStream{
			ClientStream: clientStream,
			logger:       logger,
		}, err
	}
}

type logClientStream struct {
	grpc.ClientStream
	logger *logrus.Logger
}

// RecvMsg is used to intercept log messages from server before hitting the client
func (ss logClientStream) RecvMsg(m interface{}) error {
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
			ss.logger.Log(level, logMsg.Msg)
			// this message doesn’t concern the client, treat next one
			continue

		}

		// this returns the message to the client stream
		return nil
	}
}
