package log

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/internal/i18n"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var logContextKey = struct{}{}

type logContext struct {
	idRequest           string
	sendStream          sendStreamFn
	withCallerForRemote bool
	localLogger         *logrus.Logger
}

// StreamServerInterceptor wraps the server stream to create a new dedicated logger to stream back the logs.
// It will use serverLogger to log locally the same messages, prefixing by the request ID.
// It will use ReportCaller value from localLogger to decide if we print the callstack (first frame outside
// of that package).
func StreamServerInterceptor(localLogger *logrus.Logger) func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		clientID, withCaller, err := extractMetaFromContext(ss.Context())
		if err != nil {
			return err
		}

		ssLogs := serverStreamWithLogs{
			ServerStream: ss,
		}

		// create and log request ID
		idRequest := fmt.Sprintf("%s:%s", clientID, createID())
		if err := ssLogs.sendLogs(logrus.DebugLevel.String(), "", fmt.Sprintf(i18n.G("Connecting as [[%s]]"), idRequest)); err != nil {
			localLogger.Warningf(localLogFormatWithID, idRequest, i18n.G("Couldn't send initial connection log to client"))
		}
		Infof(context.Background(), i18n.G("New connection from client [[%s]]"), idRequest)

		// attach stream logger options to context so that we can log locally and remotely from context
		ssLogs.ctx = context.WithValue(ss.Context(), logContextKey, logContext{
			idRequest:           idRequest,
			sendStream:          ssLogs.sendLogs,
			withCallerForRemote: withCaller,
			localLogger:         localLogger,
		})

		return handler(srv, ssLogs)
	}
}

type serverStreamWithLogs struct {
	grpc.ServerStream
	ctx context.Context
}

func (ss serverStreamWithLogs) Context() context.Context {
	return ss.ctx
}

// sendLogs sends directly to the stream a Log message with dedicated entries.
// This will be intercepted by the StreamClientInterceptor for every Log message matching
// its structure, preventing to hit the client.
// A harcoded header is set to double check and ensure we have Log message.
func (ss serverStreamWithLogs) sendLogs(logLevel, caller, msg string) error {
	return ss.SendMsg(&Log{
		LogHeader: logIdentifier,
		Level:     logLevel,
		Caller:    caller,
		Msg:       msg,
	})
}

type sendStreamFn func(logLevel, caller, msg string) error

func extractMetaFromContext(ctx context.Context) (clientID string, withCaller bool, err error) {
	// decorate depends on logstreamer: we can’t use it here
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("invalid metdata from client: %v\n. Please use the StreamClientInterceptor: %v"), err)
		}
	}()

	// extract logs metadata from the client
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false, errors.New(i18n.G("missing client metadata"))
	}
	clientID, err = validUniqueMdEntry(md, clientIDKey)
	if err != nil {
		return "", false, err
	}
	withCallerRaw, err := validUniqueMdEntry(md, clientWantCallerKey)
	if err != nil {
		return "", false, err
	}
	withCaller, err = strconv.ParseBool(withCallerRaw)
	if err != nil {
		return "", false, fmt.Errorf(i18n.G("%s isn't a boolean: %v"), clientWantCallerKey, err)
	}

	return clientID, withCaller, nil
}

func validUniqueMdEntry(md metadata.MD, key string) (string, error) {
	v := md.Get(key)
	if len(v) == 0 {
		return "", fmt.Errorf(i18n.G("missing metadata %s for incoming request"), key)
	}
	if len(v) != 1 {
		return "", fmt.Errorf(i18n.G("invalid metadata %s for incoming request: %q"), key, v)
	}
	return v[0], nil
}

func createID() (id string) {
	r, err := rand.Int(rand.Reader, big.NewInt(999999))
	if err != nil {
		return "xxxxxx"
	}
	return fmt.Sprintf("%06d", r.Int64())
}
