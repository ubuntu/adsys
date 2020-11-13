package log

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/internal/i18n"
)

const (
	localLogFormatWithID = "[[%s]] %s"
	logFormatWithCaller  = "%s %s"
)

// Debug logs at the DEBUG level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Print; a newline is appended to local log if missing.
func Debug(ctx context.Context, args ...interface{}) {
	log(ctx, logrus.DebugLevel, args...)
}

// Info logs at the INFO level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Print; a newline is appended to local log  if missing.
func Info(ctx context.Context, args ...interface{}) {
	log(ctx, logrus.InfoLevel, args...)
}

// Warning logs at the WARNING level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Print; a newline is appended to local log  if missing.
func Warning(ctx context.Context, args ...interface{}) {
	log(ctx, logrus.WarnLevel, args...)
}

// Error logs at the ERROR level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Print; a newline is appended to local log if missing.
func Error(ctx context.Context, args ...interface{}) {
	log(ctx, logrus.ErrorLevel, args...)
}

// Debugf logs at the DEBUG level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Printf; a newline is appended to local log if missing.
func Debugf(ctx context.Context, format string, args ...interface{}) {
	logf(ctx, logrus.DebugLevel, format, args...)
}

// Infof logs at the INFO level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Printf; a newline is appended to local log if missing.
func Infof(ctx context.Context, format string, args ...interface{}) {
	logf(ctx, logrus.InfoLevel, format, args...)
}

// Warningf logs at the WARNING level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Printf; a newline is appended to local log if missing.
func Warningf(ctx context.Context, format string, args ...interface{}) {
	logf(ctx, logrus.WarnLevel, format, args...)
}

// Errorf logs at the ERROR level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Printf; a newline is appended to local log if missing.
func Errorf(ctx context.Context, format string, args ...interface{}) {
	logf(ctx, logrus.ErrorLevel, format, args...)
}

// Debugln logs at the DEBUG level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Println; a newline is appended to local log if missing.
func Debugln(ctx context.Context, args ...interface{}) {
	logln(ctx, logrus.DebugLevel, args...)
}

// Infoln logs at the INFO level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Println; a newline is appended to local log if missing.
func Infoln(ctx context.Context, args ...interface{}) {
	logln(ctx, logrus.InfoLevel, args...)
}

// Warningln logs at the WARNING level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Println; a newline is appended to local log if missing.
func Warningln(ctx context.Context, args ...interface{}) {
	logln(ctx, logrus.WarnLevel, args...)
}

// Errorln logs at the ERROR level.
// If the context contains a stream, it will stream there and use associated local logger.
// Arguments are handled in the manner of fmt.Println; a newline is appended to local log if missing.
func Errorln(ctx context.Context, args ...interface{}) {
	logln(ctx, logrus.ErrorLevel, args...)
}

func logln(ctx context.Context, level logrus.Level, args ...interface{}) {
	log(ctx, level, sprintln(args...))
}

func logf(ctx context.Context, level logrus.Level, format string, args ...interface{}) {
	log(ctx, level, fmt.Sprintf(format, args...))
}

var (
	callerMu = sync.RWMutex{}
)

func log(ctx context.Context, level logrus.Level, args ...interface{}) {
	msg := fmt.Sprint(args...)

	var callerForRemote bool
	var sendStream sendStreamFn
	var idRequest string
	localLogger := logrus.StandardLogger()

	logCtx, withRemote := ctx.Value(logContextKey).(logContext)
	if withRemote {
		sendStream = logCtx.sendStream

		callerForRemote = logCtx.withCallerForRemote
		localLogger = logCtx.localLogger
		idRequest = logCtx.idRequest
	}

	// We are controlling and unwrapping the caller ourself outside of this package.
	// As logrus doesn't allow to specify which package to exclude manually, do it there.
	// https://github.com/sirupsen/logrus/issues/867
	callerMu.RLock()
	callerForLocal := localLogger.ReportCaller
	callerMu.RUnlock()

	// Handle call stack collect
	var caller string
	if callerForLocal || callerForRemote || streamsForwarders.showCaller {
		f := getCaller()
		fqfn := strings.Split(f.Function, "/")
		fqfn = strings.Split(fqfn[len(fqfn)-1], ".")
		funcName := strings.Join(fqfn[1:], ".")
		caller = fmt.Sprintf("%s:%d %s()", f.File, f.Line, funcName)
	}

	if err := logLocallyMaybeRemote(level, caller, msg, localLogger, idRequest, sendStream); err != nil {
		localLogger.Warningf(localLogFormatWithID, idRequest, i18n.G("couldn't send logs to client"))
	}
}

func logLocallyMaybeRemote(level logrus.Level, caller, msg string, localLogger *logrus.Logger, idRequest string, sendStream sendStreamFn) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("couldn't send logs to client: %v"), err)
		}
	}()

	localMsg := msg
	if idRequest != "" {
		localMsg = fmt.Sprintf(localLogFormatWithID, idRequest, msg)
	}
	forwardMsg := localMsg

	callerMu.Lock()
	callerForLocal := localLogger.ReportCaller
	localLogger.SetReportCaller(false)
	if callerForLocal {
		localMsg = fmt.Sprintf(logFormatWithCaller, caller, localMsg)
	}
	localLogger.Log(level, localMsg)
	// Reset value for next call
	localLogger.SetReportCaller(callerForLocal)
	callerMu.Unlock()

	if sendStream != nil {
		if err = sendStream(level.String(), caller, msg); err != nil {
			return err
		}
	}

	// Send remotely local message to global listeners
	streamsForwarders.mu.RLock()
	for stream := range streamsForwarders.fw {
		if err := stream.SendMsg(&Log{
			LogHeader: logIdentifier,
			Level:     level.String(),
			Caller:    caller,
			Msg:       forwardMsg,
		}); err != nil {
			Warningf(context.Background(), "Couldn't send log to one or more listener: %v", err)
		}
	}
	streamsForwarders.mu.RUnlock()

	return nil
}

// sprintln called fmt.Sprintln, but stripped last empty space after the new line.
func sprintln(args ...interface{}) string {
	msg := fmt.Sprintln(args...)
	return msg[:len(msg)-1]
}
