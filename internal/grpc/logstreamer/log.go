package logstreamer

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/internal/i18n"
)

const (
	localLogFormatWithID = "[[%s]] %s"
	logFormatWithCaller  = "[%s] %s"
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

func log(ctx context.Context, level logrus.Level, args ...interface{}) {
	msg := fmt.Sprint(args...)
	localMsg, remoteMsg := msg, msg

	var callerForLocal, callerForRemote bool
	var sendStream sendStreamFn
	var idRequest string
	localLogger := logrus.StandardLogger()

	logCtx, withRemote := ctx.Value(logContextKey).(logContext)
	if withRemote {
		sendStream = logCtx.sendStream

		callerForLocal = logCtx.withCallerForLocal
		callerForRemote = logCtx.withCallerForRemote
		localLogger = logCtx.localLogger
		idRequest = logCtx.idRequest
	} else {
		callerForLocal = logrus.StandardLogger().ReportCaller
	}

	// Handle call stack collect
	if callerForLocal || callerForRemote {
		f := getCaller()
		caller := fmt.Sprintf("%s:%d %s()", f.File, f.Line, f.Function)
		if callerForLocal {
			localMsg = fmt.Sprintf(logFormatWithCaller, caller, localMsg)
		}
		if callerForRemote {
			remoteMsg = fmt.Sprintf(logFormatWithCaller, caller, remoteMsg)
		}
	}

	if withRemote {
		localMsg = fmt.Sprintf(localLogFormatWithID, idRequest, localMsg)
	}

	if err := logLocallyMaybeRemote(level, sendStream, remoteMsg, localLogger, localMsg); err != nil {
		localLogger.Warningf(localLogFormatWithID, idRequest, i18n.G("couldn't send logs to client"))
	}
}

func logLocallyMaybeRemote(level logrus.Level, sendStream sendStreamFn, remoteMsg string, localLogger *logrus.Logger, localMsg string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("couldn't send logs to client: %v"), err)
		}
	}()

	localLogger.Log(level, localMsg)
	if sendStream != nil {
		if err = sendStream(level.String(), remoteMsg); err != nil {
			return err
		}
	}

	return nil
}

// sprintln called fmt.Sprintln, but stripped last empty space after the new line.
func sprintln(args ...interface{}) string {
	msg := fmt.Sprintln(args...)
	return msg[:len(msg)-1]
}
