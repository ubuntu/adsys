package loghooks_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/ubuntu/adsys/internal/loghooks"
)

var buf bytes.Buffer

func TestEventLogHook(t *testing.T) {
	msgs := map[string]string{
		"debug":   "DEBUG: Debug msg",
		"info":    "Info msg",
		"warning": "Warning msg",
		"error":   "Error msg",
	}

	tests := map[string]struct {
		level logrus.Level

		wantOut []string
	}{
		"error level": {level: logrus.ErrorLevel, wantOut: []string{"error"}},
		"warn level":  {level: logrus.WarnLevel, wantOut: []string{"warning", "error"}},
		"info level":  {level: logrus.InfoLevel, wantOut: []string{"info", "warning", "error"}},
		"debug level": {level: logrus.DebugLevel, wantOut: []string{"debug", "info", "warning", "error"}},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			buf.Reset()
			log := logrus.New()
			log.AddHook(&loghooks.EventLog{mockServiceLogger{}})
			log.SetLevel(tc.level)

			// Log only "Debug msg", as the hook itself should prepend "DEBUG: "
			// to it, announcing that it's a debug message. We do this to
			// differentiate between info and debug, as eventlog has no debug
			// level built in.
			//
			// The other messages should be logged as is.
			log.Debug("Debug msg")
			log.Info(msgs["info"])
			log.Warning(msgs["warning"])
			log.Error(msgs["error"])

			dontWantMsgs := make(map[string]string)
			for k, v := range msgs {
				dontWantMsgs[k] = v
			}
			// Messages we want in
			for _, levelWanted := range tc.wantOut {
				assert.Contains(t, buf.String(), msgs[levelWanted], "Should be in logs")
				delete(dontWantMsgs, levelWanted)
			}
			// Messages we don't want
			for _, msg := range dontWantMsgs {
				assert.NotContains(t, buf.String(), msg, "Should not be in logs")
			}
		})
	}
}

type mockServiceLogger struct{}

func (mockServiceLogger) Error(v ...interface{}) error {
	fmt.Fprintln(&buf, v...)
	return nil
}
func (mockServiceLogger) Warning(v ...interface{}) error {
	fmt.Fprintln(&buf, v...)
	return nil
}
func (mockServiceLogger) Info(v ...interface{}) error {
	fmt.Fprintln(&buf, v...)
	return nil
}

func (mockServiceLogger) Errorf(format string, a ...interface{}) error   { return nil }
func (mockServiceLogger) Warningf(format string, a ...interface{}) error { return nil }
func (mockServiceLogger) Infof(format string, a ...interface{}) error    { return nil }
