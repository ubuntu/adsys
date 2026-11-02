// Package grpcerror formats well known GRPC errors to comprehensible end-user errors.
package grpcerror

import (
	"errors"

	"github.com/leonelquinteros/gotext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Format returns the string formatted of GRPC errors,
// handling regular issues like timeout, unavailable.
// Non GRPC errors are returned as is.
func Format(err error, daemonName string) error {
	if err == nil {
		return nil
	}

	st, grpcErr := status.FromError(err)
	if !grpcErr {
		return err
	}

	switch st.Code() {
	// no daemon
	case codes.Unavailable:
		err = errors.New(gotext.Get("Couldn't connect to %s daemon: %v", daemonName, st.Message()))
	// timeout
	case codes.DeadlineExceeded:
		err = errors.New(gotext.Get("Service took too long to respond. Disconnecting client."))
	// regular error without annotation
	case codes.Unknown:
		err = errors.New(gotext.Get("Error from server: %v", st.Message()))
	// grpc error, just format it
	default:
		err = errors.New(gotext.Get("Error %s from server: %v", st.Code(), st.Message()))
	}
	return err
}
