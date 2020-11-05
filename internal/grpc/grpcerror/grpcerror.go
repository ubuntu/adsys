package grpcerror

import (
	"errors"
	"fmt"

	"github.com/ubuntu/adsys/internal/i18n"
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
		err = fmt.Errorf(i18n.G("Couldn't connect to %s daemon: %v"), daemonName, st.Message())
	// timeout
	case codes.DeadlineExceeded:
		err = errors.New(i18n.G("Service took too long to respond. Disconnecting client."))
	// regular error without annotation
	case codes.Unknown:
		err = fmt.Errorf(i18n.G("Error from server: %v"), st.Message())
	// grpc error, just format it
	default:
		err = fmt.Errorf(i18n.G("Error %s from server: %v"), st.Code(), st.Message())
	}
	return err
}
