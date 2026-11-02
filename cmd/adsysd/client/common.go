package client

import (
	"errors"
	"fmt"
	"io"

	"github.com/ubuntu/adsys"
)

type recver interface {
	Recv() (*adsys.StringResponse, error)
}

// singleMsg returns a single string that is accepted from stream.
// The stream should return StringReponse.
// In case there are multiple responses streamed, we return an error.
func singleMsg(stream recver) (msg string, err error) {
	for {
		r, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", err
		}
		if msg != "" {
			return "", fmt.Errorf("multiple answers from service streamed while we expected only one.\nWe already got:\n%s\n\nAnd now we are getting:\n%s", msg, r.GetMsg())
		}
		msg = r.GetMsg()
	}

	return msg, nil
}
