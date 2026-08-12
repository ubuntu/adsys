package adsysservice

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCertSelector(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		nickname string
		all      bool

		wantErr bool
	}{
		"A nickname selects one certificate": {nickname: "Example-CA.Machine"},
		"All selects every certificate":      {all: true},

		// Error cases: the engine resolves "all" first, so a request carrying
		// both selectors would operate on every certificate instead of the
		// named one.
		"Both selectors are rejected": {nickname: "Example-CA.Machine", all: true, wantErr: true},
		"No selector is rejected":     {wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := certSelector(tc.nickname, tc.all)
			if !tc.wantErr {
				require.NoError(t, err, "selector should be accepted")
				return
			}
			require.Error(t, err, "selector should be rejected")
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "rejection should be an invalid argument error")
		})
	}
}
