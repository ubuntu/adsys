package ad_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestTicketPath(t *testing.T) {
	// Build mock libkrb5
	var mockLibPath string
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		mockLibPath = testutils.BuildKrb5Mock(t, ".")
	}

	// We setup and rerun in a subprocess because we need to preload the mock libkrb5
	if testutils.PreloadLibInSubprocess(t, mockLibPath) {
		return
	}

	tests := map[string]struct {
		krb5Behavior string
		ccacheIsDir  bool

		wantErr     bool
		wantErrType error
	}{
		"Lookup is successful":                 {krb5Behavior: "return_ccache:FILE:%s"},
		"Allow ccache without FILE identifier": {krb5Behavior: "return_ccache:%s"},

		"Error when ccache not present on disk": {krb5Behavior: "return_ccache:FILE:%s/non-existent", wantErr: true},
		"Error when ccache is a directory":      {krb5Behavior: "return_ccache:%s", ccacheIsDir: true, wantErr: true},
		"Error when initializing context":       {krb5Behavior: "error_initializing_context", wantErr: true},
		"Error on empty ticket path":            {krb5Behavior: "return_empty_ccache", wantErr: true},
		"Error on NULL ticket path":             {krb5Behavior: "return_null_ccache", wantErr: true},
		"Error on non-FILE ccache":              {krb5Behavior: "return_memory_ccache", wantErrType: ad.ErrTicketNotPresent},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			wantOut := filepath.Join(t.TempDir(), "krb5cc_12345")
			if strings.Contains(tc.krb5Behavior, "return_ccache") {
				tc.krb5Behavior = fmt.Sprintf(tc.krb5Behavior, wantOut)
			}

			// Set up mock libwbclient behavior
			t.Setenv("ADSYS_KRB5_BEHAVIOR", tc.krb5Behavior)

			var err error
			if tc.ccacheIsDir {
				err = os.Mkdir(wantOut, 0700)
			} else {
				err = os.WriteFile(wantOut, []byte("dummy ticket data"), 0600)
			}
			require.NoError(t, err, "Setup: Failed to create path to ticket cache")

			ticketPath, err := ad.TicketPath()
			if tc.wantErr || tc.wantErrType != nil {
				require.Error(t, err, "TicketPath should have errored out")
				if tc.wantErrType != nil {
					require.ErrorIs(t, err, tc.wantErrType, "TicketPath should have returned the expected error type")
				}
				return
			}
			require.NoError(t, err, "Call to TicketPath failed")

			require.Equal(t, wantOut, ticketPath, "Returned ticket path is not the expected one")
		})
	}
}
