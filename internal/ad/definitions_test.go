package ad_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad"
)

func TestGetPolicyDefinitions(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		format   string
		distroID string

		wantADMX string
		wantADML string
		wantErr  bool
	}{
		"Load ADMX and ADML": {
			format:   "lts-only",
			wantADMX: "../../policies/Ubuntu/lts-only/Ubuntu.admx",
			wantADML: "../../policies/Ubuntu/lts-only/Ubuntu.adml",
		},

		"ADMX and ADML does not exist for this format": {
			format:  "NotExist",
			wantErr: true,
		},
		"ADMX and ADML does not exist for this distro": {
			format:   "lts-only",
			distroID: "NotExist",
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tc.distroID == "" {
				tc.distroID = "Ubuntu"
			}

			admx, adml, err := ad.GetPolicyDefinitions(context.Background(), tc.format, tc.distroID)
			if tc.wantErr {
				require.NotNil(t, err, "GetPolicyDefinitions returned no error when expecting one")
				return
			}
			require.NoError(t, err, "GetPolicyDefinitions returned an error when expecting none")

			wantADMX, err := os.ReadFile(tc.wantADMX)
			require.NoError(t, err, "Could not read wanted admx file")
			wantADML, err := os.ReadFile(tc.wantADML)
			require.NoError(t, err, "Could not read wanted adml file")

			require.Equalf(t, string(wantADMX), admx, "expected admx doesn't match")
			require.Equalf(t, string(wantADML), adml, "expected adml doesn't match")
		})
	}
}
