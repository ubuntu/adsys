package adcommon_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	adcommon "github.com/ubuntu/adsys/internal/ad/common"
)

func TestGetVersionID(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		want    string
		wantErr bool
	}{
		"Read VERSION_ID": {
			want: "21.04",
		},

		"No VERSION_ID in file": {
			wantErr: true,
		},
		"No os-release file": {
			wantErr: true,
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			versionID, err := adcommon.GetVersionID(filepath.Join("testdata", name))

			if tc.wantErr {
				require.NotNil(t, err, "GetVersionID returned no error when expecting one")
				return
			}
			require.NoError(t, err, "GetVersionID returned an error when expecting none")

			require.Equalf(t, tc.want, versionID, "expected value from GetVersionID doesn't match")
		})
	}
}
