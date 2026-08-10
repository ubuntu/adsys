package certificate

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/consts"
)

func TestNormalizeEnrollmentMethod(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method string
		want   string
		ok     bool
	}{
		"empty":       {},
		"LDAP":        {method: "LDAP", want: consts.CertEnrollmentLDAP, ok: true},
		"cepces":      {method: " cepces ", want: consts.CertEnrollmentCEPCES, ok: true},
		"unsupported": {method: "certmonger"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, ok := normalizeEnrollmentMethod(tc.method)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.want, got)
		})
	}
}
