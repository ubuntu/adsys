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

func TestNewRejectsUnknownEnrollmentMethod(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method string

		want    string
		wantErr bool
	}{
		"LDAP is normalized":     {method: "LDAP", want: consts.CertEnrollmentLDAP},
		"cepces is normalized":   {method: " cepces ", want: consts.CertEnrollmentCEPCES},
		"unknown method errors":  {method: "certmonger", wantErr: true},
		"empty method errors":    {method: "", wantErr: true},
		"no method uses default": {want: consts.DefaultCertificateEnrollment},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			opts := []Option{
				WithStateDir(t.TempDir()),
				WithRunDir(t.TempDir()),
				WithShareDir(t.TempDir()),
				WithGlobalTrustDir(t.TempDir()),
			}
			if name != "no method uses default" {
				opts = append(opts, WithEnrollmentMethod(tc.method))
			}

			m, err := New("example.com", opts...)
			if tc.wantErr {
				require.Error(t, err, "New should reject an invalid enrollment method")
				require.Nil(t, m)
				require.Contains(t, err.Error(), tc.method)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, m.enrollmentMethod)
		})
	}
}
