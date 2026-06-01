package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallRootCACertsRejectsInvalidCA(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		isCA     bool
		keyUsage x509.KeyUsage
	}{
		"not a CA certificate": {
			isCA: false,
		},
		"CA without certificate signing usage": {
			isCA:     true,
			keyUsage: x509.KeyUsageDigitalSignature,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			trustDir := t.TempDir()
			globalTrustDir := t.TempDir()

			_, _, err := installRootCACerts(certAuthority{
				Name:          "TestCA",
				CACertificate: testCertificateDER(t, tc.isCA, tc.keyUsage),
			}, trustDir, globalTrustDir)
			require.Error(t, err)
			require.NoFileExists(t, filepath.Join(trustDir, "TestCA.crt"))
			require.NoFileExists(t, filepath.Join(globalTrustDir, "TestCA.crt"))
		})
	}
}

func TestInstallRootCACertsRefusesToOverwriteRegularTrustFile(t *testing.T) {
	t.Parallel()

	trustDir := t.TempDir()
	globalTrustDir := t.TempDir()
	existingTrustFile := filepath.Join(globalTrustDir, "TestCA.crt")
	require.NoError(t, os.WriteFile(existingTrustFile, []byte("existing"), 0600))

	_, _, err := installRootCACerts(certAuthority{
		Name:          "TestCA",
		CACertificate: testCertificateDER(t, true, x509.KeyUsageCertSign),
	}, trustDir, globalTrustDir)
	require.Error(t, err)

	got, err := os.ReadFile(existingTrustFile)
	require.NoError(t, err)
	require.Equal(t, "existing", string(got))
}

func testCertificateDER(t *testing.T, isCA bool, keyUsage x509.KeyUsage) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER
}
