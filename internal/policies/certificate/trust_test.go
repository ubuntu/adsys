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
	"time"

	"github.com/stretchr/testify/assert"
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
	caDER := testCertificateDER(t, true, x509.KeyUsageCertSign)
	cert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	existingTrustFile := filepath.Join(globalTrustDir, "TestCA.root."+certificateFingerprint(cert)[:16]+".crt")
	require.NoError(t, os.WriteFile(existingTrustFile, []byte("existing"), 0600))

	_, _, err = installRootCACerts(certAuthority{
		Name:          "TestCA",
		CACertificate: caDER,
	}, trustDir, globalTrustDir)
	require.Error(t, err)

	got, err := os.ReadFile(existingTrustFile)
	require.NoError(t, err)
	require.Equal(t, "existing", string(got))
}

func TestInstallCAChainSeparatesSubordinateAndRoot(t *testing.T) {
	t.Parallel()

	now := time.Now()
	root := newChainTestCA(t, "Offline Root", nil, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	issuer := newChainTestCA(t, "Enterprise Issuer", root, now.Add(-time.Hour), now.Add(12*time.Hour), 2)
	chain := &expectedCertificateChain{
		Certificates: []*x509.Certificate{issuer.cert, root.cert},
		Fingerprints: []string{certificateFingerprint(issuer.cert), certificateFingerprint(root.cert)},
	}
	trustDir := t.TempDir()
	globalTrustDir := t.TempDir()

	roots, intermediates, symlinks, err := installCAChain(certAuthority{
		Name:  "Enterprise Issuer",
		Chain: chain,
	}, trustDir, globalTrustDir)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.Len(t, intermediates, 1)
	require.Len(t, symlinks, 1)
	require.FileExists(t, roots[0])
	require.FileExists(t, intermediates[0])
	info, err := os.Lstat(symlinks[0])
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink)
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
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER
}
