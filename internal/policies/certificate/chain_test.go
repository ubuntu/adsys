package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type chainTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func TestResolveCAChainsSelectsNewestRenewalDeterministically(t *testing.T) {
	t.Parallel()

	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	oldCA := chainTestCertificate(t, "Enterprise CA", key, nil, key, now.Add(-365*24*time.Hour), now.Add(365*24*time.Hour), 1)
	newCA := chainTestCertificate(t, "Enterprise CA", key, nil, key, now.Add(-24*time.Hour), now.Add(730*24*time.Hour), 2)
	expiredCA := chainTestCertificate(t, "Enterprise CA", key, nil, key, now.Add(-2*time.Hour), now.Add(-time.Hour), 3)

	var fingerprints []string
	for _, values := range [][][]byte{
		{oldCA.Raw, expiredCA.Raw, newCA.Raw, oldCA.Raw},
		{newCA.Raw, oldCA.Raw, expiredCA.Raw},
	} {
		resolved, err := resolveCAChains([]certAuthority{{
			Name:           "Enterprise CA",
			CACertificates: values,
		}}, trustedRootValues(values...), now)
		require.NoError(t, err)
		require.Len(t, resolved, 1)
		require.NotNil(t, resolved[0].Chain)
		fingerprints = append(fingerprints, resolved[0].Chain.issuerFingerprint())
		assert.Equal(t, certificateFingerprint(newCA), resolved[0].Chain.issuerFingerprint())
	}
	assert.Equal(t, fingerprints[0], fingerprints[1])
}

func TestResolveCAChainsOfflineRootAndSubordinate(t *testing.T) {
	t.Parallel()

	now := time.Now()
	root := newChainTestCA(t, "Offline Root", nil, now.Add(-365*24*time.Hour), now.Add(10*365*24*time.Hour), 1)
	subordinate := newChainTestCA(t, "Enterprise Issuing CA", root, now.Add(-24*time.Hour), now.Add(365*24*time.Hour), 2)

	resolved, err := resolveCAChains([]certAuthority{{
		Name:           "Enterprise Issuing CA",
		CACertificates: [][]byte{subordinate.cert.Raw},
	}}, trustedRootValues(root.cert.Raw, root.cert.Raw), now)
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	require.Len(t, resolved[0].Chain.Certificates, 2)
	assert.Equal(t, certificateFingerprint(subordinate.cert), resolved[0].Chain.Fingerprints[0])
	assert.Equal(t, certificateFingerprint(root.cert), resolved[0].Chain.Fingerprints[1])

	key, keyPEM := chainTestRSAKey(t)
	leaf := chainTestLeaf(t, key.Public(), subordinate, "host.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	verified, err := verifyIssuedCertificate(
		string(leaf),
		keyPEM,
		"host.example.com",
		resolved[0].Chain.Certificates,
		now,
	)
	require.NoError(t, err)
	assert.Equal(t, "host.example.com", verified.Subject.CommonName)
}

func TestResolveCAChainsRequiresTrustedRootPublication(t *testing.T) {
	t.Parallel()

	now := time.Now()
	root := newChainTestCA(t, "Enterprise Root", nil, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	subordinate := newChainTestCA(t, "Enterprise Issuer", root, now.Add(-time.Hour), now.Add(12*time.Hour), 2)

	tests := map[string]struct {
		caValues  [][]byte
		directory []directoryCACertificate
		wantErr   bool
	}{
		"self-signed only on enrollment service": {
			caValues: [][]byte{root.cert.Raw},
			wantErr:  true,
		},
		"self-signed only in AIA": {
			caValues: [][]byte{subordinate.cert.Raw},
			directory: []directoryCACertificate{
				{DER: root.cert.Raw, Source: certificateSourceAIA},
			},
			wantErr: true,
		},
		"offline root in trusted container": {
			caValues: [][]byte{subordinate.cert.Raw},
			directory: []directoryCACertificate{
				{DER: root.cert.Raw, Source: certificateSourceTrustedRoot},
				{DER: subordinate.cert.Raw, Source: certificateSourceAIA},
			},
		},
		"enterprise root duplicated in trusted container": {
			caValues: [][]byte{root.cert.Raw},
			directory: []directoryCACertificate{
				{DER: root.cert.Raw, Source: certificateSourceAIA},
				{DER: root.cert.Raw, Source: certificateSourceTrustedRoot},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			resolved, err := resolveCAChains([]certAuthority{{
				Name:           "Enterprise CA",
				CACertificates: tc.caValues,
			}}, tc.directory, now)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorContains(t, err, "Certification Authorities")
				return
			}
			require.NoError(t, err)
			require.Len(t, resolved, 1)
			assert.Equal(t, certificateFingerprint(root.cert), certificateFingerprint(resolved[0].Chain.root()))
		})
	}
}

func TestResolveCAChainsRejectsMissingAndMalformedValues(t *testing.T) {
	t.Parallel()

	now := time.Now()
	_, err := resolveCAChains([]certAuthority{{Name: "Missing"}}, nil, now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "no cACertificate")

	_, err = resolveCAChains([]certAuthority{{
		Name:           "Malformed",
		CACertificates: [][]byte{{1, 2, 3}},
	}}, nil, now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid cACertificate")
}

func TestVerifyIssuedCertificateRejectsUnrelatedCAAndKey(t *testing.T) {
	t.Parallel()

	now := time.Now()
	expectedCA := newChainTestCA(t, "Expected CA", nil, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	unrelatedCA := newChainTestCA(t, "Unrelated CA", nil, now.Add(-time.Hour), now.Add(24*time.Hour), 2)

	key, keyPEM := chainTestRSAKey(t)
	leaf := chainTestLeaf(t, key.Public(), unrelatedCA, "host.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	_, err := verifyIssuedCertificate(string(leaf), keyPEM, "host.example.com", []*x509.Certificate{expectedCA.cert}, now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "selected issuing CA")

	otherKey, otherKeyPEM := chainTestRSAKey(t)
	_ = otherKey
	expectedLeaf := chainTestLeaf(t, key.Public(), expectedCA, "host.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	_, err = verifyIssuedCertificate(string(expectedLeaf), otherKeyPEM, "host.example.com", []*x509.Certificate{expectedCA.cert}, now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "does not match")

	wrongIdentityLeaf := chainTestLeaf(t, key.Public(), expectedCA, "other.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	_, err = verifyIssuedCertificate(string(wrongIdentityLeaf), keyPEM, "host.example.com", []*x509.Certificate{expectedCA.cert}, now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "machine identity")
}

func newChainTestCA(t *testing.T, subject string, parent *chainTestCA, notBefore, notAfter time.Time, serial int64) *chainTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var parentCert *x509.Certificate
	parentKey := key
	if parent != nil {
		parentCert = parent.cert
		parentKey = parent.key
	}
	cert := chainTestCertificate(t, subject, key, parentCert, parentKey, notBefore, notAfter, serial)
	return &chainTestCA{cert: cert, key: key}
}

func chainTestCertificate(t *testing.T, subject string, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time, serial int64) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: subject},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
	}
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func chainTestRSAKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func chainTestLeaf(t *testing.T, publicKey any, issuer *chainTestCA, identity string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: identity},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, publicKey, issuer.key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func trustedRootValues(values ...[]byte) []directoryCACertificate {
	published := make([]directoryCACertificate, 0, len(values))
	for _, value := range values {
		published = append(published, directoryCACertificate{
			DER:    value,
			Source: certificateSourceTrustedRoot,
		})
	}
	return published
}
