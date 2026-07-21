package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateStoredEnrollmentMigratesValidLegacyState(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ca := newChainTestCA(t, "Enterprise CA", nil, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	key, keyPEM := chainTestRSAKey(t)
	certPEM := chainTestLeaf(t, key.Public(), ca, "host.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	tmpl := writeStateBindingPair(t, keyPEM, certPEM)
	state := &enrollmentState{
		ObjectName: "host",
		Domain:     "EXAMPLE.COM.",
		CAs:        []enrolledCA{{Name: "Enterprise CA", Templates: []enrolledTemplate{tmpl}}},
	}
	current := certAuthority{
		Name: "Enterprise CA",
		Chain: &expectedCertificateChain{
			Certificates: []*x509.Certificate{ca.cert},
			Fingerprints: []string{certificateFingerprint(ca.cert)},
		},
	}

	migrated, err := validateStoredEnrollment(state.CAs[0], tmpl, state, current, "host.example.com", "example.com", now)
	require.NoError(t, err)
	assert.Equal(t, rawCertificateFingerprint(pemDER(t, certPEM)), migrated.LeafFingerprint)

	state.Identity = "host.example.com"
	state.Domain = "example.com"
	state.CAs[0].IssuerFingerprint = current.Chain.issuerFingerprint()
	state.CAs[0].ChainFingerprints = append([]string(nil), current.Chain.Fingerprints...)
	state.CAs[0].Templates[0] = migrated
	stateDir := t.TempDir()
	require.NoError(t, saveState(stateDir, state))
	loaded, err := loadState(stateDir, "host")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "host.example.com", loaded.Identity)
	assert.Equal(t, current.Chain.issuerFingerprint(), loaded.CAs[0].IssuerFingerprint)
	assert.Equal(t, migrated.LeafFingerprint, loaded.CAs[0].Templates[0].LeafFingerprint)
}

func TestValidateStoredEnrollmentRejectsMismatchAndStaleBindings(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ca := newChainTestCA(t, "Enterprise CA", nil, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	key, _ := chainTestRSAKey(t)
	_, wrongKeyPEM := chainTestRSAKey(t)
	certPEM := chainTestLeaf(t, key.Public(), ca, "host.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	tmpl := writeStateBindingPair(t, wrongKeyPEM, certPEM)
	current := certAuthority{
		Name: "Enterprise CA",
		Chain: &expectedCertificateChain{
			Certificates: []*x509.Certificate{ca.cert},
			Fingerprints: []string{certificateFingerprint(ca.cert)},
		},
	}

	state := &enrollmentState{Domain: "example.com", CAs: []enrolledCA{{Name: "Enterprise CA"}}}
	_, err := validateStoredEnrollment(state.CAs[0], tmpl, state, current, "host.example.com", "example.com", now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "does not match")

	validKey, validKeyPEM := chainTestRSAKey(t)
	tmpl = writeStateBindingPair(t, validKeyPEM, chainTestLeaf(t, validKey.Public(), ca, "host.example.com", now.Add(-time.Hour), now.Add(time.Hour)))

	state.Domain = "other.example"
	_, err = validateStoredEnrollment(state.CAs[0], tmpl, state, current, "host.example.com", "example.com", now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "state domain")

	state.Domain = "example.com"
	state.Identity = "other.example.com"
	_, err = validateStoredEnrollment(state.CAs[0], tmpl, state, current, "host.example.com", "example.com", now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "machine identity")

	state.Identity = "host.example.com"
	state.CAs[0].IssuerFingerprint = "deadbeef"
	_, err = validateStoredEnrollment(state.CAs[0], tmpl, state, current, "host.example.com", "example.com", now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "issuing CA fingerprint")
}

func writeStateBindingPair(t *testing.T, keyPEM, certPEM []byte) enrolledTemplate {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "host.key")
	certPath := filepath.Join(dir, "host.crt")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	return enrolledTemplate{
		Nickname: "Enterprise-CA.Machine",
		Template: "Machine",
		KeyFile:  keyPath,
		CertFile: certPath,
	}
}

func pemDER(t *testing.T, value []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(value)
	require.NotNil(t, block)
	return block.Bytes
}
