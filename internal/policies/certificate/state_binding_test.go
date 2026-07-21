package certificate

import (
	"context"
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
	legacyCA, currentBinding := writeStateBindingCA(t, ca)
	legacyCA.Name = "Enterprise CA"
	legacyCA.Templates = []enrolledTemplate{tmpl}
	state := &enrollmentState{
		ObjectName: "host",
		Domain:     "EXAMPLE.COM.",
		CAs:        []enrolledCA{legacyCA},
	}
	current := certAuthority{
		Name: "Enterprise CA",
		Chain: &expectedCertificateChain{
			Certificates: []*x509.Certificate{ca.cert},
			Fingerprints: []string{certificateFingerprint(ca.cert)},
		},
	}

	migrated, err := validateStoredEnrollment(state.CAs[0], tmpl, state, current, currentBinding, "host.example.com", "example.com", now)
	require.NoError(t, err)
	assert.Equal(t, rawCertificateFingerprint(pemDER(t, certPEM)), migrated.LeafFingerprint)
	assert.Equal(t, currentBinding.IssuerFingerprint, migrated.IssuerFingerprint)
	assert.Equal(t, currentBinding.Fingerprints, migrated.ChainFingerprints)
	assert.Equal(t, currentBinding.Files, migrated.ChainFiles)

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
	assert.Equal(t, currentBinding.Fingerprints, loaded.CAs[0].Templates[0].ChainFingerprints)
	assert.Equal(t, currentBinding.Files, loaded.CAs[0].Templates[0].ChainFiles)
}

func TestValidateStoredEnrollmentRejectsMismatchAndStaleBindings(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ca := newChainTestCA(t, "Enterprise CA", nil, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	key, _ := chainTestRSAKey(t)
	_, wrongKeyPEM := chainTestRSAKey(t)
	certPEM := chainTestLeaf(t, key.Public(), ca, "host.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	tmpl := writeStateBindingPair(t, wrongKeyPEM, certPEM)
	stateCA, currentBinding := writeStateBindingCA(t, ca)
	stateCA.Name = "Enterprise CA"
	current := certAuthority{
		Name: "Enterprise CA",
		Chain: &expectedCertificateChain{
			Certificates: []*x509.Certificate{ca.cert},
			Fingerprints: []string{certificateFingerprint(ca.cert)},
		},
	}

	state := &enrollmentState{Domain: "example.com", CAs: []enrolledCA{stateCA}}
	_, err := validateStoredEnrollment(state.CAs[0], tmpl, state, current, currentBinding, "host.example.com", "example.com", now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "does not match")

	validKey, validKeyPEM := chainTestRSAKey(t)
	tmpl = writeStateBindingPair(t, validKeyPEM, chainTestLeaf(t, validKey.Public(), ca, "host.example.com", now.Add(-time.Hour), now.Add(time.Hour)))

	state.Domain = "other.example"
	_, err = validateStoredEnrollment(state.CAs[0], tmpl, state, current, currentBinding, "host.example.com", "example.com", now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "state domain")

	state.Domain = "example.com"
	state.Identity = "other.example.com"
	_, err = validateStoredEnrollment(state.CAs[0], tmpl, state, current, currentBinding, "host.example.com", "example.com", now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "machine identity")

	state.Identity = "host.example.com"
	state.CAs[0].IssuerFingerprint = "deadbeef"
	state.CAs[0].ChainFingerprints = append([]string(nil), currentBinding.Fingerprints...)
	_, err = validateStoredEnrollment(state.CAs[0], tmpl, state, current, currentBinding, "host.example.com", "example.com", now)
	require.Error(t, err)
	assert.ErrorContains(t, err, "issuer fingerprint")
}

func TestRemoveUnreferencedPathsHonorsOtherObjectState(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	shared := filepath.Join(stateDir, "certs", "shared-root.crt")
	require.NoError(t, os.MkdirAll(filepath.Dir(shared), 0750))
	require.NoError(t, os.WriteFile(shared, []byte("shared"), 0600))
	for _, objectName := range []string{"host-a", "host-b"} {
		require.NoError(t, saveState(stateDir, &enrollmentState{
			ObjectName: objectName,
			Domain:     "example.com",
			CAs: []enrolledCA{{
				Name:      "Enterprise CA",
				RootCerts: []string{shared},
			}},
		}))
	}

	require.NoError(t, removeUnreferencedPaths(context.Background(), stateDir, "host-a", nil, []string{shared}))
	assert.FileExists(t, shared, "another object state still owns the shared root")

	require.NoError(t, removeState(stateDir, "host-b"))
	require.NoError(t, removeUnreferencedPaths(context.Background(), stateDir, "host-a", nil, []string{shared}))
	assert.NoFileExists(t, shared)
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

func writeStateBindingCA(t *testing.T, ca *chainTestCA) (enrolledCA, templateChainBinding) {
	t.Helper()
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.crt")
	require.NoError(t, os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.cert.Raw,
	}), 0600))
	fp := certificateFingerprint(ca.cert)
	return enrolledCA{
			IssuerFingerprint: fp,
			ChainFingerprints: []string{fp},
			RootCerts:         []string{rootPath},
		}, templateChainBinding{
			IssuerFingerprint: fp,
			Fingerprints:      []string{fp},
			Files:             []string{rootPath},
		}
}
