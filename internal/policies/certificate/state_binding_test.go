package certificate

import (
	"context"
	"crypto/x509"
	"encoding/json"
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
	ownedKey := filepath.Join(stateDir, "private", "legacy.key")
	ownedCert := filepath.Join(stateDir, "certs", "legacy.crt")
	ownedRoot := filepath.Join(stateDir, "certs", "root.crt")
	require.NoError(t, os.MkdirAll(filepath.Dir(ownedKey), 0700))
	require.NoError(t, os.MkdirAll(filepath.Dir(ownedCert), 0750))
	require.NoError(t, copyFileForTest(migrated.KeyFile, ownedKey))
	require.NoError(t, copyFileForTest(migrated.CertFile, ownedCert))
	require.NoError(t, copyFileForTest(currentBinding.Files[0], ownedRoot))
	state.CAs[0].RootCerts = []string{ownedRoot}
	state.CAs[0].Templates[0].KeyFile = ownedKey
	state.CAs[0].Templates[0].CertFile = ownedCert
	state.CAs[0].Templates[0].ChainFiles = []string{ownedRoot}
	require.NoError(t, saveState(stateDir, state))
	loaded, err := loadState(stateDir, "host", "example.com")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "host.example.com", loaded.Identity)
	assert.Equal(t, current.Chain.issuerFingerprint(), loaded.CAs[0].IssuerFingerprint)
	assert.Equal(t, migrated.LeafFingerprint, loaded.CAs[0].Templates[0].LeafFingerprint)
	assert.Equal(t, currentBinding.Fingerprints, loaded.CAs[0].Templates[0].ChainFingerprints)
	assert.Equal(t, []string{ownedRoot}, loaded.CAs[0].Templates[0].ChainFiles)
}

func copyFileForTest(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0600) //nolint:gosec // Test-owned destination copied from fixture state.
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

	require.NoError(t, removeUnreferencedPaths(context.Background(), stateDir, filepath.Join(stateDir, "trust"), "host-a", "example.com", nil, []string{shared}))
	assert.FileExists(t, shared, "another object state still owns the shared root")

	require.NoError(t, removeState(stateDir, "host-b", "example.com"))
	require.NoError(t, removeUnreferencedPaths(context.Background(), stateDir, filepath.Join(stateDir, "trust"), "host-a", "example.com", nil, []string{shared}))
	assert.NoFileExists(t, shared)
}

func TestStateFileCollisionAndLegacyMigration(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	legacy := &enrollmentState{
		ObjectName: "host-",
		Identity:   "host-.example.com",
		Domain:     "example.com",
		CAs: []enrolledCA{{
			Name:     "Test CA",
			Hostname: "ca.example.com",
			Templates: []enrolledTemplate{{
				Nickname: "Test-CA.Machine",
				Template: "Machine",
			}},
		}},
	}
	data, err := json.Marshal(legacy)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(legacyStateFilePath(stateDir, "host-")), 0750))
	require.NoError(t, os.WriteFile(legacyStateFilePath(stateDir, "host-"), data, 0600))

	require.NotEqual(t, stateFilePath(stateDir, "host$"), stateFilePath(stateDir, "host-"))

	foreign, err := loadState(stateDir, "host$", "example.com")
	require.NoError(t, err)
	assert.Nil(t, foreign)
	assert.FileExists(t, legacyStateFilePath(stateDir, "host-"), "foreign legacy state must not be removed")

	migrated, err := loadState(stateDir, "host-", "example.com")
	require.NoError(t, err)
	require.NotNil(t, migrated)
	assert.Equal(t, "host-", migrated.ObjectName)
	assert.FileExists(t, stateFilePath(stateDir, "host-"))
	assert.NoFileExists(t, legacyStateFilePath(stateDir, "host-"))
}

func TestStateEnumerationPrefersCanonicalStateOverLegacyDuplicate(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	stalePath := filepath.Join(stateDir, "certs", "stale.crt")
	require.NoError(t, os.MkdirAll(filepath.Dir(stalePath), 0750))
	require.NoError(t, os.WriteFile(stalePath, []byte("stale"), 0600))

	canonical := &enrollmentState{
		ObjectName: "host-a",
		Identity:   "host-a.example.com",
		Domain:     "example.com",
	}
	require.NoError(t, saveState(stateDir, canonical))
	legacy := cloneEnrollmentState(canonical)
	legacy.CAs = []enrolledCA{{Name: "Test CA", RootCerts: []string{stalePath}}}
	require.NoError(t, writeStateFile(legacyStateFilePath(stateDir, "host-a"), legacy))

	require.NoError(t, removeUnreferencedPaths(
		context.Background(),
		stateDir,
		filepath.Join(stateDir, "trust"),
		"host-b",
		"example.com",
		nil,
		[]string{stalePath},
	))
	assert.NoFileExists(t, stalePath, "stale duplicate legacy state must not keep a path referenced")
}

func TestRemoveOwnedEnrollmentPathContainment(t *testing.T) {
	t.Run("external regular file", func(t *testing.T) {
		base := t.TempDir()
		stateDir := filepath.Join(base, "state")
		trustDir := filepath.Join(base, "trust")
		external := filepath.Join(base, "external.crt")
		require.NoError(t, os.WriteFile(external, []byte("foreign"), 0600))

		err := removeOwnedEnrollmentPath(stateDir, trustDir, external)
		require.Error(t, err)
		assert.ErrorContains(t, err, "outside ADSys-owned")
		assert.FileExists(t, external)
	})

	t.Run("intermediate symlink", func(t *testing.T) {
		base := t.TempDir()
		stateDir := filepath.Join(base, "state")
		trustDir := filepath.Join(base, "trust")
		privateRoot := filepath.Join(stateDir, "private")
		externalDir := filepath.Join(base, "external")
		require.NoError(t, os.MkdirAll(privateRoot, 0700))
		require.NoError(t, os.MkdirAll(externalDir, 0700))
		victim := filepath.Join(externalDir, "victim.key")
		require.NoError(t, os.WriteFile(victim, []byte("foreign"), 0600))
		require.NoError(t, os.Symlink(externalDir, filepath.Join(privateRoot, "escape")))

		err := removeOwnedEnrollmentPath(stateDir, trustDir, filepath.Join(privateRoot, "escape", "victim.key"))
		require.Error(t, err)
		assert.ErrorContains(t, err, "not a regular directory")
		assert.FileExists(t, victim)
	})

	t.Run("malicious final symlinks", func(t *testing.T) {
		base := t.TempDir()
		stateDir := filepath.Join(base, "state")
		trustDir := filepath.Join(base, "trust")
		privateRoot := filepath.Join(stateDir, "private", "certs")
		require.NoError(t, os.MkdirAll(privateRoot, 0700))
		require.NoError(t, os.MkdirAll(trustDir, 0750))
		external := filepath.Join(base, "foreign")
		require.NoError(t, os.WriteFile(external, []byte("foreign"), 0600))
		keyLink := filepath.Join(privateRoot, "legacy.key")
		trustLink := filepath.Join(trustDir, "foreign.crt")
		require.NoError(t, os.Symlink(external, keyLink))
		require.NoError(t, os.Symlink(external, trustLink))

		require.Error(t, removeOwnedEnrollmentPath(stateDir, trustDir, keyLink))
		require.Error(t, removeOwnedEnrollmentPath(stateDir, trustDir, trustLink))
		assert.FileExists(t, keyLink)
		assert.FileExists(t, trustLink)
		assert.FileExists(t, external)
	})

	t.Run("valid legacy paths and trust symlink", func(t *testing.T) {
		base := t.TempDir()
		stateDir := filepath.Join(base, "state")
		trustDir := filepath.Join(base, "trust")
		key := filepath.Join(stateDir, "private", "certs", "legacy.key")
		cert := filepath.Join(stateDir, "certs", "legacy.crt")
		link := filepath.Join(trustDir, "legacy.crt")
		require.NoError(t, os.MkdirAll(filepath.Dir(key), 0700))
		require.NoError(t, os.MkdirAll(filepath.Dir(cert), 0750))
		require.NoError(t, os.MkdirAll(trustDir, 0750))
		require.NoError(t, os.WriteFile(key, []byte("key"), 0600))
		require.NoError(t, os.WriteFile(cert, []byte("cert"), 0600))
		require.NoError(t, os.Symlink(cert, link))

		require.NoError(t, removeOwnedEnrollmentPath(stateDir, trustDir, link))
		require.NoError(t, removeOwnedEnrollmentPath(stateDir, trustDir, key))
		require.NoError(t, removeOwnedEnrollmentPath(stateDir, trustDir, cert))
		assert.NoFileExists(t, link)
		assert.NoFileExists(t, key)
		assert.NoFileExists(t, cert)
	})
}

func TestLegacyStateMigrationRejectsExternalArtifacts(t *testing.T) {
	base := t.TempDir()
	stateDir := filepath.Join(base, "state")
	trustDir := filepath.Join(base, "trust")
	externalKey := filepath.Join(base, "external.key")
	externalCert := filepath.Join(base, "external.crt")
	require.NoError(t, os.WriteFile(externalKey, []byte("key"), 0600))
	require.NoError(t, os.WriteFile(externalCert, []byte("cert"), 0600))
	state := &enrollmentState{
		ObjectName: "host",
		Identity:   "host.example.com",
		Domain:     "example.com",
		CAs: []enrolledCA{{
			Name: "TestCA",
			Templates: []enrolledTemplate{{
				Nickname: "TestCA.Machine",
				Template: "Machine",
				KeyFile:  externalKey,
				CertFile: externalCert,
			}},
		}},
	}
	legacyPath := legacyStateFilePath(stateDir, "host")
	require.NoError(t, writeStateFile(legacyPath, state))

	loaded, err := loadStateWithOwnedRoots(stateDir, trustDir, "host", "example.com")
	require.Error(t, err)
	assert.Nil(t, loaded)
	assert.ErrorContains(t, err, "outside owned root")
	assert.FileExists(t, legacyPath)
	assert.NoFileExists(t, stateFilePath(stateDir, "host"))
	assert.FileExists(t, externalKey)
	assert.FileExists(t, externalCert)
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
	enrolled := enrolledCA{
		IssuerFingerprint: fp,
		ChainFingerprints: []string{fp},
		RootCerts:         []string{rootPath},
	}
	template := templateChainBinding{
		IssuerFingerprint: fp,
		Fingerprints:      []string{fp},
		Files:             []string{rootPath},
	}
	return enrolled, template
}
