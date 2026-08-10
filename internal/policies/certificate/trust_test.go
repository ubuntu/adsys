package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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

			_, _, _, err := installCAChain(certAuthority{
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
	existingTrustFile := filepath.Join(globalTrustDir, trustArtifactFileName(certAuthority{Name: "TestCA"}, cert, "root"))
	require.NoError(t, os.WriteFile(existingTrustFile, []byte("existing"), 0600))

	_, _, _, err = installCAChain(certAuthority{
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

func TestInstallCAChainRollbackPreservesExistingArtifacts(t *testing.T) {
	t.Parallel()

	now := time.Now()
	root := newChainTestCA(t, "Offline Root", nil, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	oldIssuer := newChainTestCA(t, "Enterprise Issuer", root, now.Add(-time.Hour), now.Add(12*time.Hour), 2)
	newIssuer := newChainTestCA(t, "Enterprise Issuer", root, now.Add(-30*time.Minute), now.Add(18*time.Hour), 3)
	trustDir := t.TempDir()
	globalTrustDir := t.TempDir()

	oldInstallation, err := installCAChainTransaction(certAuthority{
		Name: "Enterprise Issuer",
		Chain: &expectedCertificateChain{
			Certificates: []*x509.Certificate{oldIssuer.cert, root.cert},
			Fingerprints: []string{certificateFingerprint(oldIssuer.cert), certificateFingerprint(root.cert)},
		},
	}, trustDir, globalTrustDir)
	require.NoError(t, err)
	require.Len(t, oldInstallation.RootFiles, 1)
	require.Len(t, oldInstallation.IntermediateFiles, 1)
	require.Len(t, oldInstallation.SymlinkFiles, 1)

	oldRoot, err := os.ReadFile(oldInstallation.RootFiles[0])
	require.NoError(t, err)
	oldIssuerPEM, err := os.ReadFile(oldInstallation.IntermediateFiles[0])
	require.NoError(t, err)
	oldLinkTarget, err := os.Readlink(oldInstallation.SymlinkFiles[0])
	require.NoError(t, err)
	fixedTime := now.Add(-6 * time.Hour)
	require.NoError(t, os.Chtimes(oldInstallation.RootFiles[0], fixedTime, fixedTime))

	_, err = installCAChainTransactionWithOps(certAuthority{
		Name: "Enterprise Issuer",
		Chain: &expectedCertificateChain{
			Certificates: []*x509.Certificate{newIssuer.cert, root.cert},
			Fingerprints: []string{certificateFingerprint(newIssuer.cert), certificateFingerprint(root.cert)},
		},
	}, trustDir, globalTrustDir, trustInstallOps{
		replaceSymlink: atomicSymlink,
		beforeSymlink: func() error {
			return fmt.Errorf("injected publication failure")
		},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "injected publication failure")

	gotRoot, err := os.ReadFile(oldInstallation.RootFiles[0])
	require.NoError(t, err)
	assert.Equal(t, oldRoot, gotRoot)
	gotIssuer, err := os.ReadFile(oldInstallation.IntermediateFiles[0])
	require.NoError(t, err)
	assert.Equal(t, oldIssuerPEM, gotIssuer)
	gotTarget, err := os.Readlink(oldInstallation.SymlinkFiles[0])
	require.NoError(t, err)
	assert.Equal(t, oldLinkTarget, gotTarget)
	rootInfo, err := os.Stat(oldInstallation.RootFiles[0])
	require.NoError(t, err)
	assert.True(t, rootInfo.ModTime().Equal(fixedTime), "identical preexisting root was rewritten")

	newIssuerPath := filepath.Join(
		trustDir,
		trustArtifactFileName(certAuthority{Name: "Enterprise Issuer"}, newIssuer.cert, "issuer"),
	)
	assert.NoFileExists(t, newIssuerPath, "failed attempt must remove only its newly published issuer")
	entries, err := os.ReadDir(trustDir)
	require.NoError(t, err)
	for _, entry := range entries {
		assert.False(t, strings.Contains(entry.Name(), ".stage."), "staged certificate leaked after rollback")
	}
}

func TestInstallCAChainRollbackRestoresReplacedSymlink(t *testing.T) {
	t.Parallel()

	now := time.Now()
	root := newChainTestCA(t, "Enterprise Root", nil, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	trustDir := t.TempDir()
	globalTrustDir := t.TempDir()
	fingerprint := certificateFingerprint(root.cert)
	fileName := trustArtifactFileName(certAuthority{Name: "Enterprise CA"}, root.cert, "root")
	rootPath := filepath.Join(trustDir, fileName)
	require.NoError(t, os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root.cert.Raw,
	}), 0600))
	previousTarget := filepath.Join(trustDir, "previous-root.crt")
	require.NoError(t, os.WriteFile(previousTarget, []byte("previous"), 0600))
	symlinkPath := filepath.Join(globalTrustDir, fileName)
	require.NoError(t, os.Symlink(previousTarget, symlinkPath))

	installation, err := installCAChainTransaction(certAuthority{
		Name: "Enterprise CA",
		Chain: &expectedCertificateChain{
			Certificates: []*x509.Certificate{root.cert},
			Fingerprints: []string{fingerprint},
		},
	}, trustDir, globalTrustDir)
	require.NoError(t, err)
	target, err := os.Readlink(symlinkPath)
	require.NoError(t, err)
	assert.Equal(t, rootPath, target)

	require.NoError(t, installation.rollback())
	target, err = os.Readlink(symlinkPath)
	require.NoError(t, err)
	assert.Equal(t, previousTarget, target)
	assert.FileExists(t, rootPath, "rollback removed a preexisting certificate")
}

func TestInstallCAChainDistinctIdentitiesAvoidCollision(t *testing.T) {
	t.Parallel()

	now := time.Now()
	// A single shared offline root that both CAs chain to.
	root := newChainTestCA(t, "Shared Offline Root", nil, now.Add(-time.Hour), now.Add(365*24*time.Hour), 1)
	chain := &expectedCertificateChain{
		Certificates: []*x509.Certificate{root.cert},
		Fingerprints: []string{certificateFingerprint(root.cert)},
	}
	trustDir := t.TempDir()
	globalTrustDir := t.TempDir()

	// "Corp CA" and "Corp-CA" sanitize to the same nickname and, sharing a
	// root certificate, previously collided on the same artifact paths.
	caA := certAuthority{Name: "Corp CA", Hostname: "ca.example.com", Chain: chain}
	caB := certAuthority{Name: "Corp-CA", Hostname: "ca.example.com", Chain: chain}

	instA, err := installCAChainTransaction(caA, trustDir, globalTrustDir)
	require.NoError(t, err)
	instB, err := installCAChainTransaction(caB, trustDir, globalTrustDir)
	require.NoError(t, err)

	require.NotEqual(t, instA.RootFiles[0], instB.RootFiles[0], "distinct CA identities shared a root path")
	require.NotEqual(t, instA.SymlinkFiles[0], instB.SymlinkFiles[0], "distinct CA identities shared a symlink path")

	// The unsuccessful CA rolling back must not disturb the committed CA.
	require.NoError(t, instB.rollback())
	assert.FileExists(t, instA.RootFiles[0], "the committed CA root was deleted by the other CA rollback")
	targetA, err := os.Readlink(instA.SymlinkFiles[0])
	require.NoError(t, err)
	assert.Equal(t, instA.RootFiles[0], targetA, "the committed CA trust binding was broken by the other CA rollback")
	assert.NoFileExists(t, instB.RootFiles[0], "the rolled-back CA left its own root behind")
	assert.NoFileExists(t, instB.SymlinkFiles[0], "the rolled-back CA left its own symlink behind")
}

func TestInstallationRollbackAggregatesFailures(t *testing.T) {
	t.Parallel()

	t.Run("failed symlink restoration is reported and preserved", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		symlinkPath := filepath.Join(dir, "anchor.crt")
		installedTarget := filepath.Join(dir, "new-root.crt")
		previousTarget := filepath.Join(dir, "old-root.crt")
		require.NoError(t, os.WriteFile(installedTarget, []byte("new"), 0600))
		require.NoError(t, os.WriteFile(previousTarget, []byte("old"), 0600))
		require.NoError(t, os.Symlink(installedTarget, symlinkPath))
		info, err := os.Lstat(symlinkPath)
		require.NoError(t, err)

		installation := &caChainInstallation{
			restoreSymlink: func(string, string) error { return fmt.Errorf("injected restore failure") },
			symlinkChanges: []symlinkChange{{
				path:            symlinkPath,
				installedTarget: installedTarget,
				previousTarget:  previousTarget,
				hadPrevious:     true,
				installedInfo:   info,
			}},
		}
		err = installation.rollback()
		require.Error(t, err)
		assert.ErrorContains(t, err, "injected restore failure")
		assert.ErrorContains(t, err, symlinkPath, "rollback error must name the affected path for a later repair")

		target, err := os.Readlink(symlinkPath)
		require.NoError(t, err)
		assert.Equal(t, installedTarget, target, "the unrestored symlink must be left in place for a later attempt")
	})

	t.Run("failed file removal is reported and preserved", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		created := filepath.Join(dir, "published.crt")
		now := time.Now()
		root := newChainTestCA(t, "Root", nil, now.Add(-time.Hour), now.Add(time.Hour), 1)
		require.NoError(t, os.WriteFile(created, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: root.cert.Raw,
		}), 0600))
		info, err := os.Lstat(created)
		require.NoError(t, err)

		installation := &caChainInstallation{
			removeFile: func(string) error { return fmt.Errorf("injected remove failure") },
			createdFiles: []createdCertificateFile{{
				path: created,
				raw:  append([]byte(nil), root.cert.Raw...),
				info: info,
			}},
		}
		err = installation.rollback()
		require.Error(t, err)
		assert.ErrorContains(t, err, "injected remove failure")
		assert.ErrorContains(t, err, created, "rollback error must name the leftover artifact for a later attempt")
		assert.FileExists(t, created, "the artifact must remain so a later attempt can adopt or repair it")
	})
}

func TestWithRollbackClassifiesLeftoverTrustArtifacts(t *testing.T) {
	t.Parallel()

	primary := fmt.Errorf("injected installation failure")
	assert.False(t, containsRollbackFailure(withRollback(&caChainInstallation{}, primary)))

	dir := t.TempDir()
	path := filepath.Join(dir, "leftover.crt")
	now := time.Now()
	root := newChainTestCA(t, "Root", nil, now.Add(-time.Hour), now.Add(time.Hour), 1)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw}), 0600))
	info, err := os.Lstat(path)
	require.NoError(t, err)
	installation := &caChainInstallation{
		removeFile: func(string) error { return fmt.Errorf("injected cleanup failure") },
		createdFiles: []createdCertificateFile{{
			path: path,
			raw:  root.cert.Raw,
			info: info,
		}},
	}

	err = withRollback(installation, primary)
	require.Error(t, err)
	assert.True(t, containsRollbackFailure(err))
	assert.ErrorContains(t, err, "injected installation failure")
	assert.ErrorContains(t, err, "injected cleanup failure")
	assert.FileExists(t, path)
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
