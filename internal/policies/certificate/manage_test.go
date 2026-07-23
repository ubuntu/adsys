package certificate

import (
	"context"
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

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/entry"
)

const mgrTestDomain = "example.com"
const mgrTestObject = "keypress"

func TestListCertificates(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "state")
	now := time.Now()

	// Build one template per health outcome, each with its own on-disk files.
	var templates []enrolledTemplate

	// healthy: valid well beyond the renewal window, key matches.
	healthyKey, healthyKeyPEM := mgrKeyPEM(t)
	healthyCertPEM := mgrSelfSigned(t, healthyKey, "healthy", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	templates = append(templates, mgrWritePair(t, stateDir, "healthy", "Machine", healthyKeyPEM, healthyCertPEM))

	// due_renewal: still valid, but a third of its lifetime exceeds the
	// remaining validity, so it sits inside its bounded renewal window.
	dueKey, dueKeyPEM := mgrKeyPEM(t)
	dueCertPEM := mgrSelfSigned(t, dueKey, "due", now.Add(-26*24*time.Hour), now.Add(5*24*time.Hour))
	templates = append(templates, mgrWritePair(t, stateDir, "due", "Machine", dueKeyPEM, dueCertPEM))

	// short-lived healthy: a freshly issued 6-day certificate is well outside
	// its bounded renewal window and must not report due_renewal.
	shortKey, shortKeyPEM := mgrKeyPEM(t)
	shortCertPEM := mgrSelfSigned(t, shortKey, "short", now.Add(-time.Hour), now.Add(6*24*time.Hour))
	templates = append(templates, mgrWritePair(t, stateDir, "short", "Machine", shortKeyPEM, shortCertPEM))

	// not yet valid: issuance clock skew produced a certificate whose validity
	// window starts tomorrow; it must not report healthy.
	futureKey, futureKeyPEM := mgrKeyPEM(t)
	futureCertPEM := mgrSelfSigned(t, futureKey, "future", now.Add(24*time.Hour), now.Add(30*24*time.Hour))
	templates = append(templates, mgrWritePair(t, stateDir, "future", "Machine", futureKeyPEM, futureCertPEM))

	// expired: NotAfter in the past, key matches.
	expiredKey, expiredKeyPEM := mgrKeyPEM(t)
	expiredCertPEM := mgrSelfSigned(t, expiredKey, "expired", now.Add(-48*time.Hour), now.Add(-time.Hour))
	templates = append(templates, mgrWritePair(t, stateDir, "expired", "Machine", expiredKeyPEM, expiredCertPEM))

	// key_mismatch: cert present and valid but the on-disk key is a different key.
	certKey, _ := mgrKeyPEM(t)
	_, otherKeyPEM := mgrKeyPEM(t)
	mismatchCertPEM := mgrSelfSigned(t, certKey, "mismatch", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	templates = append(templates, mgrWritePair(t, stateDir, "mismatch", "Machine", otherKeyPEM, mismatchCertPEM))

	// unparseable: garbage certificate file, key present so OnDisk is true.
	_, unparseKeyPEM := mgrKeyPEM(t)
	templates = append(templates, mgrWritePair(t, stateDir, "unparseable", "Machine", unparseKeyPEM, []byte("not a certificate")))

	// missing: state references files that do not exist on disk.
	keyPath, certPath := mgrPaths(stateDir, "missing")
	templates = append(templates, enrolledTemplate{Nickname: "missing", Template: "Machine", KeyFile: keyPath, CertFile: certPath})

	mgrWriteState(t, stateDir, []enrolledCA{{
		Name:      "TestCA",
		Hostname:  "ca.example.com",
		RootCerts: []string{filepath.Join(stateDir, "certs", "TestCA.crt")},
		Symlinks:  []string{filepath.Join(tmpdir, "trust", "TestCA.crt")},
		Templates: templates,
	}})

	m := mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"))

	certs, err := m.ListCertificates(context.Background(), mgrTestObject)
	require.NoError(t, err)
	require.Len(t, certs, len(templates))

	byNickname := make(map[string]CertInfo, len(certs))
	for _, c := range certs {
		byNickname[c.Nickname] = c
	}

	wantHealth := map[string]CertHealth{
		"healthy":     CertHealthy,
		"due":         CertDueRenewal,
		"short":       CertHealthy,
		"future":      CertNotYetValid,
		"expired":     CertExpired,
		"mismatch":    CertKeyMismatch,
		"unparseable": CertUnparseable,
		"missing":     CertMissing,
	}
	for nickname, want := range wantHealth {
		got, ok := byNickname[nickname]
		require.True(t, ok, "expected a CertInfo for %q", nickname)
		assert.Equal(t, want, got.Health, "health for %q", nickname)
	}

	// A healthy certificate should be fully populated.
	healthy := byNickname["healthy"]
	assert.True(t, healthy.OnDisk)
	assert.True(t, healthy.KeyMatchesCert)
	assert.Equal(t, "TestCA", healthy.CAName)
	assert.Equal(t, "ca.example.com", healthy.CAHostname)
	assert.Equal(t, "ECDSA", healthy.KeyAlgo)
	assert.Equal(t, 256, healthy.KeySize)
	assert.NotEmpty(t, healthy.Serial)
	assert.Contains(t, healthy.Subject, "healthy")
	assert.False(t, healthy.LastEnrolled.IsZero())
	assert.Greater(t, healthy.DaysUntilExpiry, 300)

	// The mismatch case still parses the certificate, so metadata is present.
	assert.False(t, byNickname["mismatch"].KeyMatchesCert)
	assert.True(t, byNickname["mismatch"].OnDisk)
}

func TestListCertificatesNoState(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()
	m := mgrManager(t, filepath.Join(tmpdir, "state"), filepath.Join(tmpdir, "trust"))

	certs, err := m.ListCertificates(context.Background(), mgrTestObject)
	require.NoError(t, err)
	assert.Empty(t, certs)
	assert.NotNil(t, certs)
}

func TestCertificateStatus(t *testing.T) {
	t.Parallel()

	newSingle := func(t *testing.T) *Manager {
		t.Helper()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		key, keyPEM := mgrKeyPEM(t)
		certPEM := mgrSelfSigned(t, key, "only", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
		tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, certPEM)
		mgrWriteState(t, stateDir, []enrolledCA{{Name: "TestCA", Hostname: "ca.example.com", Templates: []enrolledTemplate{tmpl}}})
		return mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"))
	}

	newMulti := func(t *testing.T) *Manager {
		t.Helper()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		var templates []enrolledTemplate
		for _, nick := range []string{"TestCA.Machine", "TestCA.WebServer"} {
			key, keyPEM := mgrKeyPEM(t)
			certPEM := mgrSelfSigned(t, key, nick, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
			templates = append(templates, mgrWritePair(t, stateDir, nick, strings.TrimPrefix(nick, "TestCA."), keyPEM, certPEM))
		}
		mgrWriteState(t, stateDir, []enrolledCA{{Name: "TestCA", Hostname: "ca.example.com", Templates: templates}})
		return mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"))
	}

	t.Run("empty nickname with single certificate returns it", func(t *testing.T) {
		t.Parallel()
		info, err := newSingle(t).CertificateStatus(context.Background(), mgrTestObject, "")
		require.NoError(t, err)
		assert.Equal(t, "TestCA.Machine", info.Nickname)
		assert.Equal(t, CertHealthy, info.Health)
	})

	t.Run("no certificates enrolled errors", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		m := mgrManager(t, filepath.Join(tmpdir, "state"), filepath.Join(tmpdir, "trust"))
		_, err := m.CertificateStatus(context.Background(), mgrTestObject, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no enrolled certificates")
	})

	t.Run("empty nickname with multiple certificates is ambiguous", func(t *testing.T) {
		t.Parallel()
		_, err := newMulti(t).CertificateStatus(context.Background(), mgrTestObject, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TestCA.Machine")
		assert.Contains(t, err.Error(), "TestCA.WebServer")
	})

	t.Run("by nickname returns match", func(t *testing.T) {
		t.Parallel()
		info, err := newMulti(t).CertificateStatus(context.Background(), mgrTestObject, "TestCA.WebServer")
		require.NoError(t, err)
		assert.Equal(t, "TestCA.WebServer", info.Nickname)
	})

	t.Run("by unknown nickname lists valid nicknames", func(t *testing.T) {
		t.Parallel()
		_, err := newMulti(t).CertificateStatus(context.Background(), mgrTestObject, "TestCA.Nope")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TestCA.Machine")
		assert.Contains(t, err.Error(), "TestCA.WebServer")
	})
}

func TestRenewCertificates(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T, templates []string) (*Manager, string, []string) {
		t.Helper()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")

		caCert, caKey, caDER := mgrTestCA(t)
		rootPath := mgrWriteCACertificate(t, stateDir, "TestCA.root.crt", caDER)

		var enrolled []enrolledTemplate
		var certPaths []string
		for _, tmpl := range templates {
			nick := "TestCA." + tmpl
			key, keyPEM := mgrKeyPEM(t)
			certPEM := mgrCASignedLeaf(t, caCert, caKey, &key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
			et := mgrWritePair(t, stateDir, nick, tmpl, keyPEM, certPEM)
			et = mgrBindTemplate(t, et, certPEM, caDER, rootPath)
			enrolled = append(enrolled, et)
			certPaths = append(certPaths, et.CertFile)
		}
		caFingerprint := rawCertificateFingerprint(caDER)
		mgrWriteState(t, stateDir, []enrolledCA{{
			Name:              "TestCA",
			Hostname:          "ca.example.com",
			IssuerFingerprint: caFingerprint,
			ChainFingerprints: []string{caFingerprint},
			RootCerts:         []string{rootPath},
			Templates:         enrolled,
		}})

		submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
			return mgrIssueFromCSR(t, csrPEM, time.Now().Add(365*24*time.Hour), caCert, caKey), nil
		}
		m := mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"),
			WithLDAPConnector(mgrConnector("CN=Configuration,DC=example,DC=com", templates, caDER)),
			WithCertificateRequester(IssuedCertificateRequester(submitter)),
		)
		return m, stateDir, certPaths
	}

	t.Run("renew single by nickname", func(t *testing.T) {
		t.Parallel()
		m, stateDir, certPaths := setup(t, []string{"Machine"})
		before, err := os.ReadFile(certPaths[0])
		require.NoError(t, err)
		stateBefore, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
		require.NoError(t, err)

		var msgs []string
		err = m.RenewCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false, func(s string) { msgs = append(msgs, s) })
		require.NoError(t, err)

		stateAfter, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
		require.NoError(t, err)
		renewedPath := stateAfter.CAs[0].Templates[0].CertFile
		require.NotEqual(t, certPaths[0], renewedPath)
		after, err := os.ReadFile(renewedPath)
		require.NoError(t, err)
		assert.NotEqual(t, before, after, "certificate file should be replaced on renewal")
		assert.NoFileExists(t, certPaths[0], "legacy certificate path should be pruned after state is saved")
		assert.False(t, stateAfter.UpdatedAt.Before(stateBefore.UpdatedAt), "state UpdatedAt should advance")

		joined := strings.Join(msgs, "\n")
		assert.Contains(t, joined, "Renewing")
		assert.Contains(t, joined, "Renewed TestCA.Machine")
	})

	t.Run("renew all templates", func(t *testing.T) {
		t.Parallel()
		m, stateDir, certPaths := setup(t, []string{"Machine", "WebServer"})
		before := make([][]byte, len(certPaths))
		for i, p := range certPaths {
			b, err := os.ReadFile(p)
			require.NoError(t, err)
			before[i] = b
		}

		var msgs []string
		err := m.RenewCertificates(context.Background(), mgrTestObject, "", true, func(s string) { msgs = append(msgs, s) })
		require.NoError(t, err)

		state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
		require.NoError(t, err)
		for i, tmpl := range state.CAs[0].Templates {
			require.NotEqual(t, certPaths[i], tmpl.CertFile)
			after, err := os.ReadFile(tmpl.CertFile)
			require.NoError(t, err)
			assert.NotEqual(t, before[i], after, "certificate %d should be replaced", i)
			assert.NoFileExists(t, certPaths[i])
		}
		assert.Equal(t, 2, strings.Count(strings.Join(msgs, "\n"), "Renewed"))
	})

	t.Run("renew unknown nickname errors", func(t *testing.T) {
		t.Parallel()
		m, _, _ := setup(t, []string{"Machine"})
		err := m.RenewCertificates(context.Background(), mgrTestObject, "TestCA.Nope", false, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TestCA.Machine")
	})

	t.Run("renewal failure is aggregated without changing state", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		caCert, caKey, caDER := mgrTestCA(t)
		rootPath := mgrWriteCACertificate(t, stateDir, "TestCA.root.crt", caDER)
		key, keyPEM := mgrKeyPEM(t)
		certPEM := mgrCASignedLeaf(t, caCert, caKey, &key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
		tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, certPEM)
		tmpl = mgrBindTemplate(t, tmpl, certPEM, caDER, rootPath)
		caFingerprint := rawCertificateFingerprint(caDER)
		mgrWriteState(t, stateDir, []enrolledCA{{
			Name:              "TestCA",
			Hostname:          "ca.example.com",
			IssuerFingerprint: caFingerprint,
			ChainFingerprints: []string{caFingerprint},
			RootCerts:         []string{rootPath},
			Templates:         []enrolledTemplate{tmpl},
		}})

		submitter := func(_ context.Context, _, _, _, _ string) (string, error) {
			return "", fmt.Errorf("mock submit failure")
		}
		m := mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"),
			WithLDAPConnector(mgrConnector("CN=Configuration,DC=example,DC=com", []string{"Machine"}, caDER)),
			WithCertificateRequester(IssuedCertificateRequester(submitter)),
		)
		stateBefore, err := os.ReadFile(stateFilePath(stateDir, mgrTestObject))
		require.NoError(t, err)

		var msgs []string
		err = m.RenewCertificates(context.Background(), mgrTestObject, "", true, func(s string) { msgs = append(msgs, s) })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TestCA.Machine")
		assert.Contains(t, strings.Join(msgs, "\n"), "Failed to renew")
		require.FileExists(t, stateFilePath(stateDir, mgrTestObject))
		stateAfter, readErr := os.ReadFile(stateFilePath(stateDir, mgrTestObject))
		require.NoError(t, readErr)
		assert.Equal(t, stateBefore, stateAfter)
	})
}

func TestTargetedRenewalRetainsPerTemplateExactChains(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		subordinate bool
	}{
		"new-key self-signed CA renewal": {},
		"subordinate issuer renewal":     {subordinate: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			now := time.Now()
			var root, oldIssuer, newIssuer *chainTestCA
			if tc.subordinate {
				root = newChainTestCA(t, "Offline Root", nil, now.Add(-24*time.Hour), now.Add(365*24*time.Hour), 1)
				oldIssuer = newChainTestCA(t, "Enterprise Issuer", root, now.Add(-12*time.Hour), now.Add(180*24*time.Hour), 2)
				newIssuer = newChainTestCA(t, "Enterprise Issuer", root, now.Add(-time.Hour), now.Add(240*24*time.Hour), 3)
			} else {
				oldIssuer = newChainTestCA(t, "Enterprise CA", nil, now.Add(-12*time.Hour), now.Add(180*24*time.Hour), 2)
				newIssuer = newChainTestCA(t, "Enterprise CA", nil, now.Add(-time.Hour), now.Add(240*24*time.Hour), 3)
				root = oldIssuer
			}

			baseDir := t.TempDir()
			stateDir := filepath.Join(baseDir, "state")
			globalTrustDir := filepath.Join(baseDir, "trust")
			oldRootPath := mgrWriteCACertificate(t, stateDir, "old-root.crt", root.cert.Raw)
			oldChain := []*x509.Certificate{oldIssuer.cert}
			oldChainFiles := []string{oldRootPath}
			var oldIssuerPath string
			if tc.subordinate {
				oldIssuerPath = mgrWriteCACertificate(t, stateDir, "old-issuer.crt", oldIssuer.cert.Raw)
				oldChain = []*x509.Certificate{oldIssuer.cert, root.cert}
				oldChainFiles = []string{oldIssuerPath, oldRootPath}
			}

			var templates []enrolledTemplate
			for _, templateName := range []string{"Machine", "WebServer"} {
				key, keyPEM := mgrKeyPEM(t)
				leafPEM := mgrCASignedLeaf(
					t,
					oldIssuer.cert,
					oldIssuer.key,
					&key.PublicKey,
					now.Add(-time.Hour),
					now.Add(90*24*time.Hour),
				)
				tmpl := mgrWritePair(t, stateDir, "TestCA."+templateName, templateName, keyPEM, leafPEM)
				templates = append(templates, mgrBindTemplateChain(t, tmpl, leafPEM, oldChain, oldChainFiles...))
			}
			oldFingerprints := make([]string, 0, len(oldChain))
			for _, cert := range oldChain {
				oldFingerprints = append(oldFingerprints, certificateFingerprint(cert))
			}
			oldCA := enrolledCA{
				Name:              "TestCA",
				Hostname:          "ca.example.com",
				IssuerFingerprint: oldFingerprints[0],
				ChainFingerprints: oldFingerprints,
				RootCerts:         []string{oldRootPath},
				Templates:         templates,
			}
			if tc.subordinate {
				oldCA.IntermediateCerts = []string{oldIssuerPath}
			}
			mgrWriteState(t, stateDir, []enrolledCA{oldCA})

			trustedRoot := newIssuer.cert
			if tc.subordinate {
				trustedRoot = root.cert
			}
			submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
				return mgrIssueFromCSR(t, csrPEM, now.Add(180*24*time.Hour), newIssuer.cert, newIssuer.key), nil
			}
			manager := mgrManager(
				t,
				stateDir,
				globalTrustDir,
				WithLDAPConnector(mgrConnectorWithChain(
					"CN=Configuration,DC=example,DC=com",
					[]string{"Machine", "WebServer"},
					newIssuer.cert.Raw,
					trustedRoot.Raw,
				)),
				WithCertificateRequester(IssuedCertificateRequester(submitter)),
			)

			untouchedBefore, err := os.ReadFile(templates[1].CertFile)
			require.NoError(t, err)
			require.NoError(t, manager.RenewCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false, nil))

			untouchedAfter, err := os.ReadFile(templates[1].CertFile)
			require.NoError(t, err)
			assert.Equal(t, untouchedBefore, untouchedAfter, "targeted renewal changed the untouched template")
			require.FileExists(t, oldRootPath)
			if tc.subordinate {
				require.FileExists(t, oldIssuerPath)
			}

			stateAfterFirst, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, err)
			require.Len(t, stateAfterFirst.CAs, 1)
			require.Len(t, stateAfterFirst.CAs[0].Templates, 2)
			assert.NotEqual(
				t,
				stateAfterFirst.CAs[0].Templates[0].IssuerFingerprint,
				stateAfterFirst.CAs[0].Templates[1].IssuerFingerprint,
			)
			results, err := manager.VerifyCertificates(context.Background(), mgrTestObject, "", false)
			require.NoError(t, err)
			require.Len(t, results, 2)
			for _, result := range results {
				assert.True(t, result.ChainOK, "%s: %v", result.Nickname, result.Messages)
				assert.True(t, result.KeyMatchOK, "%s: %v", result.Nickname, result.Messages)
			}

			require.NoError(t, manager.RenewCertificates(context.Background(), mgrTestObject, "TestCA.WebServer", false, nil))
			stateAfterSecond, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, err)
			assert.Equal(
				t,
				stateAfterSecond.CAs[0].Templates[0].ChainFingerprints,
				stateAfterSecond.CAs[0].Templates[1].ChainFingerprints,
			)
			if tc.subordinate {
				assert.NoFileExists(t, oldIssuerPath, "old issuer must be pruned after its final template migrates")
				require.NotEmpty(t, stateAfterSecond.CAs[0].RootCerts)
				for _, rootPath := range stateAfterSecond.CAs[0].RootCerts {
					assert.FileExists(t, rootPath, "shared offline root must remain installed")
				}
			} else {
				assert.NoFileExists(t, oldRootPath, "old root must be pruned after its final template migrates")
			}
		})
	}
}

func TestPolicyReconciliationPreservesPreviousStateOnTrustInstallFailure(t *testing.T) {
	t.Parallel()

	now := time.Now()
	oldCA := newChainTestCA(t, "Enterprise CA", nil, now.Add(-24*time.Hour), now.Add(365*24*time.Hour), 1)
	newCA := newChainTestCA(t, "Enterprise CA", nil, now.Add(-time.Hour), now.Add(2*365*24*time.Hour), 2)
	baseDir := t.TempDir()
	stateDir := filepath.Join(baseDir, "state")
	globalTrustDir := filepath.Join(baseDir, "trust")
	require.NoError(t, os.MkdirAll(globalTrustDir, 0750))

	oldRootPath := mgrWriteCACertificate(t, stateDir, "old-root.crt", oldCA.cert.Raw)
	oldSymlink := filepath.Join(globalTrustDir, "old-root.crt")
	require.NoError(t, os.Symlink(oldRootPath, oldSymlink))
	key, keyPEM := mgrKeyPEM(t)
	leafPEM := mgrCASignedLeaf(t, oldCA.cert, oldCA.key, &key.PublicKey, now.Add(-time.Hour), now.Add(180*24*time.Hour))
	tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, leafPEM)
	tmpl = mgrBindTemplateChain(t, tmpl, leafPEM, []*x509.Certificate{oldCA.cert}, oldRootPath)
	tmpl.TrustAnchorSymlink = oldSymlink
	oldFingerprint := certificateFingerprint(oldCA.cert)
	mgrWriteState(t, stateDir, []enrolledCA{{
		Name:              "TestCA",
		Hostname:          "ca.example.com",
		IssuerFingerprint: oldFingerprint,
		ChainFingerprints: []string{oldFingerprint},
		RootCerts:         []string{oldRootPath},
		Symlinks:          []string{oldSymlink},
		Templates:         []enrolledTemplate{tmpl},
	}})

	blockedSymlink := filepath.Join(
		globalTrustDir,
		trustArtifactFileName(certAuthority{Name: "TestCA", Hostname: "ca.example.com"}, newCA.cert, "root"),
	)
	require.NoError(t, os.WriteFile(blockedSymlink, []byte("owned by another enrollment"), 0600))
	var submissions int
	manager := mgrManager(
		t,
		stateDir,
		globalTrustDir,
		WithLDAPConnector(mgrConnector(
			"CN=Configuration,DC=example,DC=com",
			[]string{"Machine"},
			newCA.cert.Raw,
		)),
		WithCertificateRequester(IssuedCertificateRequester(func(context.Context, string, string, string, string) (string, error) {
			submissions++
			return "", fmt.Errorf("unexpected submission")
		})),
	)

	require.NoError(t, manager.enroll(context.Background(), mgrTestObject))
	assert.Zero(t, submissions)
	assert.FileExists(t, oldRootPath)
	require.FileExists(t, tmpl.CertFile)
	require.FileExists(t, tmpl.KeyFile)
	target, err := os.Readlink(oldSymlink)
	require.NoError(t, err)
	assert.Equal(t, oldRootPath, target)
	blocker, err := os.ReadFile(blockedSymlink)
	require.NoError(t, err)
	assert.Equal(t, "owned by another enrollment", string(blocker))

	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.CAs, 1)
	require.Len(t, state.CAs[0].Templates, 1)
	assert.Equal(t, oldFingerprint, state.CAs[0].Templates[0].IssuerFingerprint)
	assert.Equal(t, []string{oldRootPath}, state.CAs[0].Templates[0].ChainFiles)
}

func TestRemoveCertificates(t *testing.T) {
	t.Parallel()

	t.Run("without force is refused", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		m := mgrManager(t, filepath.Join(tmpdir, "state"), filepath.Join(tmpdir, "trust"))
		err := m.RemoveCertificates(context.Background(), mgrTestObject, "", true, false, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "force")
	})

	t.Run("single removal prunes the template but keeps the CA", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		globalTrustDir := filepath.Join(tmpdir, "trust")
		require.NoError(t, os.MkdirAll(globalTrustDir, 0750))

		rootPath := filepath.Join(stateDir, "certs", "TestCA.crt")
		symlinkPath := filepath.Join(globalTrustDir, "TestCA.crt")

		var templates []enrolledTemplate
		for _, tmpl := range []string{"Machine", "WebServer"} {
			key, keyPEM := mgrKeyPEM(t)
			certPEM := mgrSelfSigned(t, key, tmpl, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
			templates = append(templates, mgrWritePair(t, stateDir, "TestCA."+tmpl, tmpl, keyPEM, certPEM))
		}
		require.NoError(t, os.WriteFile(rootPath, []byte("root"), 0600))
		require.NoError(t, os.Symlink(rootPath, symlinkPath))
		mgrWriteState(t, stateDir, []enrolledCA{{
			Name: "TestCA", Hostname: "ca.example.com",
			RootCerts: []string{rootPath}, Symlinks: []string{symlinkPath}, Templates: templates,
		}})

		m := mgrManager(t, stateDir, globalTrustDir)

		var msgs []string
		err := m.RemoveCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false, true, func(s string) { msgs = append(msgs, s) })
		require.NoError(t, err)

		assert.NoFileExists(t, templates[0].CertFile)
		assert.NoFileExists(t, templates[0].KeyFile)
		assert.FileExists(t, templates[1].CertFile, "other template should remain")
		// CA still has a template, so its root and symlink must remain.
		assert.FileExists(t, rootPath)
		assert.FileExists(t, symlinkPath)

		state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
		require.NoError(t, err)
		require.Len(t, state.CAs, 1)
		require.Len(t, state.CAs[0].Templates, 1)
		assert.Equal(t, "TestCA.WebServer", state.CAs[0].Templates[0].Nickname)
	})

	t.Run("removing the last template drops the CA and state", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		globalTrustDir := filepath.Join(tmpdir, "trust")
		require.NoError(t, os.MkdirAll(globalTrustDir, 0750))

		rootPath := filepath.Join(stateDir, "certs", "TestCA.crt")
		symlinkPath := filepath.Join(globalTrustDir, "TestCA.crt")
		key, keyPEM := mgrKeyPEM(t)
		certPEM := mgrSelfSigned(t, key, "Machine", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
		tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, certPEM)
		require.NoError(t, os.WriteFile(rootPath, []byte("root"), 0600))
		require.NoError(t, os.Symlink(rootPath, symlinkPath))
		mgrWriteState(t, stateDir, []enrolledCA{{
			Name: "TestCA", Hostname: "ca.example.com",
			RootCerts: []string{rootPath}, Symlinks: []string{symlinkPath}, Templates: []enrolledTemplate{tmpl},
		}})

		m := mgrManager(t, stateDir, globalTrustDir)
		err := m.RemoveCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false, true, nil)
		require.NoError(t, err)

		assert.NoFileExists(t, tmpl.CertFile)
		assert.NoFileExists(t, tmpl.KeyFile)
		assert.NoFileExists(t, rootPath, "root cert should be removed with the last template")
		assert.NoFileExists(t, symlinkPath, "trust symlink should be removed with the last template")
		assert.NoFileExists(t, stateFilePath(stateDir, mgrTestObject), "state file should be removed")
	})

	t.Run("unknown nickname lists valid nicknames", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		key, keyPEM := mgrKeyPEM(t)
		certPEM := mgrSelfSigned(t, key, "Machine", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
		tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, certPEM)
		mgrWriteState(t, stateDir, []enrolledCA{{Name: "TestCA", Hostname: "ca.example.com", Templates: []enrolledTemplate{tmpl}}})

		m := mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"))
		err := m.RemoveCertificates(context.Background(), mgrTestObject, "TestCA.Nope", false, true, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TestCA.Machine")
	})

	t.Run("remove all unenrolls the machine", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		globalTrustDir := filepath.Join(tmpdir, "trust")
		require.NoError(t, os.MkdirAll(globalTrustDir, 0750))

		rootPath := filepath.Join(stateDir, "certs", "TestCA.crt")
		symlinkPath := filepath.Join(globalTrustDir, "TestCA.crt")
		key, keyPEM := mgrKeyPEM(t)
		certPEM := mgrSelfSigned(t, key, "Machine", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
		tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, certPEM)
		require.NoError(t, os.WriteFile(rootPath, []byte("root"), 0600))
		require.NoError(t, os.Symlink(rootPath, symlinkPath))
		mgrWriteState(t, stateDir, []enrolledCA{{
			Name: "TestCA", Hostname: "ca.example.com",
			RootCerts: []string{rootPath}, Symlinks: []string{symlinkPath}, Templates: []enrolledTemplate{tmpl},
		}})

		m := mgrManager(t, stateDir, globalTrustDir)
		var msgs []string
		err := m.RemoveCertificates(context.Background(), mgrTestObject, "", true, true, func(s string) { msgs = append(msgs, s) })
		require.NoError(t, err)

		assert.NoFileExists(t, tmpl.CertFile)
		assert.NoFileExists(t, tmpl.KeyFile)
		assert.NoFileExists(t, rootPath)
		assert.NoFileExists(t, symlinkPath)
		assert.NoFileExists(t, stateFilePath(stateDir, mgrTestObject))
		assert.Contains(t, strings.Join(msgs, "\n"), "Removed all certificates")
	})
}

func TestVerifyCertificates(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "state")
	globalTrustDir := filepath.Join(tmpdir, "trust")

	caCert, caKey, caDER := mgrTestCA(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	rootPath := filepath.Join(stateDir, "certs", "TestCA.crt")
	require.NoError(t, os.MkdirAll(filepath.Dir(rootPath), 0750))
	require.NoError(t, os.WriteFile(rootPath, caPEM, 0600))

	now := time.Now()

	// valid: leaf signed by the CA, key matches.
	validKey, validKeyPEM := mgrKeyPEM(t)
	validCertPEM := mgrCASignedLeaf(t, caCert, caKey, &validKey.PublicKey, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	validTmpl := mgrWritePair(t, stateDir, "TestCA.Valid", "Machine", validKeyPEM, validCertPEM)
	validTmpl = mgrBindTemplate(t, validTmpl, validCertPEM, caDER, rootPath)

	// expired: leaf signed by the CA but past its NotAfter.
	expiredKey, expiredKeyPEM := mgrKeyPEM(t)
	expiredCertPEM := mgrCASignedLeaf(t, caCert, caKey, &expiredKey.PublicKey, now.Add(-48*time.Hour), now.Add(-time.Hour))
	expiredTmpl := mgrWritePair(t, stateDir, "TestCA.Expired", "Machine", expiredKeyPEM, expiredCertPEM)
	expiredTmpl = mgrBindTemplate(t, expiredTmpl, expiredCertPEM, caDER, rootPath)

	// mismatch: leaf valid and chains, but the on-disk key is a different key.
	leafKey, _ := mgrKeyPEM(t)
	_, otherKeyPEM := mgrKeyPEM(t)
	mismatchCertPEM := mgrCASignedLeaf(t, caCert, caKey, &leafKey.PublicKey, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	mismatchTmpl := mgrWritePair(t, stateDir, "TestCA.Mismatch", "Machine", otherKeyPEM, mismatchCertPEM)
	mismatchTmpl = mgrBindTemplate(t, mismatchTmpl, mismatchCertPEM, caDER, rootPath)

	caFingerprint := rawCertificateFingerprint(caDER)
	mgrWriteState(t, stateDir, []enrolledCA{{
		Name:              "TestCA",
		Hostname:          "ca.example.com",
		IssuerFingerprint: caFingerprint,
		ChainFingerprints: []string{caFingerprint},
		RootCerts:         []string{rootPath},
		Templates:         []enrolledTemplate{validTmpl, expiredTmpl, mismatchTmpl},
	}})

	m := mgrManager(t, stateDir, globalTrustDir)

	results, err := m.VerifyCertificates(context.Background(), mgrTestObject, "", false)
	require.NoError(t, err)
	require.Len(t, results, 3)

	byNickname := make(map[string]VerifyResult, len(results))
	for _, r := range results {
		byNickname[r.Nickname] = r
		assert.False(t, r.RevocationChecked, "offline verification must not check revocation")
	}

	valid := byNickname["TestCA.Valid"]
	assert.True(t, valid.ValidityOK, "valid cert should be within its validity window")
	assert.True(t, valid.KeyMatchOK, "valid cert key should match")
	assert.True(t, valid.ChainOK, "valid cert should chain to the CA root: %v", valid.Messages)

	expired := byNickname["TestCA.Expired"]
	assert.False(t, expired.ValidityOK, "expired cert should fail validity")
	assert.True(t, expired.KeyMatchOK)
	assert.False(t, expired.ChainOK, "expired cert should fail chain verification")

	mismatch := byNickname["TestCA.Mismatch"]
	assert.True(t, mismatch.ValidityOK)
	assert.False(t, mismatch.KeyMatchOK, "mismatched key should be detected")
	assert.True(t, mismatch.ChainOK, "mismatched key does not affect chain verification")

	// Verifying a single certificate by nickname returns just that one.
	single, err := m.VerifyCertificates(context.Background(), mgrTestObject, "TestCA.Valid", false)
	require.NoError(t, err)
	require.Len(t, single, 1)
	assert.Equal(t, "TestCA.Valid", single[0].Nickname)

	// An unknown nickname is an error.
	_, err = m.VerifyCertificates(context.Background(), mgrTestObject, "TestCA.Nope", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TestCA.Valid")
}

func TestVerifyCertificatesRejectsCrossCABindingAndChainTampering(t *testing.T) {
	t.Parallel()

	type fixture struct {
		manager     *Manager
		stateDir    string
		caATemplate enrolledTemplate
		caACert     *x509.Certificate
		caAKey      *ecdsa.PrivateKey
		caARoot     string
		caBKeyPEM   []byte
		caBLeafPEM  []byte
		caBRootPEM  []byte
	}
	setup := func(t *testing.T) fixture {
		t.Helper()
		baseDir := t.TempDir()
		stateDir := filepath.Join(baseDir, "state")
		now := time.Now()
		caACert, caAKey, caADER := mgrTestCA(t)
		caBCert, caBKey, caBDER := mgrTestCA(t)
		caARoot := mgrWriteCACertificate(t, stateDir, "ca-a-root.crt", caADER)
		caBRoot := mgrWriteCACertificate(t, stateDir, "ca-b-root.crt", caBDER)

		caALeafKey, caALeafKeyPEM := mgrKeyPEM(t)
		caALeafPEM := mgrCASignedLeaf(t, caACert, caAKey, &caALeafKey.PublicKey, now.Add(-time.Hour), now.Add(24*time.Hour))
		caATemplate := mgrWritePair(t, stateDir, "CA-A.Machine", "Machine", caALeafKeyPEM, caALeafPEM)
		caATemplate = mgrBindTemplate(t, caATemplate, caALeafPEM, caADER, caARoot)

		caBLeafKey, caBLeafKeyPEM := mgrKeyPEM(t)
		caBLeafPEM := mgrCASignedLeaf(t, caBCert, caBKey, &caBLeafKey.PublicKey, now.Add(-time.Hour), now.Add(24*time.Hour))
		caBTemplate := mgrWritePair(t, stateDir, "CA-B.Machine", "Machine", caBLeafKeyPEM, caBLeafPEM)
		caBTemplate = mgrBindTemplate(t, caBTemplate, caBLeafPEM, caBDER, caBRoot)

		mgrWriteState(t, stateDir, []enrolledCA{
			{
				Name:              "CA-A",
				Hostname:          "ca-a.example.com",
				IssuerFingerprint: rawCertificateFingerprint(caADER),
				ChainFingerprints: []string{rawCertificateFingerprint(caADER)},
				RootCerts:         []string{caARoot},
				Templates:         []enrolledTemplate{caATemplate},
			},
			{
				Name:              "CA-B",
				Hostname:          "ca-b.example.com",
				IssuerFingerprint: rawCertificateFingerprint(caBDER),
				ChainFingerprints: []string{rawCertificateFingerprint(caBDER)},
				RootCerts:         []string{caBRoot},
				Templates:         []enrolledTemplate{caBTemplate},
			},
		})
		return fixture{
			manager:     mgrManager(t, stateDir, filepath.Join(baseDir, "trust")),
			stateDir:    stateDir,
			caATemplate: caATemplate,
			caACert:     caACert,
			caAKey:      caAKey,
			caARoot:     caARoot,
			caBKeyPEM:   caBLeafKeyPEM,
			caBLeafPEM:  caBLeafPEM,
			caBRootPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBDER}),
		}
	}

	t.Run("valid leaf and key from another enrolled CA", func(t *testing.T) {
		t.Parallel()
		fixture := setup(t)
		require.NoError(t, os.WriteFile(fixture.caATemplate.KeyFile, fixture.caBKeyPEM, 0600))
		require.NoError(t, os.WriteFile(fixture.caATemplate.CertFile, fixture.caBLeafPEM, 0600))

		results, err := fixture.manager.VerifyCertificates(context.Background(), mgrTestObject, "CA-A.Machine", false)
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.True(t, results[0].KeyMatchOK, "the substituted pair is internally valid")
		assert.False(t, results[0].ChainOK, "CA-B material must not validate through CA-A state")
		assert.Contains(t, strings.Join(results[0].Messages, "\n"), "persisted fingerprint")
	})

	t.Run("leaf with the wrong machine identity", func(t *testing.T) {
		t.Parallel()
		fixture := setup(t)
		wrongKey, wrongKeyPEM := mgrKeyPEM(t)
		wrongLeafPEM := mgrCASignedLeafForIdentity(
			t,
			fixture.caACert,
			fixture.caAKey,
			&wrongKey.PublicKey,
			"other.example.com",
			time.Now().Add(-time.Hour),
			time.Now().Add(24*time.Hour),
		)
		require.NoError(t, os.WriteFile(fixture.caATemplate.KeyFile, wrongKeyPEM, 0600))
		require.NoError(t, os.WriteFile(fixture.caATemplate.CertFile, wrongLeafPEM, 0600))
		state, err := loadState(fixture.stateDir, mgrTestObject, mgrTestDomain)
		require.NoError(t, err)
		block, _ := pem.Decode(wrongLeafPEM)
		require.NotNil(t, block)
		state.CAs[0].Templates[0].LeafFingerprint = rawCertificateFingerprint(block.Bytes)
		require.NoError(t, saveState(fixture.stateDir, state))

		results, err := fixture.manager.VerifyCertificates(context.Background(), mgrTestObject, "CA-A.Machine", false)
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.True(t, results[0].KeyMatchOK)
		assert.False(t, results[0].ChainOK)
		assert.Contains(t, strings.Join(results[0].Messages, "\n"), "machine identity verification failed")
	})

	for name, mutate := range map[string]func(t *testing.T, fixture fixture){
		"missing chain file": func(t *testing.T, fixture fixture) {
			t.Helper()
			require.NoError(t, os.Remove(fixture.caARoot))
		},
		"tampered chain file": func(t *testing.T, fixture fixture) {
			t.Helper()
			require.NoError(t, os.WriteFile(fixture.caARoot, fixture.caBRootPEM, 0600))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := setup(t)
			mutate(t, fixture)
			results, err := fixture.manager.VerifyCertificates(context.Background(), mgrTestObject, "CA-A.Machine", false)
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.False(t, results[0].ChainOK)
			assert.Contains(t, strings.Join(results[0].Messages, "\n"), "persisted exact chain")
		})
	}
}

func TestDiscoverCAsInfo(t *testing.T) {
	t.Parallel()

	_, _, caDER := mgrTestCA(t)
	configDN := "CN=Configuration,DC=example,DC=com"

	t.Run("discovered CA without local enrollment", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		m := mgrManager(t, filepath.Join(tmpdir, "state"), filepath.Join(tmpdir, "trust"),
			WithLDAPConnector(mgrConnector(configDN, []string{"Machine", "WebServer"}, caDER)),
		)

		cas, err := m.DiscoverCAsInfo(context.Background(), mgrTestObject)
		require.NoError(t, err)
		require.Len(t, cas, 1)

		ca := cas[0]
		assert.Equal(t, "TestCA", ca.Name)
		assert.Equal(t, "ca.example.com", ca.Hostname)
		assert.ElementsMatch(t, []string{"Machine", "WebServer"}, ca.Templates)
		require.Len(t, ca.RootFingerprints, 1)
		assert.Len(t, ca.RootFingerprints[0], 64, "SHA-256 fingerprint should be 64 hex chars")
		assert.False(t, ca.InstalledInTrust, "directory discovery alone does not mean the CA is installed locally")
		assert.False(t, ca.Enrolled, "no local state means not enrolled")
	})

	t.Run("discovered CA cross-referenced with enrollment state", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		key, keyPEM := mgrKeyPEM(t)
		certPEM := mgrSelfSigned(t, key, "Machine", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
		tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, certPEM)
		mgrWriteState(t, stateDir, []enrolledCA{{Name: "TestCA", Hostname: "ca.example.com", Templates: []enrolledTemplate{tmpl}}})

		m := mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"),
			WithLDAPConnector(mgrConnector(configDN, []string{"Machine"}, caDER)),
		)

		cas, err := m.DiscoverCAsInfo(context.Background(), mgrTestObject)
		require.NoError(t, err)
		require.Len(t, cas, 1)
		assert.True(t, cas[0].Enrolled, "state records an on-disk certificate for this CA")
	})

	t.Run("discovery failure is surfaced", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		m := mgrManager(t, filepath.Join(tmpdir, "state"), filepath.Join(tmpdir, "trust"),
			WithLDAPConnector(LDAPConnectorFunc(func(context.Context, string) (LDAPClient, error) { return nil, fmt.Errorf("connection failed") })),
		)
		_, err := m.DiscoverCAsInfo(context.Background(), mgrTestObject)
		require.Error(t, err)
	})
}

func TestDiscoverCAsInfoCancellationReleasesManagerLock(t *testing.T) {
	t.Parallel()

	m := mgrManager(t, t.TempDir(), t.TempDir(), WithLDAPConnector(LDAPConnectorFunc(
		func(ctx context.Context, _ string) (LDAPClient, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	defer cancel()

	start := time.Now()
	_, err := m.DiscoverCAsInfo(ctx, mgrTestObject)
	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second)
	require.True(t, m.mu.TryLock(), "manager lock remained held after LDAP cancellation")
	m.mu.Unlock()
}

func TestManagementMethodsRequireLDAPMethod(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()
	m := New(mgrTestDomain,
		WithStateDir(filepath.Join(tmpdir, "state")),
		WithRunDir(filepath.Join(tmpdir, "run")),
		WithShareDir(filepath.Join(tmpdir, "share")),
		WithGlobalTrustDir(filepath.Join(tmpdir, "trust")),
		WithEnrollmentMethod("cepces"),
	)

	ctx := context.Background()

	_, err := m.ListCertificates(ctx, mgrTestObject)
	assert.ErrorIs(t, err, ErrNotLDAPMethod)

	_, err = m.CertificateStatus(ctx, mgrTestObject, "")
	assert.ErrorIs(t, err, ErrNotLDAPMethod)

	err = m.RenewCertificates(ctx, mgrTestObject, "", true, nil)
	assert.ErrorIs(t, err, ErrNotLDAPMethod)

	err = m.RemoveCertificates(ctx, mgrTestObject, "", true, true, nil)
	assert.ErrorIs(t, err, ErrNotLDAPMethod)

	_, err = m.VerifyCertificates(ctx, mgrTestObject, "", false)
	assert.ErrorIs(t, err, ErrNotLDAPMethod)

	_, err = m.DiscoverCAsInfo(ctx, mgrTestObject)
	assert.ErrorIs(t, err, ErrNotLDAPMethod)

	_, err = m.SupportedTemplates(ctx, "ca.example.com")
	assert.ErrorIs(t, err, ErrNotLDAPMethod)
}

func TestSupportedTemplates(t *testing.T) {
	t.Parallel()

	identity := machineDirectoryIdentity{shortName: "keypress", samAccountName: "keypress$", dnsName: "keypress.example.com"}
	_, _, testCADER := mgrTestCA(t)
	_, _, otherCADER := mgrTestCA(t)
	cas := []mgrDirectoryCA{
		{name: "TestCA", hostname: "ca.example.com", templates: []string{"Machine", "WebServer"}, der: testCADER},
		{name: "OtherCA", hostname: "other-ca.example.com", templates: []string{"User"}, der: otherCADER},
	}

	tests := map[string]struct {
		server string

		wantTemplates []string
		wantErr       bool
	}{
		"templates for the requested CA only": {server: "ca.example.com", wantTemplates: []string{"Machine", "WebServer"}},
		"requested CA matched by name":        {server: "OtherCA", wantTemplates: []string{"User"}},
		"requested CA matched case-insensitively": {
			server:        "CA.Example.COM",
			wantTemplates: []string{"Machine", "WebServer"},
		},
		"unknown server is rejected":    {server: "rogue.example.com", wantErr: true},
		"arbitrary endpoint is rejected": {server: "localhost:4444", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var dialed []string
			connector := LDAPConnectorFunc(func(ctx context.Context, address string) (LDAPClient, error) {
				dialed = append(dialed, address)
				return mgrConnectorForIdentity(identity, cas).Connect(ctx, address)
			})

			m := New(mgrTestDomain,
				WithStateDir(t.TempDir()),
				WithRunDir(t.TempDir()),
				WithShareDir(t.TempDir()),
				WithGlobalTrustDir(t.TempDir()),
				WithEnrollmentMethod("ldap"),
				WithLDAPConnector(connector),
			)

			templates, err := m.SupportedTemplates(context.Background(), tc.server)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.server)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantTemplates, templates)
			}

			// The requested server only selects among discovered CAs: discovery
			// must always target domain controllers of the configured domain,
			// never the caller-provided address.
			for _, address := range dialed {
				assert.NotContains(t, address, "localhost", "caller-provided endpoint must never be dialed")
				assert.NotContains(t, address, "rogue.example.com", "caller-provided endpoint must never be dialed")
			}
		})
	}
}

// TestSupportedTemplatesDoesNotBlockPolicyOperations ensures a stalled
// directory endpoint does not hold the manager or trust lifecycle locks, so
// concurrent certificate operations keep working.
func TestSupportedTemplatesDoesNotBlockPolicyOperations(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	connector := LDAPConnectorFunc(func(ctx context.Context, _ string) (LDAPClient, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})

	m := New(mgrTestDomain,
		WithStateDir(t.TempDir()),
		WithRunDir(t.TempDir()),
		WithShareDir(t.TempDir()),
		WithGlobalTrustDir(t.TempDir()),
		WithEnrollmentMethod("ldap"),
		WithLDAPConnector(connector),
	)

	templatesDone := make(chan error, 1)
	go func() {
		_, err := m.SupportedTemplates(ctx, "ca.example.com")
		templatesDone <- err
	}()

	// Wait for the stalled query to be in flight, then run an operation that
	// takes both the manager and trust lifecycle locks: it must complete
	// without waiting for the stalled query.
	<-started
	listDone := make(chan error, 1)
	go func() {
		_, err := m.ListCertificates(context.Background(), mgrTestObject)
		listDone <- err
	}()

	select {
	case err := <-listDone:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("ListCertificates blocked behind a stalled SupportedTemplates query")
	}

	// Cancelling the caller context must release the stalled query promptly.
	cancel()
	select {
	case err := <-templatesDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(30 * time.Second):
		t.Fatal("SupportedTemplates did not honor caller cancellation")
	}
}

func TestRenewCertificatesReplacesInvalidTargets(t *testing.T) {
	t.Parallel()

	now := time.Now()
	// build persists a single self-signed CA enrollment whose only template's
	// leaf expires at leafNotAfter, optionally deleting the leaf on disk.
	build := func(t *testing.T, leafNotAfter time.Time, removeCert bool) (*Manager, string) {
		t.Helper()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		caCert, caKey, caDER := mgrTestCA(t)
		rootPath := mgrWriteCACertificate(t, stateDir, "TestCA.root.crt", caDER)
		key, keyPEM := mgrKeyPEM(t)
		leafPEM := mgrCASignedLeaf(t, caCert, caKey, &key.PublicKey, now.Add(-2*time.Hour), leafNotAfter)
		tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, leafPEM)
		tmpl = mgrBindTemplate(t, tmpl, leafPEM, caDER, rootPath)
		caFP := rawCertificateFingerprint(caDER)
		mgrWriteState(t, stateDir, []enrolledCA{{
			Name:              "TestCA",
			Hostname:          "ca.example.com",
			IssuerFingerprint: caFP,
			ChainFingerprints: []string{caFP},
			RootCerts:         []string{rootPath},
			Templates:         []enrolledTemplate{tmpl},
		}})
		if removeCert {
			require.NoError(t, os.Remove(tmpl.CertFile))
		}
		submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
			return mgrIssueFromCSR(t, csrPEM, now.Add(365*24*time.Hour), caCert, caKey), nil
		}
		m := mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"),
			WithLDAPConnector(mgrConnector("CN=Configuration,DC=example,DC=com", []string{"Machine"}, caDER)),
			WithCertificateRequester(IssuedCertificateRequester(submitter)),
		)
		return m, tmpl.CertFile
	}

	t.Run("expired target leaf is replaced", func(t *testing.T) {
		t.Parallel()
		m, certFile := build(t, now.Add(-time.Hour), false)
		require.NoError(t, m.RenewCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false, nil))
		state, err := loadState(m.stateDir, mgrTestObject, mgrTestDomain)
		require.NoError(t, err)
		require.FileExists(t, state.CAs[0].Templates[0].CertFile)
		assert.NoFileExists(t, certFile)
		results, err := m.VerifyCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false)
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.True(t, results[0].ValidityOK, "renewed leaf must be within its validity window")
		assert.True(t, results[0].ChainOK, "%v", results[0].Messages)
		assert.True(t, results[0].KeyMatchOK)
	})

	t.Run("missing target cert is replaced", func(t *testing.T) {
		t.Parallel()
		m, certFile := build(t, now.Add(365*24*time.Hour), true)
		require.NoFileExists(t, certFile)
		require.NoError(t, m.RenewCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false, nil))
		state, err := loadState(m.stateDir, mgrTestObject, mgrTestDomain)
		require.NoError(t, err)
		require.FileExists(t, state.CAs[0].Templates[0].CertFile)
		assert.NotEqual(t, certFile, state.CAs[0].Templates[0].CertFile)
		results, err := m.VerifyCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false)
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.True(t, results[0].ChainOK, "%v", results[0].Messages)
	})
}

func TestRenewCertificatesReplacesTargetWithExpiredOldIssuer(t *testing.T) {
	t.Parallel()

	now := time.Now()
	root := newChainTestCA(t, "Offline Root", nil, now.Add(-48*time.Hour), now.Add(365*24*time.Hour), 1)
	oldIssuer := newChainTestCA(t, "Enterprise Issuer", root, now.Add(-40*time.Hour), now.Add(-time.Hour), 2)
	newIssuer := newChainTestCA(t, "Enterprise Issuer", root, now.Add(-time.Hour), now.Add(240*24*time.Hour), 3)

	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "state")
	globalTrustDir := filepath.Join(tmpdir, "trust")
	oldRootPath := mgrWriteCACertificate(t, stateDir, "old-root.crt", root.cert.Raw)
	oldIssuerPath := mgrWriteCACertificate(t, stateDir, "old-issuer.crt", oldIssuer.cert.Raw)

	key, keyPEM := mgrKeyPEM(t)
	leafPEM := mgrCASignedLeaf(t, oldIssuer.cert, oldIssuer.key, &key.PublicKey, now.Add(-30*time.Hour), now.Add(90*24*time.Hour))
	tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, leafPEM)
	oldChain := []*x509.Certificate{oldIssuer.cert, root.cert}
	tmpl = mgrBindTemplateChain(t, tmpl, leafPEM, oldChain, oldIssuerPath, oldRootPath)
	oldFPs := []string{certificateFingerprint(oldIssuer.cert), certificateFingerprint(root.cert)}
	mgrWriteState(t, stateDir, []enrolledCA{{
		Name:              "TestCA",
		Hostname:          "ca.example.com",
		IssuerFingerprint: oldFPs[0],
		ChainFingerprints: oldFPs,
		RootCerts:         []string{oldRootPath},
		IntermediateCerts: []string{oldIssuerPath},
		Templates:         []enrolledTemplate{tmpl},
	}})

	submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
		return mgrIssueFromCSR(t, csrPEM, now.Add(180*24*time.Hour), newIssuer.cert, newIssuer.key), nil
	}
	m := mgrManager(t, stateDir, globalTrustDir,
		WithLDAPConnector(mgrConnectorWithChain(
			"CN=Configuration,DC=example,DC=com",
			[]string{"Machine"},
			newIssuer.cert.Raw,
			root.cert.Raw,
		)),
		WithCertificateRequester(IssuedCertificateRequester(submitter)),
	)

	// Precondition: the persisted chain is currently invalid because the old
	// issuer has expired.
	before, err := m.VerifyCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false)
	require.NoError(t, err)
	require.Len(t, before, 1)
	require.False(t, before[0].ChainOK, "precondition: expired old issuer chain must not verify")

	require.NoError(t, m.RenewCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false, nil))

	after, err := m.VerifyCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false)
	require.NoError(t, err)
	require.Len(t, after, 1)
	assert.True(t, after[0].ChainOK, "%v", after[0].Messages)
	assert.True(t, after[0].ValidityOK)
	assert.True(t, after[0].KeyMatchOK)
}

func TestRenewCertificatesFailsSafelyOnBrokenNonTarget(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "state")
	caCert, caKey, caDER := mgrTestCA(t)
	rootPath := mgrWriteCACertificate(t, stateDir, "TestCA.root.crt", caDER)

	mkTemplate := func(name string) enrolledTemplate {
		key, keyPEM := mgrKeyPEM(t)
		leafPEM := mgrCASignedLeaf(t, caCert, caKey, &key.PublicKey, now.Add(-time.Hour), now.Add(365*24*time.Hour))
		tmpl := mgrWritePair(t, stateDir, "TestCA."+name, name, keyPEM, leafPEM)
		return mgrBindTemplate(t, tmpl, leafPEM, caDER, rootPath)
	}
	machine := mkTemplate("Machine")
	web := mkTemplate("WebServer")
	caFP := rawCertificateFingerprint(caDER)
	mgrWriteState(t, stateDir, []enrolledCA{{
		Name:              "TestCA",
		Hostname:          "ca.example.com",
		IssuerFingerprint: caFP,
		ChainFingerprints: []string{caFP},
		RootCerts:         []string{rootPath},
		Templates:         []enrolledTemplate{machine, web},
	}})
	// Break the unrelated non-target template's certificate on disk.
	require.NoError(t, os.Remove(web.CertFile))

	machineBefore, err := os.ReadFile(machine.CertFile)
	require.NoError(t, err)

	var submissions int
	submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
		submissions++
		return mgrIssueFromCSR(t, csrPEM, now.Add(365*24*time.Hour), caCert, caKey), nil
	}
	m := mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"),
		WithLDAPConnector(mgrConnector("CN=Configuration,DC=example,DC=com", []string{"Machine", "WebServer"}, caDER)),
		WithCertificateRequester(IssuedCertificateRequester(submitter)),
	)

	err = m.RenewCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WebServer", "the broken retained template must be named")
	assert.Zero(t, submissions, "no target may be renewed while a retained template is broken")

	// The target certificate is untouched and no state entry is dropped.
	machineAfter, err := os.ReadFile(machine.CertFile)
	require.NoError(t, err)
	assert.Equal(t, machineBefore, machineAfter, "target cert must not change on a fail-safe abort")
	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.CAs, 1)
	require.Len(t, state.CAs[0].Templates, 2, "no template may be dropped on a fail-safe abort")
}

func TestRenewCertificatesRetainsValidOldEntryOnFailure(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "state")
	caCert, caKey, caDER := mgrTestCA(t)
	rootPath := mgrWriteCACertificate(t, stateDir, "TestCA.root.crt", caDER)
	key, keyPEM := mgrKeyPEM(t)
	leafPEM := mgrCASignedLeaf(t, caCert, caKey, &key.PublicKey, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, leafPEM)
	tmpl = mgrBindTemplate(t, tmpl, leafPEM, caDER, rootPath)
	caFP := rawCertificateFingerprint(caDER)
	mgrWriteState(t, stateDir, []enrolledCA{{
		Name:              "TestCA",
		Hostname:          "ca.example.com",
		IssuerFingerprint: caFP,
		ChainFingerprints: []string{caFP},
		RootCerts:         []string{rootPath},
		Templates:         []enrolledTemplate{tmpl},
	}})
	before, err := os.ReadFile(tmpl.CertFile)
	require.NoError(t, err)

	submitter := func(_ context.Context, _, _, _, _ string) (string, error) {
		return "", fmt.Errorf("mock submit failure")
	}
	m := mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"),
		WithLDAPConnector(mgrConnector("CN=Configuration,DC=example,DC=com", []string{"Machine"}, caDER)),
		WithCertificateRequester(IssuedCertificateRequester(submitter)),
	)

	err = m.RenewCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TestCA.Machine")

	after, err := os.ReadFile(tmpl.CertFile)
	require.NoError(t, err)
	assert.Equal(t, before, after, "still-valid old certificate must be preserved on failed renewal")
	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.CAs, 1)
	require.Len(t, state.CAs[0].Templates, 1, "valid old template must be retained")
	results, err := m.VerifyCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].ChainOK, "%v", results[0].Messages)
}

func TestRemovalPreservesOtherObjectSharedPaths(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) (*Manager, enrolledTemplate, string, string) {
		t.Helper()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		globalTrustDir := filepath.Join(tmpdir, "trust")
		require.NoError(t, os.MkdirAll(globalTrustDir, 0750))

		caCert, caKey, caDER := mgrTestCA(t)
		rootPath := mgrWriteCACertificate(t, stateDir, "shared-root.crt", caDER)
		symlinkPath := filepath.Join(globalTrustDir, "shared-anchor.crt")
		require.NoError(t, os.Symlink(rootPath, symlinkPath))

		key, keyPEM := mgrKeyPEM(t)
		leafPEM := mgrCASignedLeaf(t, caCert, caKey, &key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
		shared := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, leafPEM)
		shared = mgrBindTemplate(t, shared, leafPEM, caDER, rootPath)
		shared.TrustAnchorSymlink = symlinkPath
		caFP := rawCertificateFingerprint(caDER)
		for _, obj := range []string{"host-a", "host-b"} {
			identity, err := enrollmentMachineIdentity(obj, mgrTestDomain)
			require.NoError(t, err)
			require.NoError(t, saveState(stateDir, &enrollmentState{
				ObjectName: obj,
				Identity:   identity.dnsName,
				Domain:     mgrTestDomain,
				CAs: []enrolledCA{{
					Name:              "TestCA",
					Hostname:          "ca.example.com",
					IssuerFingerprint: caFP,
					ChainFingerprints: []string{caFP},
					RootCerts:         []string{rootPath},
					Symlinks:          []string{symlinkPath},
					Templates:         []enrolledTemplate{shared},
				}},
			}))
		}
		return mgrManager(t, stateDir, globalTrustDir), shared, rootPath, symlinkPath
	}
	assertShared := func(t *testing.T, stateDir string, shared enrolledTemplate, rootPath, symlinkPath string) {
		t.Helper()
		assert.FileExists(t, shared.CertFile, "shared cert deleted despite another owner")
		assert.FileExists(t, shared.KeyFile, "shared key deleted despite another owner")
		assert.FileExists(t, rootPath, "shared root deleted despite another owner")
		assert.FileExists(t, symlinkPath, "shared trust anchor deleted despite another owner")
		stateB, err := loadState(stateDir, "host-b", mgrTestDomain)
		require.NoError(t, err)
		require.Len(t, stateB.CAs, 1)
		require.Len(t, stateB.CAs[0].Templates, 1, "the untouched object state must be intact")
	}

	t.Run("single removal", func(t *testing.T) {
		t.Parallel()
		m, shared, rootPath, symlinkPath := setup(t)
		require.NoError(t, m.RemoveCertificates(context.Background(), "host-a", "TestCA.Machine", false, true, nil))
		assertShared(t, m.stateDir, shared, rootPath, symlinkPath)
	})

	t.Run("full unenroll", func(t *testing.T) {
		t.Parallel()
		m, shared, rootPath, symlinkPath := setup(t)
		require.NoError(t, m.RemoveCertificates(context.Background(), "host-a", "", true, true, nil))
		assertShared(t, m.stateDir, shared, rootPath, symlinkPath)
	})
}

func TestVerifyCertificatesRejectsMismatchedRequestedIdentity(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T, objectName, identity string) *Manager {
		t.Helper()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		caCert, caKey, caDER := mgrTestCA(t)
		rootPath := mgrWriteCACertificate(t, stateDir, "TestCA.root.crt", caDER)
		key, keyPEM := mgrKeyPEM(t)
		leafPEM := mgrCASignedLeafForIdentity(t, caCert, caKey, &key.PublicKey, identity, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
		tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, leafPEM)
		tmpl = mgrBindTemplate(t, tmpl, leafPEM, caDER, rootPath)
		caFP := rawCertificateFingerprint(caDER)
		state := &enrollmentState{
			ObjectName: objectName,
			Identity:   identity,
			Domain:     mgrTestDomain,
			CAs: []enrolledCA{{
				Name:              "TestCA",
				Hostname:          "ca.example.com",
				IssuerFingerprint: caFP,
				ChainFingerprints: []string{caFP},
				RootCerts:         []string{rootPath},
				Templates:         []enrolledTemplate{tmpl},
			}},
		}
		require.NoError(t, writeStateFile(stateFilePath(stateDir, objectName), state))
		return mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"))
	}

	t.Run("sanitized object-name collision is isolated", func(t *testing.T) {
		t.Parallel()
		m := setup(t, "host-", "host-.example.com")
		require.NotEqual(t, stateFilePath(m.stateDir, "host$"), stateFilePath(m.stateDir, "host-"))
		results, err := m.VerifyCertificates(context.Background(), "host$", "", false)
		require.NoError(t, err)
		assert.Empty(t, results)

		results, err = m.VerifyCertificates(context.Background(), "host-", "", false)
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.True(t, results[0].ChainOK, "%v", results[0].Messages)
	})

	t.Run("stored identity that does not match the target is rejected", func(t *testing.T) {
		t.Parallel()
		// The state claims a different machine identity than the requested
		// object resolves to; the stored value must never override the target.
		m := setup(t, "keypress", "other.example.com")
		_, err := m.VerifyCertificates(context.Background(), mgrTestObject, "", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
	})
}

func TestCollidingObjectNamesStayIsolatedAcrossManagement(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) (*Manager, string, map[string]enrolledTemplate) {
		t.Helper()
		baseDir := t.TempDir()
		stateDir := filepath.Join(baseDir, "state")
		templates := make(map[string]enrolledTemplate)
		for _, objectName := range []string{"host$", "host-"} {
			identity, err := enrollmentMachineIdentity(objectName, mgrTestDomain)
			require.NoError(t, err)
			key, keyPEM := mgrKeyPEM(t)
			nickname := map[string]string{"host$": "Dollar.Machine", "host-": "Dash.Machine"}[objectName]
			certPEM := mgrSelfSigned(t, key, identity.dnsName, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
			tmpl := mgrWritePair(t, stateDir, nickname, "Machine", keyPEM, certPEM)
			templates[objectName] = tmpl
			require.NoError(t, saveState(stateDir, &enrollmentState{
				ObjectName: objectName,
				Identity:   identity.dnsName,
				Domain:     mgrTestDomain,
				CAs: []enrolledCA{{
					Name:      "TestCA",
					Hostname:  "ca.example.com",
					Templates: []enrolledTemplate{tmpl},
				}},
			}))
		}
		return mgrManager(t, stateDir, filepath.Join(baseDir, "trust")), stateDir, templates
	}

	t.Run("list", func(t *testing.T) {
		t.Parallel()
		manager, _, _ := setup(t)
		dollar, err := manager.ListCertificates(context.Background(), "host$")
		require.NoError(t, err)
		require.Len(t, dollar, 1)
		assert.Equal(t, "Dollar.Machine", dollar[0].Nickname)
		dash, err := manager.ListCertificates(context.Background(), "host-")
		require.NoError(t, err)
		require.Len(t, dash, 1)
		assert.Equal(t, "Dash.Machine", dash[0].Nickname)
	})

	t.Run("remove", func(t *testing.T) {
		t.Parallel()
		manager, stateDir, templates := setup(t)
		require.NoError(t, manager.RemoveCertificates(context.Background(), "host$", "Dollar.Machine", false, true, nil))
		assert.NoFileExists(t, templates["host$"].CertFile)
		assert.FileExists(t, templates["host-"].CertFile)
		dash, err := loadState(stateDir, "host-", mgrTestDomain)
		require.NoError(t, err)
		require.NotNil(t, dash)
		require.Len(t, dash.CAs, 1)
	})

	t.Run("full unenroll", func(t *testing.T) {
		t.Parallel()
		manager, stateDir, templates := setup(t)
		require.NoError(t, manager.RemoveCertificates(context.Background(), "host$", "", true, true, nil))
		assert.NoFileExists(t, stateFilePath(stateDir, "host$"))
		assert.FileExists(t, stateFilePath(stateDir, "host-"))
		assert.FileExists(t, templates["host-"].CertFile)
	})
}

func TestCollidingObjectLegacyRenewalUsesCurrentArtifactPaths(t *testing.T) {
	t.Parallel()

	for _, submitFails := range []bool{false, true} {
		name := "success"
		if submitFails {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			baseDir := t.TempDir()
			stateDir := filepath.Join(baseDir, "state")
			globalTrustDir := filepath.Join(baseDir, "trust")
			caCert, caKey, caDER := mgrTestCA(t)
			rootPath := mgrWriteCACertificate(t, stateDir, "legacy-root.crt", caDER)

			sharedKey, sharedKeyPEM := mgrKeyPEM(t)
			sharedCertPEM := mgrCASignedLeafForIdentity(
				t,
				caCert,
				caKey,
				&sharedKey.PublicKey,
				"host-.example.com",
				time.Now().Add(-time.Hour),
				time.Now().Add(365*24*time.Hour),
			)
			shared := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", sharedKeyPEM, sharedCertPEM)
			shared = mgrBindTemplate(t, shared, sharedCertPEM, caDER, rootPath)
			caFP := certificateFingerprint(caCert)
			for _, objectName := range []string{"host$", "host-"} {
				identity, err := enrollmentMachineIdentity(objectName, mgrTestDomain)
				require.NoError(t, err)
				require.NoError(t, saveState(stateDir, &enrollmentState{
					ObjectName: objectName,
					Identity:   identity.dnsName,
					Domain:     mgrTestDomain,
					CAs: []enrolledCA{{
						Name:              "TestCA",
						Hostname:          "ca.example.com",
						IssuerFingerprint: caFP,
						ChainFingerprints: []string{caFP},
						RootCerts:         []string{rootPath},
						Templates:         []enrolledTemplate{shared},
					}},
				}))
			}

			sharedKeyBefore, err := os.ReadFile(shared.KeyFile)
			require.NoError(t, err)
			sharedCertBefore, err := os.ReadFile(shared.CertFile)
			require.NoError(t, err)
			dollarStateBefore, err := os.ReadFile(stateFilePath(stateDir, "host$"))
			require.NoError(t, err)
			dashStateBefore, err := os.ReadFile(stateFilePath(stateDir, "host-"))
			require.NoError(t, err)

			identity, err := enrollmentMachineIdentity("host$", mgrTestDomain)
			require.NoError(t, err)
			submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
				if submitFails {
					return "", fmt.Errorf("injected renewal failure")
				}
				return mgrIssueFromCSRForIdentity(t, csrPEM, time.Now().Add(365*24*time.Hour), caCert, caKey, identity.dnsName), nil
			}
			manager := mgrManager(
				t,
				stateDir,
				globalTrustDir,
				WithLDAPConnector(mgrConnectorForIdentity(identity, []mgrDirectoryCA{{
					name: "TestCA", hostname: "ca.example.com", templates: []string{"Machine"}, der: caDER,
				}})),
				WithCertificateRequester(IssuedCertificateRequester(submitter)),
			)

			err = manager.RenewCertificates(context.Background(), "host$", "TestCA.Machine", false, nil)
			if submitFails {
				require.Error(t, err)
				dollarStateAfter, readErr := os.ReadFile(stateFilePath(stateDir, "host$"))
				require.NoError(t, readErr)
				assert.Equal(t, dollarStateBefore, dollarStateAfter, "failed renewal changed persisted state")
			} else {
				require.NoError(t, err)
				state, loadErr := loadState(stateDir, "host$", mgrTestDomain)
				require.NoError(t, loadErr)
				renewed := state.CAs[0].Templates[0]
				assert.NotEqual(t, shared.KeyFile, renewed.KeyFile)
				assert.NotEqual(t, shared.CertFile, renewed.CertFile)
				assert.Contains(t, filepath.Base(renewed.GenerationRoot), leafArtifactBase("host$", certAuthority{
					Name: "TestCA", Hostname: "ca.example.com",
				}, "Machine"))
				assert.FileExists(t, renewed.KeyFile)
				assert.FileExists(t, renewed.CertFile)
			}

			gotSharedKey, err := os.ReadFile(shared.KeyFile)
			require.NoError(t, err)
			gotSharedCert, err := os.ReadFile(shared.CertFile)
			require.NoError(t, err)
			assert.Equal(t, sharedKeyBefore, gotSharedKey, "renewal overwrote the other object's legacy key")
			assert.Equal(t, sharedCertBefore, gotSharedCert, "renewal overwrote the other object's legacy certificate")
			dashStateAfter, err := os.ReadFile(stateFilePath(stateDir, "host-"))
			require.NoError(t, err)
			assert.Equal(t, dashStateBefore, dashStateAfter, "renewal changed the other object's state")
		})
	}
}

func TestEnrollmentIgnoresCollidingForeignLegacyState(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	stateDir := filepath.Join(baseDir, "state")
	foreign := &enrollmentState{
		ObjectName: "host-",
		Identity:   "host-.example.com",
		Domain:     mgrTestDomain,
	}
	require.NoError(t, writeStateFile(legacyStateFilePath(stateDir, "host-"), foreign))

	caCert, caKey, caDER := mgrTestCA(t)
	identity, err := enrollmentMachineIdentity("host$", mgrTestDomain)
	require.NoError(t, err)
	manager := mgrManager(
		t,
		stateDir,
		filepath.Join(baseDir, "trust"),
		WithLDAPConnector(mgrConnectorForIdentity(identity, []mgrDirectoryCA{{
			name: "TestCA", hostname: "ca.example.com", templates: []string{"Machine"}, der: caDER,
		}})),
		WithCertificateRequester(IssuedCertificateRequester(func(_ context.Context, _, _, _, csrPEM string) (string, error) {
			return mgrIssueFromCSRForIdentity(t, csrPEM, time.Now().Add(365*24*time.Hour), caCert, caKey, identity.dnsName), nil
		})),
	)

	require.NoError(t, manager.enroll(context.Background(), "host$"))
	assert.FileExists(t, stateFilePath(stateDir, "host$"))
	assert.FileExists(t, legacyStateFilePath(stateDir, "host-"), "foreign legacy state was deleted")
	certs, err := manager.ListCertificates(context.Background(), "host$")
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, managementNickname("TestCA", "ca.example.com", "Machine"), certs[0].Nickname)

	migrated, err := loadState(stateDir, "host-", mgrTestDomain)
	require.NoError(t, err)
	require.NotNil(t, migrated)
	assert.FileExists(t, stateFilePath(stateDir, "host-"))
	assert.FileExists(t, stateFilePath(stateDir, "host$"))
	assert.NoFileExists(t, legacyStateFilePath(stateDir, "host-"))
}

func TestManagementNicknameCollisionsAreDisambiguated(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	stateDir := filepath.Join(baseDir, "state")
	caACert, caAKey, caADER := mgrTestCA(t)
	caBCert, caBKey, caBDER := mgrTestCA(t)
	rootA := mgrWriteCACertificate(t, stateDir, "ca-a-legacy-root.crt", caADER)
	rootB := mgrWriteCACertificate(t, stateDir, "ca-b-legacy-root.crt", caBDER)

	buildTemplate := func(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, caDER []byte, root string) enrolledTemplate {
		key, keyPEM := mgrKeyPEM(t)
		leaf := mgrCASignedLeaf(t, caCert, caKey, &key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
		tmpl := mgrWritePair(t, stateDir, legacyManagementNickname("Corp CA", "Machine"), "Machine", keyPEM, leaf)
		return mgrBindTemplate(t, tmpl, leaf, caDER, root)
	}
	templateA := buildTemplate(caACert, caAKey, caADER, rootA)
	// Both raw CA names sanitize to the same historical nickname and file
	// prefix. Give the second legacy leaf a separate fixture path while keeping
	// the colliding management nickname.
	keyB, keyBPEM := mgrKeyPEM(t)
	leafB := mgrCASignedLeaf(t, caBCert, caBKey, &keyB.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	templateB := mgrWritePair(t, stateDir, "legacy-ca-b-leaf", "Machine", keyBPEM, leafB)
	templateB.Nickname = legacyManagementNickname("Corp-CA", "Machine")
	templateB = mgrBindTemplate(t, templateB, leafB, caBDER, rootB)

	state := &enrollmentState{
		ObjectName: mgrTestObject,
		Identity:   "keypress.example.com",
		Domain:     mgrTestDomain,
		CAs: []enrolledCA{
			{
				Name:              "Corp CA",
				Hostname:          "ca-a.example.com",
				IssuerFingerprint: certificateFingerprint(caACert),
				ChainFingerprints: []string{certificateFingerprint(caACert)},
				RootCerts:         []string{rootA},
				Templates:         []enrolledTemplate{templateA},
			},
			{
				Name:              "Corp-CA",
				Hostname:          "ca-b.example.com",
				IssuerFingerprint: certificateFingerprint(caBCert),
				ChainFingerprints: []string{certificateFingerprint(caBCert)},
				RootCerts:         []string{rootB},
				Templates:         []enrolledTemplate{templateB},
			},
		},
	}
	require.NoError(t, saveState(stateDir, state))
	nicknameA := state.CAs[0].Templates[0].Nickname
	nicknameB := state.CAs[1].Templates[0].Nickname
	require.NotEqual(t, nicknameA, nicknameB)
	assert.Equal(t, managementNickname("Corp CA", "ca-a.example.com", "Machine"), nicknameA)
	assert.Equal(t, managementNickname("Corp-CA", "ca-b.example.com", "Machine"), nicknameB)

	identity, err := enrollmentMachineIdentity(mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	manager := mgrManager(
		t,
		stateDir,
		filepath.Join(baseDir, "trust"),
		WithLDAPConnector(mgrConnectorForIdentity(identity, []mgrDirectoryCA{
			{name: "Corp CA", hostname: "ca-a.example.com", templates: []string{"Machine"}, der: caADER},
			{name: "Corp-CA", hostname: "ca-b.example.com", templates: []string{"Machine"}, der: caBDER},
		})),
		WithCertificateRequester(IssuedCertificateRequester(func(_ context.Context, _, caName, _ string, csrPEM string) (string, error) {
			switch caName {
			case "Corp CA":
				return mgrIssueFromCSR(t, csrPEM, time.Now().Add(365*24*time.Hour), caACert, caAKey), nil
			case "Corp-CA":
				return mgrIssueFromCSR(t, csrPEM, time.Now().Add(365*24*time.Hour), caBCert, caBKey), nil
			default:
				return "", fmt.Errorf("unexpected CA %q", caName)
			}
		})),
	)

	listed, err := manager.ListCertificates(context.Background(), mgrTestObject)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{nicknameA, nicknameB}, nicknamesOf(listed))

	legacyNickname := legacyManagementNickname("Corp CA", "Machine")
	certABefore, err := os.ReadFile(templateA.CertFile)
	require.NoError(t, err)
	certBBefore, err := os.ReadFile(templateB.CertFile)
	require.NoError(t, err)
	err = manager.RenewCertificates(context.Background(), mgrTestObject, legacyNickname, false, nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "ambiguous")
	assert.ErrorContains(t, err, nicknameA)
	assert.ErrorContains(t, err, nicknameB)
	gotA, err := os.ReadFile(templateA.CertFile)
	require.NoError(t, err)
	gotB, err := os.ReadFile(templateB.CertFile)
	require.NoError(t, err)
	assert.Equal(t, certABefore, gotA)
	assert.Equal(t, certBBefore, gotB)

	require.NoError(t, manager.RenewCertificates(context.Background(), mgrTestObject, nicknameA, false, nil))
	afterRenew, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	assert.NotEqual(t, templateA.CertFile, afterRenew.CAs[0].Templates[0].CertFile)
	assert.Equal(t, templateB.CertFile, afterRenew.CAs[1].Templates[0].CertFile)
	gotB, err = os.ReadFile(templateB.CertFile)
	require.NoError(t, err)
	assert.Equal(t, certBBefore, gotB, "targeted renewal changed the colliding CA")

	require.NoError(t, manager.RemoveCertificates(context.Background(), mgrTestObject, nicknameB, false, true, nil))
	afterRemove, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, afterRemove.CAs, 1)
	assert.Equal(t, "Corp CA", afterRemove.CAs[0].Name)
}

func TestEnrollmentRollbackFailuresAreNeverMasked(t *testing.T) {
	t.Parallel()

	for _, includeSuccessfulCA := range []bool{false, true} {
		name := "zero successful CAs"
		if includeSuccessfulCA {
			name = "one successful CA"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			baseDir := t.TempDir()
			stateDir := filepath.Join(baseDir, "state")
			badCert, _, badDER := mgrTestCA(t)
			goodCert, goodKey, goodDER := mgrTestCA(t)
			identity, err := enrollmentMachineIdentity(mgrTestObject, mgrTestDomain)
			require.NoError(t, err)

			cas := []mgrDirectoryCA{{
				name: "Rollback CA", hostname: "rollback.example.com", templates: []string{"Machine"}, der: badDER,
			}}
			if includeSuccessfulCA {
				cas = append([]mgrDirectoryCA{{
					name: "Good CA", hostname: "good.example.com", templates: []string{"Machine"}, der: goodDER,
				}}, cas...)
			}
			manager := mgrManager(
				t,
				stateDir,
				filepath.Join(baseDir, "trust"),
				WithLDAPConnector(mgrConnectorForIdentity(identity, cas)),
				WithCertificateRequester(IssuedCertificateRequester(func(_ context.Context, _, caName, _ string, csrPEM string) (string, error) {
					if caName == "Rollback CA" {
						return "", fmt.Errorf("injected submission failure")
					}
					return mgrIssueFromCSR(t, csrPEM, time.Now().Add(365*24*time.Hour), goodCert, goodKey), nil
				})),
			)
			manager.installChain = func(ca certAuthority, trustDir, globalTrustDir string) (*caChainInstallation, error) {
				installation, err := installCAChainTransaction(ca, trustDir, globalTrustDir)
				if err != nil {
					return nil, err
				}
				if ca.Name == "Rollback CA" {
					installation.removeFile = func(string) error {
						return fmt.Errorf("injected rollback removal failure")
					}
				}
				return installation, nil
			}

			err = manager.enroll(context.Background(), mgrTestObject)
			require.Error(t, err)
			assert.ErrorContains(t, err, "injected rollback removal failure")
			badRoot := filepath.Join(
				stateDir,
				"certs",
				trustArtifactFileName(certAuthority{Name: "Rollback CA", Hostname: "rollback.example.com"}, badCert, "root"),
			)
			assert.FileExists(t, badRoot, "injected rollback failure should leave a named repairable artifact")

			state, loadErr := loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, loadErr)
			if includeSuccessfulCA {
				require.NotNil(t, state)
				require.Len(t, state.CAs, 1)
				assert.Equal(t, "Good CA", state.CAs[0].Name)
			} else {
				assert.Nil(t, state)
				assert.ErrorContains(t, err, "could not enroll to any certificate authorities")
			}
		})
	}
}

func TestEnrollmentSerializesCreatorRollbackAndAdopterCommit(t *testing.T) {
	baseDir := t.TempDir()
	stateDir := filepath.Join(baseDir, "state")
	globalTrustDir := filepath.Join(baseDir, "trust")
	caCert, caKey, caDER := mgrTestCA(t)
	identity, err := enrollmentMachineIdentity(mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	connector := mgrConnectorForIdentity(identity, []mgrDirectoryCA{{
		name: "Shared CA", hostname: "ca.example.com", templates: []string{"Machine"}, der: caDER,
	}})

	creatorSubmitted := make(chan struct{})
	releaseCreator := make(chan struct{})
	creator := mgrManager(
		t,
		stateDir,
		globalTrustDir,
		WithLDAPConnector(connector),
		WithCertificateRequester(IssuedCertificateRequester(func(context.Context, string, string, string, string) (string, error) {
			close(creatorSubmitted)
			<-releaseCreator
			return "", fmt.Errorf("injected creator failure")
		})),
	)
	adopterConnected := make(chan struct{})
	adopterConnector := LDAPConnectorFunc(func(ctx context.Context, server string) (LDAPClient, error) {
		close(adopterConnected)
		return connector.Connect(ctx, server)
	})
	adopter := mgrManager(
		t,
		stateDir,
		globalTrustDir,
		WithLDAPConnector(adopterConnector),
		WithCertificateRequester(IssuedCertificateRequester(func(_ context.Context, _, _, _ string, csrPEM string) (string, error) {
			return mgrIssueFromCSRForIdentityResult(
				csrPEM,
				time.Now().Add(365*24*time.Hour),
				caCert,
				caKey,
				"keypress.example.com",
			)
		})),
	)

	creatorDone := make(chan error, 1)
	go func() {
		creatorDone <- creator.enroll(context.Background(), mgrTestObject)
	}()
	select {
	case <-creatorSubmitted:
	case <-time.After(5 * time.Second):
		t.Fatal("creator did not reach certificate submission")
	}

	adopterDone := make(chan error, 1)
	go func() {
		adopterDone <- adopter.enroll(context.Background(), mgrTestObject)
	}()
	select {
	case <-adopterConnected:
		t.Fatal("adopter entered the trust lifecycle before the creator rolled back")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseCreator)
	require.Error(t, <-creatorDone)
	require.NoError(t, <-adopterDone)

	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Len(t, state.CAs, 1)
	require.Len(t, state.CAs[0].RootCerts, 1)
	require.Len(t, state.CAs[0].Symlinks, 1)
	require.Len(t, state.CAs[0].Templates, 1)
	assert.FileExists(t, state.CAs[0].RootCerts[0], "creator rollback removed the adopter's committed root")
	assert.FileExists(t, state.CAs[0].Symlinks[0], "creator rollback removed the adopter's committed anchor")
	assert.FileExists(t, state.CAs[0].Templates[0].KeyFile)
	assert.FileExists(t, state.CAs[0].Templates[0].CertFile)
	target, err := os.Readlink(state.CAs[0].Symlinks[0])
	require.NoError(t, err)
	assert.Equal(t, state.CAs[0].RootCerts[0], target)
}

func TestManagementRejectsForeignCanonicalState(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	stateDir := filepath.Join(baseDir, "state")
	marker := filepath.Join(stateDir, "certs", "foreign.crt")
	require.NoError(t, os.MkdirAll(filepath.Dir(marker), 0750))
	require.NoError(t, os.WriteFile(marker, []byte("foreign"), 0600))
	foreign := &enrollmentState{
		ObjectName: "host-",
		Identity:   "host-.example.com",
		Domain:     mgrTestDomain,
		CAs: []enrolledCA{{
			Name:     "Foreign CA",
			Hostname: "foreign.example.com",
			Templates: []enrolledTemplate{{
				Nickname: "Foreign-CA.Machine",
				Template: "Machine",
				CertFile: marker,
				KeyFile:  marker,
			}},
		}},
	}
	foreignPath := stateFilePath(stateDir, mgrTestObject)
	require.NoError(t, writeStateFile(foreignPath, foreign))

	_, _, caDER := mgrTestCA(t)
	manager := mgrManager(
		t,
		stateDir,
		filepath.Join(baseDir, "trust"),
		WithLDAPConnector(mgrConnector("CN=Configuration,DC=example,DC=com", []string{"Machine"}, caDER)),
		WithCertificateRequester(IssuedCertificateRequester(func(context.Context, string, string, string, string) (string, error) {
			return "", fmt.Errorf("CSR submission must not use foreign state")
		})),
	)

	operations := map[string]func() error{
		"list": func() error {
			_, err := manager.ListCertificates(context.Background(), mgrTestObject)
			return err
		},
		"status": func() error {
			_, err := manager.CertificateStatus(context.Background(), mgrTestObject, "")
			return err
		},
		"renew": func() error {
			return manager.RenewCertificates(context.Background(), mgrTestObject, "Foreign-CA.Machine", false, nil)
		},
		"remove": func() error {
			return manager.RemoveCertificates(context.Background(), mgrTestObject, "Foreign-CA.Machine", false, true, nil)
		},
		"full unenroll": func() error {
			return manager.RemoveCertificates(context.Background(), mgrTestObject, "", true, true, nil)
		},
		"verify": func() error {
			_, err := manager.VerifyCertificates(context.Background(), mgrTestObject, "", false)
			return err
		},
		"show CAs": func() error {
			_, err := manager.DiscoverCAsInfo(context.Background(), mgrTestObject)
			return err
		},
		"policy enroll": func() error {
			return manager.ApplyPolicy(context.Background(), mgrTestObject, true, true, []entry.Entry{{
				Key: "autoenroll", Value: "1",
			}})
		},
		"policy unenroll": func() error {
			return manager.ApplyPolicy(context.Background(), mgrTestObject, true, true, nil)
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := operation()
			require.Error(t, err)
			assert.ErrorContains(t, err, "does not match requested object")
			assert.FileExists(t, foreignPath)
			assert.FileExists(t, marker)
		})
	}
}

// --- test helpers ---

func mgrManager(t *testing.T, stateDir, globalTrustDir string, opts ...Option) *Manager {
	t.Helper()
	base := []Option{
		WithStateDir(stateDir),
		WithRunDir(filepath.Join(t.TempDir(), "run")),
		WithShareDir(filepath.Join(t.TempDir(), "share")),
		WithGlobalTrustDir(globalTrustDir),
		WithEnrollmentMethod("ldap"),
	}
	return New(mgrTestDomain, append(base, opts...)...)
}

func mgrKeyPEM(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func mgrSelfSigned(t *testing.T, key *ecdsa.PrivateKey, cn string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mgrTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key, der
}

func mgrCASignedLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, leafPub any, notBefore, notAfter time.Time) []byte {
	t.Helper()
	return mgrCASignedLeafForIdentity(t, caCert, caKey, leafPub, "keypress.example.com", notBefore, notAfter)
}

func mgrCASignedLeafForIdentity(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, leafPub any, identity string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: identity},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, leafPub, caKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mgrIssueFromCSR(t *testing.T, csrPEM string, notAfter time.Time, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) string {
	t.Helper()
	return mgrIssueFromCSRForIdentity(t, csrPEM, notAfter, caCert, caKey, "keypress.example.com")
}

func mgrIssueFromCSRForIdentity(t *testing.T, csrPEM string, notAfter time.Time, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, identity string) string {
	t.Helper()
	certPEM, err := mgrIssueFromCSRForIdentityResult(csrPEM, notAfter, caCert, caKey, identity)
	require.NoError(t, err)
	return certPEM
}

func mgrIssueFromCSRForIdentityResult(csrPEM string, notAfter time.Time, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, identity string) (string, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing CSR: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", fmt.Errorf("generating certificate serial: %w", err)
	}
	leaf := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: identity},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &leaf, caCert, csr.PublicKey, caKey)
	if err != nil {
		return "", fmt.Errorf("creating certificate: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// mgrPaths returns the on-disk key and cert paths for a nickname without
// creating any files.
func mgrPaths(stateDir, nickname string) (keyPath, certPath string) {
	return filepath.Join(stateDir, "private", "certs", nickname+".key"),
		filepath.Join(stateDir, "certs", nickname+".crt")
}

// mgrWritePair writes the key and certificate to their canonical on-disk
// locations and returns the corresponding enrolledTemplate.
func mgrWritePair(t *testing.T, stateDir, nickname, template string, keyPEM, certPEM []byte) enrolledTemplate {
	t.Helper()
	keyPath, certPath := mgrPaths(stateDir, nickname)
	require.NoError(t, os.MkdirAll(filepath.Dir(keyPath), 0700))
	require.NoError(t, os.MkdirAll(filepath.Dir(certPath), 0750))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	return enrolledTemplate{Nickname: nickname, Template: template, KeyFile: keyPath, CertFile: certPath}
}

func mgrWriteState(t *testing.T, stateDir string, cas []enrolledCA) {
	t.Helper()
	require.NoError(t, saveState(stateDir, &enrollmentState{
		ObjectName: mgrTestObject,
		Identity:   "keypress.example.com",
		Domain:     mgrTestDomain,
		CAs:        cas,
	}))
}

func mgrWriteCACertificate(t *testing.T, stateDir, name string, der []byte) string {
	t.Helper()
	path := filepath.Join(stateDir, "certs", name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0750))
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	return path
}

func mgrBindTemplate(t *testing.T, tmpl enrolledTemplate, leafPEM, issuerDER []byte, chainFiles ...string) enrolledTemplate {
	t.Helper()
	issuer, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)
	return mgrBindTemplateChain(t, tmpl, leafPEM, []*x509.Certificate{issuer}, chainFiles...)
}

func mgrBindTemplateChain(t *testing.T, tmpl enrolledTemplate, leafPEM []byte, chain []*x509.Certificate, chainFiles ...string) enrolledTemplate {
	t.Helper()
	leafBlock, _ := pem.Decode(leafPEM)
	require.NotNil(t, leafBlock)
	require.NotEmpty(t, chain)
	require.Len(t, chainFiles, len(chain))
	fingerprints := make([]string, 0, len(chain))
	for _, cert := range chain {
		fingerprints = append(fingerprints, certificateFingerprint(cert))
	}
	tmpl.LeafFingerprint = rawCertificateFingerprint(leafBlock.Bytes)
	tmpl.IssuerFingerprint = fingerprints[0]
	tmpl.ChainFingerprints = fingerprints
	tmpl.ChainFiles = append([]string(nil), chainFiles...)
	return tmpl
}

// mgrConnector returns an LDAPConnector backed by an in-memory mock that
// answers root DSE, enrollment service and certificate template queries.
func mgrConnector(configDN string, templates []string, caDER []byte) LDAPConnector {
	return mgrConnectorWithChain(configDN, templates, caDER, caDER)
}

type mgrDirectoryCA struct {
	name      string
	hostname  string
	templates []string
	der       []byte
}

func mgrConnectorForIdentity(identity machineDirectoryIdentity, cas []mgrDirectoryCA) LDAPConnector {
	configDN := "CN=Configuration,DC=example,DC=com"
	defaultDN := "DC=example,DC=com"
	enrollBaseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)
	caBaseDN := fmt.Sprintf("CN=Certification Authorities,CN=Public Key Services,CN=Services,%s", configDN)
	templateBaseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)

	enrollmentEntries := make([]*ldap.Entry, 0, len(cas))
	caEntries := make([]*ldap.Entry, 0, len(cas))
	templateNames := make(map[string]struct{})
	for _, ca := range cas {
		enrollmentEntries = append(enrollmentEntries, newCAEntry(enrollBaseDN, ca.name, ca.hostname, ca.templates, ca.der))
		caEntries = append(caEntries, newCAEntry(caBaseDN, ca.name, "", nil, ca.der))
		for _, template := range ca.templates {
			templateNames[template] = struct{}{}
		}
	}

	templateEntries := make([]*ldap.Entry, 0, len(templateNames))
	for template := range templateNames {
		templateEntry := ldap.NewEntry(fmt.Sprintf("CN=%s,%s", template, templateBaseDN), map[string][]string{
			"cn":                            {template},
			"flags":                         {"64"},
			"msPKI-Template-Schema-Version": {"2"},
			"msPKI-Enrollment-Flag":         {"32"},
			"msPKI-Minimal-Key-Size":        {"2048"},
		})
		templateEntry.Attributes = append(templateEntry.Attributes, &ldap.EntryAttribute{
			Name:       "nTSecurityDescriptor",
			ByteValues: [][]byte{aclNullDACL()},
		})
		templateEntries = append(templateEntries, templateEntry)
	}

	computerDN := fmt.Sprintf("CN=%s,CN=Computers,%s", identity.shortName, defaultDN)
	resolvedComputer := ldap.NewEntry(computerDN, map[string][]string{
		"sAMAccountName": {identity.samAccountName},
		"dNSHostName":    {identity.dnsName},
	})
	computer := ldap.NewEntry(computerDN, map[string][]string{
		"sAMAccountName": {identity.samAccountName},
		"dNSHostName":    {identity.dnsName},
		"primaryGroupID": {"515"},
	})
	computer.Attributes = append(computer.Attributes,
		&ldap.EntryAttribute{Name: "objectSid", ByteValues: [][]byte{aclSID(5, 21, 1, 2, 3, 1000)}},
		&ldap.EntryAttribute{Name: "tokenGroups", ByteValues: [][]byte{aclSID(5, 21, 1, 2, 3, 515)}},
	)

	conn := &mockLDAPClient{searchResults: map[string]*ldap.SearchResult{
		"": {Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{
			"configurationNamingContext": {configDN},
			"defaultNamingContext":       {defaultDN},
		})}},
		enrollBaseDN:   {Entries: enrollmentEntries},
		caBaseDN:       {Entries: caEntries},
		templateBaseDN: {Entries: templateEntries},
		defaultDN:      {Entries: []*ldap.Entry{resolvedComputer}},
		computerDN:     {Entries: []*ldap.Entry{computer}},
	}}
	return LDAPConnectorFunc(func(context.Context, string) (LDAPClient, error) { return conn, nil })
}

func mgrConnectorWithChain(configDN string, templates []string, issuerDER, trustedRootDER []byte, aiaDER ...[]byte) LDAPConnector {
	defaultDN := "DC=example,DC=com"
	enrollBaseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)
	caBaseDN := fmt.Sprintf("CN=Certification Authorities,CN=Public Key Services,CN=Services,%s", configDN)
	aiaBaseDN := fmt.Sprintf("CN=AIA,CN=Public Key Services,CN=Services,%s", configDN)
	templateBaseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)

	results := map[string]*ldap.SearchResult{
		"": {Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{
			"configurationNamingContext": {configDN},
			"defaultNamingContext":       {defaultDN},
		})}},
		enrollBaseDN: {Entries: []*ldap.Entry{newCAEntry(enrollBaseDN, "TestCA", "ca.example.com", templates, issuerDER)}},
		caBaseDN:     {Entries: []*ldap.Entry{newCAEntry(caBaseDN, "TestCA", "", nil, trustedRootDER)}},
	}
	if len(aiaDER) != 0 {
		aiaEntry := ldap.NewEntry("CN=TestCA,"+aiaBaseDN, nil)
		aiaEntry.Attributes = append(aiaEntry.Attributes, &ldap.EntryAttribute{Name: "cACertificate", ByteValues: aiaDER})
		results[aiaBaseDN] = &ldap.SearchResult{Entries: []*ldap.Entry{aiaEntry}}
	}
	tEntries := make([]*ldap.Entry, 0, len(templates))
	for _, tmpl := range templates {
		entry := ldap.NewEntry(fmt.Sprintf("CN=%s,%s", tmpl, templateBaseDN), map[string][]string{
			"cn":                            {tmpl},
			"flags":                         {"64"},
			"msPKI-Template-Schema-Version": {"2"},
			"msPKI-Enrollment-Flag":         {"32"},
			"msPKI-Minimal-Key-Size":        {"2048"},
		})
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
			Name:       "nTSecurityDescriptor",
			ByteValues: [][]byte{aclNullDACL()},
		})
		tEntries = append(tEntries, entry)
	}
	results[templateBaseDN] = &ldap.SearchResult{Entries: tEntries}
	computerDN := "CN=keypress,CN=Computers," + defaultDN
	resolvedComputer := ldap.NewEntry(computerDN, map[string][]string{
		"sAMAccountName": {"keypress$"},
		"dNSHostName":    {"keypress.example.com"},
	})
	computer := ldap.NewEntry(computerDN, map[string][]string{
		"sAMAccountName": {"keypress$"},
		"dNSHostName":    {"keypress.example.com"},
		"primaryGroupID": {"515"},
	})
	computer.Attributes = append(computer.Attributes,
		&ldap.EntryAttribute{Name: "objectSid", ByteValues: [][]byte{aclSID(5, 21, 1, 2, 3, 1000)}},
		&ldap.EntryAttribute{Name: "tokenGroups", ByteValues: [][]byte{aclSID(5, 21, 1, 2, 3, 515)}},
	)
	results[defaultDN] = &ldap.SearchResult{Entries: []*ldap.Entry{resolvedComputer}}
	results[computerDN] = &ldap.SearchResult{Entries: []*ldap.Entry{computer}}

	conn := &mockLDAPClient{searchResults: results}
	return LDAPConnectorFunc(func(context.Context, string) (LDAPClient, error) { return conn, nil })
}
