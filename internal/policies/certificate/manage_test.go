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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// due_renewal: still valid but within certRenewalWindow of expiry.
	dueKey, dueKeyPEM := mgrKeyPEM(t)
	dueCertPEM := mgrSelfSigned(t, dueKey, "due", now.Add(-time.Hour), now.Add(10*24*time.Hour))
	templates = append(templates, mgrWritePair(t, stateDir, "due", "Machine", dueKeyPEM, dueCertPEM))

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

		_, _, caDER := mgrTestCA(t)

		var enrolled []enrolledTemplate
		var certPaths []string
		for _, tmpl := range templates {
			nick := "TestCA." + tmpl
			key, keyPEM := mgrKeyPEM(t)
			certPEM := mgrSelfSigned(t, key, nick, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
			et := mgrWritePair(t, stateDir, nick, tmpl, keyPEM, certPEM)
			enrolled = append(enrolled, et)
			certPaths = append(certPaths, et.CertFile)
		}
		mgrWriteState(t, stateDir, []enrolledCA{{Name: "TestCA", Hostname: "ca.example.com", Templates: enrolled}})

		submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
			return mgrIssueFromCSR(t, csrPEM, time.Now().Add(365*24*time.Hour)), nil
		}
		m := mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"),
			WithLDAPConnector(mgrConnector("CN=Configuration,DC=example,DC=com", "TestCA", "ca.example.com", templates, caDER, 2048)),
			WithCSRSubmitter(submitter),
		)
		return m, stateDir, certPaths
	}

	t.Run("renew single by nickname", func(t *testing.T) {
		t.Parallel()
		m, stateDir, certPaths := setup(t, []string{"Machine"})
		before, err := os.ReadFile(certPaths[0])
		require.NoError(t, err)
		stateBefore, err := loadState(stateDir, mgrTestObject)
		require.NoError(t, err)

		var msgs []string
		err = m.RenewCertificates(context.Background(), mgrTestObject, "TestCA.Machine", false, func(s string) { msgs = append(msgs, s) })
		require.NoError(t, err)

		after, err := os.ReadFile(certPaths[0])
		require.NoError(t, err)
		assert.NotEqual(t, before, after, "certificate file should be rewritten on renewal")

		stateAfter, err := loadState(stateDir, mgrTestObject)
		require.NoError(t, err)
		assert.False(t, stateAfter.UpdatedAt.Before(stateBefore.UpdatedAt), "state UpdatedAt should advance")

		joined := strings.Join(msgs, "\n")
		assert.Contains(t, joined, "Renewing")
		assert.Contains(t, joined, "Renewed TestCA.Machine")
	})

	t.Run("renew all templates", func(t *testing.T) {
		t.Parallel()
		m, _, certPaths := setup(t, []string{"Machine", "WebServer"})
		before := make([][]byte, len(certPaths))
		for i, p := range certPaths {
			b, err := os.ReadFile(p)
			require.NoError(t, err)
			before[i] = b
		}

		var msgs []string
		err := m.RenewCertificates(context.Background(), mgrTestObject, "", true, func(s string) { msgs = append(msgs, s) })
		require.NoError(t, err)

		for i, p := range certPaths {
			after, err := os.ReadFile(p)
			require.NoError(t, err)
			assert.NotEqual(t, before[i], after, "certificate %d should be rewritten", i)
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

	t.Run("renewal failure is aggregated but state is saved", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		stateDir := filepath.Join(tmpdir, "state")
		key, keyPEM := mgrKeyPEM(t)
		certPEM := mgrSelfSigned(t, key, "TestCA.Machine", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
		tmpl := mgrWritePair(t, stateDir, "TestCA.Machine", "Machine", keyPEM, certPEM)
		mgrWriteState(t, stateDir, []enrolledCA{{Name: "TestCA", Hostname: "ca.example.com", Templates: []enrolledTemplate{tmpl}}})

		submitter := func(_ context.Context, _, _, _, _ string) (string, error) {
			return "", fmt.Errorf("mock submit failure")
		}
		m := mgrManager(t, stateDir, filepath.Join(tmpdir, "trust"),
			WithLDAPConnector(func(string) (LDAPClient, error) { return nil, fmt.Errorf("no ldap") }),
			WithCSRSubmitter(submitter),
		)

		var msgs []string
		err := m.RenewCertificates(context.Background(), mgrTestObject, "", true, func(s string) { msgs = append(msgs, s) })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TestCA.Machine")
		assert.Contains(t, strings.Join(msgs, "\n"), "Failed to renew")
		require.FileExists(t, filepath.Join(stateDir, "certs", "state_keypress.json"))
	})
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
		require.NoError(t, os.WriteFile(symlinkPath, []byte("root"), 0600))
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

		state, err := loadState(stateDir, mgrTestObject)
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
		require.NoError(t, os.WriteFile(symlinkPath, []byte("root"), 0600))
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
		assert.NoFileExists(t, filepath.Join(stateDir, "certs", "state_keypress.json"), "state file should be removed")
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
		require.NoError(t, os.WriteFile(symlinkPath, []byte("root"), 0600))
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
		assert.NoFileExists(t, filepath.Join(stateDir, "certs", "state_keypress.json"))
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
	validCertPEM := mgrCASignedLeaf(t, caCert, caKey, &validKey.PublicKey, "valid.example.com", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	validTmpl := mgrWritePair(t, stateDir, "TestCA.Valid", "Machine", validKeyPEM, validCertPEM)

	// expired: leaf signed by the CA but past its NotAfter.
	expiredKey, expiredKeyPEM := mgrKeyPEM(t)
	expiredCertPEM := mgrCASignedLeaf(t, caCert, caKey, &expiredKey.PublicKey, "expired.example.com", now.Add(-48*time.Hour), now.Add(-time.Hour))
	expiredTmpl := mgrWritePair(t, stateDir, "TestCA.Expired", "Machine", expiredKeyPEM, expiredCertPEM)

	// mismatch: leaf valid and chains, but the on-disk key is a different key.
	leafKey, _ := mgrKeyPEM(t)
	_, otherKeyPEM := mgrKeyPEM(t)
	mismatchCertPEM := mgrCASignedLeaf(t, caCert, caKey, &leafKey.PublicKey, "mismatch.example.com", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	mismatchTmpl := mgrWritePair(t, stateDir, "TestCA.Mismatch", "Machine", otherKeyPEM, mismatchCertPEM)

	mgrWriteState(t, stateDir, []enrolledCA{{
		Name: "TestCA", Hostname: "ca.example.com",
		RootCerts: []string{rootPath},
		Templates: []enrolledTemplate{validTmpl, expiredTmpl, mismatchTmpl},
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

func TestDiscoverCAsInfo(t *testing.T) {
	t.Parallel()

	_, _, caDER := mgrTestCA(t)
	configDN := "CN=Configuration,DC=example,DC=com"

	t.Run("discovered CA without local enrollment", func(t *testing.T) {
		t.Parallel()
		tmpdir := t.TempDir()
		m := mgrManager(t, filepath.Join(tmpdir, "state"), filepath.Join(tmpdir, "trust"),
			WithLDAPConnector(mgrConnector(configDN, "TestCA", "ca.example.com", []string{"Machine", "WebServer"}, caDER, 2048)),
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
		assert.True(t, ca.InstalledInTrust, "a temporally valid self-signed CA verifies as installed")
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
			WithLDAPConnector(mgrConnector(configDN, "TestCA", "ca.example.com", []string{"Machine"}, caDER, 2048)),
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
			WithLDAPConnector(func(string) (LDAPClient, error) { return nil, fmt.Errorf("connection failed") }),
		)
		_, err := m.DiscoverCAsInfo(context.Background(), mgrTestObject)
		require.Error(t, err)
	})
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

func mgrCASignedLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, leafPub any, cn string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, leafPub, caKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mgrIssueFromCSR(t *testing.T, csrPEM string, notAfter time.Time) string {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block, "failed to decode CSR PEM")
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Renew Test CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	leaf := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "renewed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &leaf, caCert, csr.PublicKey, caKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
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
		Domain:     mgrTestDomain,
		CAs:        cas,
	}))
}

// mgrConnector returns an LDAPConnector backed by an in-memory mock that
// answers root DSE, enrollment service and certificate template queries.
func mgrConnector(configDN, caName, hostname string, templates []string, caDER []byte, minKeySize int) LDAPConnector {
	enrollBaseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)
	templateBaseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)

	results := map[string]*ldap.SearchResult{
		"":           {Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{"configurationNamingContext": {configDN}})}},
		enrollBaseDN: {Entries: []*ldap.Entry{newCAEntry(enrollBaseDN, caName, hostname, templates, caDER)}},
	}
	tEntries := make([]*ldap.Entry, 0, len(templates))
	for _, tmpl := range templates {
		tEntries = append(tEntries, ldap.NewEntry(fmt.Sprintf("CN=%s,%s", tmpl, templateBaseDN), map[string][]string{
			"cn":                     {tmpl},
			"msPKI-Minimal-Key-Size": {strconv.Itoa(minKeySize)},
		}))
	}
	results[templateBaseDN] = &ldap.SearchResult{Entries: tEntries}

	conn := &mockLDAPClient{searchResults: results}
	return func(string) (LDAPClient, error) { return conn, nil }
}
